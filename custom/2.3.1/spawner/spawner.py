import asyncio
import copy
import json
import logging
import os
import random
import re
import uuid
from datetime import datetime
from pathlib import Path

from async_generator import aclosing
from custom_utils.backend_services import BackendException
from custom_utils.backend_services import drf_request
from custom_utils.backend_services import drf_request_properties
from custom_utils.options_form import check_formdata_keys
from custom_utils.options_form import get_options_form
from custom_utils.options_form import get_options_from_form
from jupyterhub.spawner import Spawner
from jupyterhub.utils import maybe_future
from jupyterhub.utils import url_path_join
from tornado.httpclient import HTTPClientError
from tornado.httpclient import HTTPRequest
from tornado.ioloop import PeriodicCallback
from traitlets import Integer


class BackendSpawner(Spawner):
    _cancel_pending = False
    _cancel_event_yielded = False
    _yielded_events = []
    svc_name = ""

    latest_events = []
    events = {}
    start_id = ""
    clear_events = True
    yield_wait_seconds = 1

    poll_interval_randomizer = Integer(
        20,
        help="""
        random.randint(0, 1e3 * self.poll_interval_randomizer) will be added to
	self.poll_interval. Each Spawner object will have it's own interval.
        """,
    ).tag(config=True)

    def get_state(self):
        """get the current state"""
        state = super().get_state()
        if self.svc_name:
            state["svc_name"] = self.svc_name
        if self.start_id:
            state["start_id"] = self.start_id
        if self.events:
            self.events["latest"] = self.latest_events
            # Clear logs older than 24h or empty logs
            events_keys = copy.deepcopy(list(self.events.keys()))
            for key in events_keys:
                value = self.events.get(key, None)
                if value and len(value) > 0 and value[0]:
                    stime = self._get_event_time(value[0])
                    dtime = datetime.strptime(stime, "%Y_%m_%d %H:%M:%S")
                    now = datetime.now()
                    delta = now - dtime
                    if delta.days:
                        del self.events[key]
                else:  # empty logs
                    del self.events[key]
            state["events"] = self.events
        return state

    def load_state(self, state):
        """load state from the database"""
        super().load_state(state)
        if "events" in state:
            self.events = state["events"]
        if "svc_name" in state:
            self.svc_name = state["svc_name"]
        if "start_id" in state:
            self.start_id = state["start_id"]

    def clear_state(self):
        """clear any state (called after shutdown)"""
        self.svc_name = ""
        self.start_id = ""
        if self.clear_events:
            self.events = {}
            self.clear_events = False
        super().clear_state()

    def start_polling(self):
        """Start polling periodically for single-user server's running state.

        Callbacks registered via `add_poll_callback` will fire if/when the server stops.
        Explicit termination via the stop method will not trigger the callbacks.

        We've added a randomized timer self.poll_interval_randomizer.
        If you restart JupyterHub, all polls start at the same time. With the randomizing
        factor, only the first poll for each server happens at the same time.
        """
        if self.poll_interval <= 0:
            self.log.debug("Not polling subprocess")
            return
        else:
            poll_interval = 1e3 * self.poll_interval + random.randint(
                0, 1e3 * self.poll_interval_randomizer
            )
            self.log.debug("Polling subprocess every %ims", poll_interval)

        self.stop_polling()

        self._poll_callback = PeriodicCallback(self.poll_and_notify, poll_interval)
        self._poll_callback.start()

    def status_update_url(self, server_name=""):
        """API path for status update endpoint for a server with a given name"""
        url_parts = ["users", "progress", "update", self.user.escaped_name]
        if server_name:
            url_parts.append(server_name)
        return url_path_join(*url_parts)

    @property
    def _status_update_url(self):
        return self.status_update_url(self.name)

    def get_env(self):
        env = super().get_env()
        env["JUPYTERHUB_STATUS_URL"] = self._status_update_url
        env["JUPYTERHUB_USER_ID"] = self.user.orm_user.id
        env["JUPYTERHUB_STAGE"] = os.environ.get("JUPYTERHUB_STAGE", "")
        return env

    def get_svc_name(self):
        custom_config = self.user.authenticator.custom_config
        drf_service = (
            custom_config.get("systems", {})
            .get(self.user_options["system"], {})
            .get("drf-service", None)
        )
        # max length for svc names: 63 (without suffix)
        # drf_service + "-" + self.name + "-" + self.start_id
        #      21     +  1  +    32     +  1  + 8 = 63
        drf_service_short = drf_service[:21]

        svc_name = f"{drf_service_short}-{self.name}-{self.start_id}"
        return f"{svc_name}"

    def get_svc_name_suffix(self):
        k8s_tunnel_deployment_namespace = os.environ.get("TUNNEL_DEPLOYMENT_NAMESPACE")
        return f".{k8s_tunnel_deployment_namespace}.svc"

    def _get_req_prop(self, auth_state):
        custom_config = self.user.authenticator.custom_config
        drf_service = (
            custom_config.get("systems", {})
            .get(self.user_options["system"], {})
            .get("drf-service", None)
        )
        send_access_token = (
            custom_config.get("drf-services", {})
            .get(drf_service, {})
            .get("send_access_token", False)
        )
        access_token = auth_state["access_token"] if send_access_token else None
        req_prop = drf_request_properties(
            drf_service, custom_config, self.log, self.name, access_token
        )
        return req_prop

    def _get_event_time(self, event):
        # Regex for date time
        pattern = re.compile(
            r"([0-9]+(_[0-9]+)+).*[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,3})?"
        )
        message = event["html_message"]
        match = re.search(pattern, message)
        return match.group()

    async def start(self):
        # Save latest events with start event time
        if self.latest_events != []:
            try:
                start_event = self.latest_events[0]
                start_event_time = self._get_event_time(start_event)
                self.events[start_event_time] = self.latest_events
            except:
                self.log.info(
                    f"Could not retrieve latest_events. Reset events list for {self._log_name}"
                )
                self.latest_events = []
                self.events = []
        # Reset latest events only
        self.latest_events = []
        self.events["latest"] = self.latest_events

        self._cancel_pending = False
        self._cancel_event_yielded = False
        return await self._start()

    async def create_certs(self):
        from certipy import Certipy

        self.start_id = uuid.uuid4().hex[:8]
        self.ssl_alt_names += [f"DNS:{self.get_svc_name()}{self.get_svc_name_suffix()}"]

        default_names = ["DNS:localhost", "IP:127.0.0.1"]
        alt_names = []
        alt_names.extend(self.ssl_alt_names)

        if self.ssl_alt_names_include_local:
            alt_names = default_names + alt_names

        self.log.info("Creating certs for %s: %s", self._log_name, ";".join(alt_names))

        certipy = Certipy(store_dir=self.internal_certs_location)
        notebook_component = "notebooks-ca"
        notebook_key_pair = certipy.create_signed_pair(
            f"{self.name}_{self.start_id}",
            notebook_component,
            alt_names=alt_names,
            overwrite=True,
        )
        paths = {
            "keyfile": notebook_key_pair["files"]["key"],
            "certfile": notebook_key_pair["files"]["cert"],
            "cafile": self.internal_trust_bundles[notebook_component],
        }
        return paths

    async def get_certs(self):
        ret = {}
        for key, path in self.cert_paths.items():
            with open(path, "r") as f:
                ret[key] = f.read()
        return ret

    async def _start(self):
        config = self.user.authenticator.custom_config
        def map_user_options():
            ret = {}
            for key, value in self.user_options.items():
                ret[config.get("map_user_options").get(key, key)] = value
            return ret

        if not self.internal_ssl:
            # Create certs was never called, so no start_id was defined yet
            self.start_id = uuid.uuid4().hex[:8]

        self.svc_name = self.get_svc_name()

        now = datetime.now().strftime("%Y_%m_%d %H:%M:%S.%f")[:-3]
        user_options = map_user_options()
        try:
            check_formdata_keys(user_options, config)
        except KeyError as e:
            error = "Invalid input"
            detailed_error = str(e)
            jupyterhub_html_message = (
                f"<details><summary>{now}: {error}</summary>{detailed_error}</details>"
            )
            failed_event = {
                "progress": 100,
                "failed": True,
                "html_message": jupyterhub_html_message,
            }
            self.latest_events.append(failed_event)
            raise BackendException(error, detailed_error, jupyterhub_html_message, 400)

        self.log.info(
            "Spawn submit ...",
            extra={
                "uuidcode": self.name,
                "username": self.user.name,
                "userid": self.user.id,
                "start_id": self.start_id,
                "svc_name": self.svc_name,
                "action": "start",
                "options": user_options,
            },
        )

        user_messages = config.get("user_messages", {})
        start_pre_default = f"Sending request to backend service to start your service on {user_options['system']}."
        start_pre_msg = user_messages.get("start_pre", start_pre_default)
        start_event = {
            "failed": False,
            "progress": 10,
            "html_message": f"<details><summary>{now}: {start_pre_msg}</summary>\
                &nbsp;&nbsp;Start ID: {self.start_id}<br>&nbsp;&nbsp;Options:<br><pre>{json.dumps(user_options, indent=2)}</pre></details>",
        }
        ready_default = f"Service {user_options['name']} started on {user_options['system']}."
        ready_msg = user_messages.get("ready", ready_default)
        self.ready_event[
            "html_message"
        ] = f"<details><summary><now>: {ready_msg}</summary>You will be redirected to <a href=\"<url>\"><url></a></details>"
        self.latest_events = [start_event]

        self.port = 8080

        auth_state = await self.user.get_auth_state()

        add_env = {}
        for options in config.get("additional_spawn_options", {}).items():
            for key in options[1]:
                add_env[f"JUPYTER_MODULE_{key.upper()}_ENABLED"] = int(key in user_options.get("additional_spawn_options"))

        env = self.get_env()
        env.update(add_env)
        popen_kwargs = {
            "auth_state": auth_state,
            "env": env,
            "user_options": user_options,
            "start_id": self.start_id,
        }

        if self.internal_ssl:
            popen_kwargs["certs"] = await self.get_certs()

        req_prop = self._get_req_prop(auth_state)
        service_url = req_prop.get("urls", {}).get("services", "None")
        req = HTTPRequest(
            service_url,
            method="POST",
            headers=req_prop["headers"],
            body=json.dumps(popen_kwargs),
            request_timeout=req_prop["request_timeout"],
            validate_cert=req_prop["validate_cert"],
            ca_certs=req_prop["ca_certs"],
        )

        if os.environ.get("LOGGING_METRICS_ENABLED", "false").lower() in [
            "true",
            "1",
        ]:
            options = ';'.join(['%s=%s' % (k, v) for k, v in self.user_options.items()])
            metrics_logger = logging.getLogger("Metrics")            
            metrics_extras = {
                "action": "start",
                "userid": self.user.id,
                "servername": self.name,
                "options": self.user_options
            }
            metrics_logger.info(f"action={metrics_extras['action']};userid={metrics_extras['userid']};servername={metrics_extras['servername']};{options}")
            self.log.info("start", extra=metrics_extras)

        try:
            resp_json = await drf_request(
                req,
                self.log,
                self.user.authenticator.fetch,
                "start",
                self.user.name,
                self._log_name,
                parse_json=True,
                raise_exception=True,
            )
        except BackendException as e:
            self.log.warning(
                "Spawn submit ... failed.",
                extra={
                    "uuidcode": self.name,
                    "username": self.user.name,
                    "userid": self.user.id,
                    "start_id": self.start_id,
                    "svc_name": self.svc_name,
                    "action": "submit_fail",
                    "user_msg": e.jupyterhub_html_message,
                },
            )
            failed_event = {
                "progress": 100,
                "failed": True,
                "html_message": e.jupyterhub_html_message,
            }
            self.latest_events.append(failed_event)
            try:
                self.stop()
            except:
                pass
            raise e

        svc_name_suffix = self.get_svc_name_suffix()
        self.log.debug(
            f"Expect JupyterLab at {self.svc_name}{svc_name_suffix}:{self.port}",
            extra={"uuidcode": self.name},
        )
        now = datetime.now().strftime("%Y_%m_%d %H:%M:%S.%f")[:-3]
        if self.user.authenticator.custom_config.get("systems", {}).get(user_options["system"], {}).get("drf-service", "") == "unicoremgr":
            unicore_post_default = "Waiting for UNICORE job to run... (click on log lines for more information)"
            unicore_post_msg = user_messages.get("start_post_unicore", unicore_post_default)
            submit_message = f"<details><summary>{now}: {unicore_post_msg}</summary>You will receive further information about the service status from the UNICORE job.</details>"
        else:
            k8s_post_default = "Waiting for Kubernetes container to start... (click on log lines for more information)"
            k8s_post_msg = user_messages.get("start_post_k8s", k8s_post_default)
            submit_message = f"<details><summary>{now}: {k8s_post_msg}</summary>You will receive further information about the service status from the container.</details>"
        submitted_event = {
            "failed": False,
            "progress": 30,
            "html_message": submit_message,
        }
        self.latest_events.append(submitted_event)
        self.log.info(
            "Spawn submit ... done.",
            extra={
                "uuidcode": self.name,
                "username": self.user.name,
                "userid": self.user.id,
                "start_id": self.start_id,
                "svc_name": self.svc_name,
                "action": "submitted",
                "response": resp_json,
            },
        )
        return (f"{self.svc_name}{svc_name_suffix}", self.port)

    async def poll(self):
        if self._cancel_pending:
            # avoid loop with cancel
            return 0

        auth_state = await self.user.get_auth_state()

        req_prop = self._get_req_prop(auth_state)
        service_url = req_prop.get("urls", {}).get("services", "None")

        req = HTTPRequest(
            f"{service_url}{self.name}/",
            method="GET",
            headers=req_prop["headers"],
            request_timeout=req_prop["request_timeout"],
            validate_cert=req_prop["validate_cert"],
            ca_certs=req_prop["ca_certs"],
        )

        try:
            resp_json = await drf_request(
                req,
                self.log,
                self.user.authenticator.fetch,
                "poll",
                self.user.name,
                self._log_name,
                parse_json=True,
                raise_exception=True,
            )
        except HTTPClientError as e:
            if getattr(e, 'code', 500) == 404:
                resp_json = {"running": False}
            else:
                self.log.warning("Unexpected error", exc_info=True)
                return None
        except Exception:
            self.log.warning("Unexpected error", exc_info=True)
            return None
        if not resp_json.get("running", True):
            if self._spawn_pending:
                # During the spawn progress we've received that it's already stopped.
                # We want to show the error message to the user
                now = datetime.now().strftime("%Y_%m_%d %H:%M:%S.%f")[:-3]
                summary = resp_json.get("details", {}).get("error", "Start failed.")
                details = resp_json.get("details", {}).get(
                    "detailed_error", "No details available."
                )
                event = {
                    "failed": True,
                    "progress": 100,
                    "html_message": f"<details><summary>{now}: {summary}</summary>{details}</details>",
                }
                await self.cancel(event)
                return 0
            else:
                # It's not running anymore. Call stop to delete all resources
                await self.stop()
            return 0
        return None

    def stop(self):
        return asyncio.ensure_future(self._stop())

    async def _stop(self):
        auth_state = await self.user.get_auth_state()

        req_prop = self._get_req_prop(auth_state)
        service_url = req_prop.get("urls", {}).get("services", "None")

        req = HTTPRequest(
            f"{service_url}{self.name}/",
            method="DELETE",
            headers=req_prop["headers"],
            request_timeout=req_prop["request_timeout"],
            validate_cert=req_prop["validate_cert"],
            ca_certs=req_prop["ca_certs"],
        )
        
        await drf_request(
            req,
            self.log,
            self.user.authenticator.fetch,
            "stop",
            self.user.name,
            self._log_name,
            parse_json=True,
            raise_exception=False,
        )

        custom_config = self.user.authenticator.custom_config
        tunnel_req_prop = drf_request_properties(
            "tunnel", custom_config, self.log, self.name
        )

        tunnel_service_url = tunnel_req_prop.get("urls", {}).get("tunnel", "None")
        tunnel_req = HTTPRequest(
            f"{tunnel_service_url}{self.name}/",
            method="DELETE",
            headers=tunnel_req_prop["headers"],
            request_timeout=tunnel_req_prop["request_timeout"],
            validate_cert=tunnel_req_prop["validate_cert"],
            ca_certs=tunnel_req_prop["ca_certs"],
        )
        await drf_request(
            tunnel_req,
            self.log,
            self.user.authenticator.fetch,
            "removetunnel",
            self.user.name,
            f"{self.user.name}::removetunnel",
            parse_json=True,
            raise_exception=False,
        )

        if self.cert_paths:
            Path(self.cert_paths["keyfile"]).unlink(missing_ok=True)
            Path(self.cert_paths["certfile"]).unlink(missing_ok=True)
            try:
                Path(self.cert_paths["certfile"]).parent.rmdir()
            except:
                pass

    async def _generate_progress(self):
        """Private wrapper of progress generator

        This method is always an async generator and will always yield at least one event.
        """
        if not self._spawn_pending:
            self.log.warning(
                "Spawn not pending, can't generate progress for %s", self._log_name
            )
            return

        async with aclosing(self.progress()) as progress:
            async for event in progress:
                yield event

    async def progress(self):
        spawn_future = self._spawn_future
        next_event = 0

        break_while_loop = False
        while True:
            # Ensure we always capture events following the start_future
            # signal has fired.
            if spawn_future.done():
                break_while_loop = True

            len_events = len(self.latest_events)
            if next_event < len_events:
                for i in range(next_event, len_events):
                    yield self.latest_events[i]
                    if self.latest_events[i].get("failed", False) == True:
                        self._cancel_event_yielded = True
                        break_while_loop = True
                next_event = len_events

            if break_while_loop:
                break
            await asyncio.sleep(self.yield_wait_seconds)

    async def _cancel_future(self, future):
        if type(future) is asyncio.Task:
            if future._state in ["PENDING"]:
                try:
                    future.cancel()
                    await maybe_future(future)
                except asyncio.CancelledError:
                    pass
                return True
        return False

    async def cancel(self, event):
        self.log.info("Cancel Start")
        self._cancel_pending = True
        self.latest_events.append(event)

        # Let generate_progress catch this event.
        # This will show the new event at the control panel site
        for _ in range(0, 2):
            if self._cancel_event_yielded:
                break
            else:
                await asyncio.sleep(self.yield_wait_seconds)
        if not self._cancel_event_yielded:
            self.log.warning("Cancel event will not be displayed at control panel.")

        await self.stop()

        try:
            await self.user.stop(self.name)
        except asyncio.CancelledError:
            pass
        await self._cancel_future(self._spawn_future)

        self._cancel_pending = False
        self.log.info("Cancel Done")

    async def options_form(self, spawner):
        query_options = {}
        for key, byte_list in spawner.handler.request.query_arguments.items():
            query_options[key] = [bs.decode("utf8") for bs in byte_list]
        service = query_options.get("service", "JupyterLab")
        if type(service) == list:
            service = service[0]
        service_type = service.split("/")[0]

        services = self.user.authenticator.custom_config.get("services")
        if service_type in services.keys():
            return await get_options_form(
                spawner, service, services[service_type].get("options", {})
            )
        raise NotImplementedError(f"Service type {service_type} from {service} unknown")

    async def options_from_form(self, formdata):
        custom_config = self.user.authenticator.custom_config
        service = formdata.get("service", [""])[0]
        service_type = service.split("/")[0]
        if service_type in custom_config.get("services").keys():
            return await get_options_from_form(formdata, custom_config)
        raise NotImplementedError(f"Service type {service_type} from {service} unknown")
