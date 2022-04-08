import datetime
import json

from custom_utils.backend_services import BackendException
from custom_utils.backend_services import drf_request
from custom_utils.backend_services import drf_request_properties
from jupyterhub.apihandlers.base import APIHandler
from jupyterhub.scopes import needs_scope
from tornado import web
from tornado.httpclient import HTTPRequest

user_cancel_message = "Start cancelled by user."


class SpawnProgressUpdateAPIHandler(APIHandler):
    @needs_scope("access:servers")
    async def post(self, user_name, server_name=""):
        self.set_header("Cache-Control", "no-cache")
        if server_name is None:
            server_name = ""
        user = self.find_user(user_name)
        if user is None:
            # no such user
            raise web.HTTPError(404)
        if server_name not in user.spawners:
            # user has no such server
            raise web.HTTPError(404)
        body = self.request.body.decode("utf8")
        event = json.loads(body) if body else {}

        user = self.find_user(user_name)
        spawner = user.spawners[server_name]
        uuidcode = server_name

        if event.get("html_message", ""):
            # Add timestamp
            now = datetime.datetime.now().strftime("%Y_%m_%d %H:%M:%S.%f")[:-3]
            if event["html_message"].startswith("<details><summary>"):
                event[
                    "html_message"
                ] = f"<details><summary>{now}: {event['html_message'][len('<details><summary>'):]}"
            else:
                event["html_message"] = f"{now}: {event['html_message']}"

        if event and event.get("failed", False):
            if event.get("html_message", "") == user_cancel_message:
                self.log.debug(
                    "APICall: SpawnUpdate",
                    extra={
                        "uuidcode": uuidcode,
                        "log_name": f"{user_name}:{server_name}",
                        "user": user_name,
                        "action": "cancel",
                        "event": event,
                    },
                )
            else:
                self.log.debug(
                    "APICall: SpawnUpdate",
                    extra={
                        "uuidcode": uuidcode,
                        "log_name": f"{user_name}:{server_name}",
                        "user": user_name,
                        "action": "failed",
                        "event": event,
                    },
                )
            await spawner.cancel(event)
            self.set_header("Content-Type", "text/plain")
            self.set_status(204)
            return
        elif event:
            self.log.debug(
                "APICall: SpawnUpdate",
                extra={
                    "uuidcode": uuidcode,
                    "log_name": f"{user_name}:{server_name}",
                    "user": user_name,
                    "action": "spawnupdate",
                    "event": event,
                },
            )
            spawner = user.spawners[server_name]
            spawner.current_events.append(event)
            if "setup_tunnel" in event.keys():
                event["setup_tunnel"]["servername"] = spawner.name
                event["setup_tunnel"]["svc_port"] = spawner.port
                event["setup_tunnel"]["svc_name"] = spawner.svc_name
                custom_config = user.authenticator.custom_config
                req_prop = drf_request_properties(
                    "tunnel", custom_config, self.log, uuidcode
                )
                service_url = req_prop.get("urls", {}).get("tunnel", "None")
                req = HTTPRequest(
                    service_url,
                    method="POST",
                    headers=req_prop["headers"],
                    body=json.dumps(event["setup_tunnel"]),
                    request_timeout=req_prop["request_timeout"],
                    validate_cert=req_prop["validate_cert"],
                    ca_certs=req_prop["ca_certs"],
                )
                try:
                    await drf_request(
                        req,
                        self.log,
                        user.authenticator.fetch,
                        "setuptunnel",
                        user.name,
                        f"{user.name}::setuptunnel",
                        parse_json=True,
                        raise_exception=True,
                    )
                except BackendException as e:
                    now = datetime.datetime.now().strftime("%Y_%m_%d %H:%M:%S.%f")[:-3]
                    failed_event = {
                        "progress": 100,
                        "failed": True,
                        "html_message": f"<details><summary>{now}: Could not setup tunnel</summary>{e.error_detail}</details>",
                    }
                    self.log.exception(
                        f"Could not setup tunnel for {user_name}:{server_name}",
                        extra={
                            "uuidcode": uuidcode,
                            "log_name": f"{user_name}:{server_name}",
                            "user": user_name,
                            "action": "tunnelfailed",
                            "event": failed_event,
                        },
                    )
                    await spawner.cancel(failed_event)
                except Exception as e:
                    now = datetime.datetime.now().strftime("%Y_%m_%d %H:%M:%S.%f")[:-3]
                    failed_event = {
                        "progress": 100,
                        "failed": True,
                        "html_message": f"<details><summary>{now}: Could not setup tunnel</summary>{str(e)}</details>",
                    }
                    self.log.exception(
                        f"Could not setup tunnel for {user_name}:{server_name}",
                        extra={
                            "uuidcode": uuidcode,
                            "log_name": f"{user_name}:{server_name}",
                            "user": user_name,
                            "action": "tunnelfailed",
                            "event": failed_event,
                        },
                    )
                    await spawner.cancel(failed_event)

            self.set_header("Content-Type", "text/plain")
            self.set_status(204)
            return
        else:
            self.set_header("Content-Type", "text/plain")
            self.write("Bad Request - No event in request body.")
            self.set_status(400)
            return


class SpawnProgressStatusAPIHandler(APIHandler):
    @needs_scope("read:servers")
    async def get(self, user_name, server_name=""):
        user = self.find_user(user_name)
        if user is None:
            # no such user
            raise web.HTTPError(404)
        if server_name not in user.spawners:
            # user has no such server
            raise web.HTTPError(404)
        spawner = user.spawners[server_name]
        data = {
            "events": spawner.current_events,
            "active": spawner.active,
            "ready": spawner.ready,
        }
        self.write(json.dumps(data))
