import asyncio
import datetime
import json
import os

from jupyterhub.apihandlers import default_handlers
from jupyterhub.apihandlers.base import APIHandler
from jupyterhub.scopes import needs_scope
from tornado import web
from tornado.httpclient import HTTPRequest

from .. import get_custom_config
from ..backendspawner import user_cancel_message


class SetupTunnelAPIHandler(APIHandler):
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
        json_body = json.loads(body) if body else {}

        user = self.find_user(user_name)
        spawner = user.spawners[server_name]
        uuidcode = server_name

        if json_body:
            self.log.debug(
                "APICall: SetupTunnel",
                extra={
                    "uuidcode": uuidcode,
                    "log_name": f"{user_name}:{server_name}",
                    "user": user_name,
                    "action": "setuptunnel",
                    "event": json_body,
                },
            )

            json_body["servername"] = spawner.name
            json_body["svc_port"] = spawner.port
            json_body["svc_name"] = spawner.get_service_address()
            labels = {
                "hub.jupyter.org/username": user.name,
                "hub.jupyter.org/servername": spawner.name,
                "component": "singleuser-server",
                "app": os.environ.get("JUPYTERHUB_APP", "jupyterhub"),
            }

            for param, value in spawner.user_options.items():
                if param == "name" or param == "additional_spawn_options":
                    continue
                key = f"hub.jupyter.org/{param}"
                value = str(value).replace(
                    "/", "-"
                )  # cannot have '/' in k8s label values
                labels.update({key: value})

            custom_config = get_custom_config()
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": os.environ.get("TUNNEL_AUTHENTICATION_TOKEN", None),
                "uuidcode": spawner.name,
                "labels": json.dumps(labels),  # Add labels to headers
            }
            service_url = (
                custom_config.get("drf-services", {})
                .get("tunnel", {})
                .get("urls", {})
                .get("tunnel", "None")
            )

            request_kwargs = (
                custom_config.get("drf-services", {})
                .get("tunnel", {})
                .get("request_kwargs", {})
            )
            if not request_kwargs and hasattr(spawner, "request_kwargs"):
                # If nothing's configured, we use the spawner kwargs as backup
                request_kwargs = spawner.request_kwargs

            req = HTTPRequest(
                url=service_url,
                method="POST",
                headers=headers,
                body=json.dumps(json_body),
                **spawner.request_kwargs,
            )

            try:
                resp_json = await spawner.send_request(req, action="setuptunnel")
            except Exception as e:
                now = datetime.datetime.now().strftime("%Y_%m_%d %H:%M:%S.%f")[:-3]
                failed_event = {
                    "progress": 100,
                    "failed": True,
                    "html_message": f"<details><summary>{now}Could not setup tunnel</summary>{resp_json} - {str(e)}</details>",
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
                asyncio.create_task(spawner.stop(cancel=True, event=failed_event))

            self.set_header("Content-Type", "text/plain")
            self.set_status(204)
            return
        else:
            self.set_header("Content-Type", "text/plain")
            self.write("Bad Request - No event in request body.")
            self.set_status(400)
            return


default_handlers.append((r"/api/users/setuptunnel/([^/]+)", SetupTunnelAPIHandler))
default_handlers.append(
    (r"/api/users/setuptunnel/([^/]+)/([^/]+)", SetupTunnelAPIHandler)
)
