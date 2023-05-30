import asyncio
import datetime
import json
import os

from jupyterhub.apihandlers import default_handlers
from jupyterhub.apihandlers.base import APIHandler
from jupyterhub.scopes import needs_scope
from tornado import web
from tornado.httpclient import HTTPRequest

from ..misc import get_custom_config


class UpdateLabAPIHandler(APIHandler):
    @needs_scope("access:servers")
    async def patch(self, user_name, server_name=""):
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
        user = self.find_user(user_name)
        spawner = user.spawners[server_name]
        uuidcode = server_name

        if spawner._stop_pending:
            self.log.debug(
                "APICall: Update Service - but spawner is already stopping.",
                extra={
                    "uuidcode": uuidcode,
                    "log_name": f"{user_name}:{server_name}",
                    "user": user_name,
                    "action": "updateservice",
                },
            )
            self.set_header("Content-Type", "text/plain")
            self.write("Bad Request.")
            self.set_status(400)
            return

        custom_config = get_custom_config()
        drf_service = (
            custom_config.get("systems", {})
            .get(spawner.user_options.get("system", "None"), {})
            .get("drf-service", None)
        )
        if drf_service == "k8smgrhdfcloud":
            self.log.debug(
                "APICall: Update Service",
                extra={
                    "uuidcode": uuidcode,
                    "log_name": f"{user_name}:{server_name}",
                    "user": user_name,
                    "action": "updateservice",
                },
            )
            base_url = (
                custom_config.get("drf-services", {})
                .get(drf_service, {})
                .get("urls", {})
                .get("services", "None")
            )
            request_kwargs = (
                custom_config.get("drf-services", {})
                .get(drf_service, {})
                .get("request_kwargs", {})
            )
            if "request_timeout" not in request_kwargs.keys():
                request_kwargs["request_timeout"] = 30
            url = f"{base_url}{spawner.name}/"
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": os.environ.get(
                    f"{drf_service.upper()}_AUTHENTICATION_TOKEN", None
                ),
                "uuidcode": spawner.name,
            }
            req = HTTPRequest(
                url=url,
                method="PATCH",
                headers=headers,
                body=json.dumps({}),
                **request_kwargs,
            )
            try:
                await spawner.send_request(
                    req, action="updateservice", raise_exception=False
                )
            except Exception as e:
                now = datetime.datetime.now().strftime("%Y_%m_%d %H:%M:%S.%f")[:-3]
                failed_event = {
                    "progress": 100,
                    "failed": True,
                    "html_message": f"<details><summary>{now}: Could not create necessary resources.</summary>{str(e)}</details>",
                }
                self.log.exception(
                    f"Could not update service for {user_name}:{server_name}",
                    extra={
                        "uuidcode": uuidcode,
                        "log_name": f"{user_name}:{server_name}",
                        "user": user_name,
                        "action": "updateservicefailed",
                        "event": failed_event,
                    },
                )
                asyncio.create_task(spawner.stop(cancel=True, event=failed_event))
        else:
            self.set_header("Content-Type", "text/plain")
            self.write("Bad Request.")
            self.set_status(400)
            return


default_handlers.append((r"/api/users/updatelab/([^/]+)", UpdateLabAPIHandler))
default_handlers.append((r"/api/users/updatelab/([^/]+)/([^/]+)", UpdateLabAPIHandler))
