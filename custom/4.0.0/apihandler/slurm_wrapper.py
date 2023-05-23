import json

from jupyterhub.apihandlers.base import APIHandler
from jupyterhub.handlers import default_handlers
from jupyterhub.scopes import needs_scope
from tornado import web


class SlurmWrapperAPIHandler(APIHandler):
    def check_xsrf_cookie(self):
        pass

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
        kernel_infos = json.loads(body) if body else {}

        user = self.find_user(user_name)
        spawner = user.spawners[server_name]

        metrics_extras = {
            "action": "slurmwrapper",
            "username": user_name,
            "userid": user.id,
            "servername": server_name,
            "user_options": spawner.user_options,
            "kernel_infos": kernel_infos,
        }
        self.log.info("slurmwrapper", extra=metrics_extras)


default_handlers.append((r"/api/slurmwrapper/([^/]+)/([^/]+)", SlurmWrapperAPIHandler))
