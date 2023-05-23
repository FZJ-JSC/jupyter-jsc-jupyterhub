import json
import uuid

from jupyterhub.handlers import default_handlers
from tornado.httpclient import HTTPRequest

from ..misc import get_custom_config
from .misc import RequestAPIHandler


class ForwardTunnelRestartAPIHandler(RequestAPIHandler):
    def check_xsrf_cookie(self):
        pass

    """APIHandler to forward restart request to tunnel webservice"""

    async def post(self):
        self.set_header("Cache-Control", "no-cache")
        if not self.request.headers.get("Authorization", None):
            self.set_status(403)
            return

        uuidcode = self.request.headers.get("uuidcode", uuid.uuid4().hex)
        body = self.request.body.decode("utf8")
        body_dict = json.loads(body) if body else {}
        log_extras = {
            "uuidcode": uuidcode,
            "action": "restarttunnel",
            "body": body_dict,
        }
        self.log.info("Forward request to restart ssh-tunnels", extra=log_extras)
        custom_config = get_custom_config()
        req_prop = self.get_req_prop(custom_config, "tunnel", uuidcode)
        req_prop["headers"]["Authorization"] = self.request.headers["Authorization"]
        tunnel_url = req_prop.get("urls", {}).get("restart", "None")
        req = HTTPRequest(
            tunnel_url,
            method="POST",
            headers=req_prop["headers"],
            body=self.request.body,
            **req_prop.get("request_kwargs", {})
        )
        try:
            await self.send_request(req, "restarttunnel", uuidcode)
        except Exception as e:
            self.set_status(500)
            self.write(str(e))
            return

        self.set_status(200)
        return


default_handlers.append((r"/api/restarttunnel", ForwardTunnelRestartAPIHandler))
