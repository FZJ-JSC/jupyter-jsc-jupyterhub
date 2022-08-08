import json
import uuid

from custom_utils.backend_services import BackendException
from custom_utils.backend_services import drf_request
from custom_utils.backend_services import drf_request_properties
from jupyterhub.apihandlers.base import APIHandler
from tornado.httpclient import HTTPClientError
from tornado.httpclient import HTTPRequest


class ForwardTunnelRestartAPIHandler(APIHandler):
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
        custom_config = self.authenticator.custom_config
        req_prop = drf_request_properties("tunnel", custom_config, self.log, uuidcode)
        req_prop["headers"]["Authorization"] = self.request.headers["Authorization"]
        tunnel_url = req_prop.get("urls", {}).get("restart", "None")
        req = HTTPRequest(
            tunnel_url,
            method="POST",
            headers=req_prop["headers"],
            body=self.request.body,
            request_timeout=req_prop["request_timeout"],
            validate_cert=req_prop["validate_cert"],
            ca_certs=req_prop["ca_certs"],
        )
        try:
            await drf_request(
                req,
                self.log,
                self.authenticator.fetch,
                "restarttunnel",
                raise_exception=True,
            )
        except BackendException as e:
            self.set_status(e.code)
            self.write(e.error_detail)
            return
        except:
            self.set_status(500)
            return

        self.set_status(200)
        return
