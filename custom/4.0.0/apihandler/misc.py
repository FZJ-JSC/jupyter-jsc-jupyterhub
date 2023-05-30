import json
import os
import time
import uuid
from urllib.parse import urlparse
from urllib.parse import urlunparse

from jupyterhub.apihandlers import APIHandler
from tornado.httpclient import AsyncHTTPClient
from tornado.httpclient import HTTPClientError
from traitlets import Any
from traitlets import default


class RequestAPIHandler(APIHandler):

    http_client = AsyncHTTPClient(
        force_instance=True, defaults=dict(validate_cert=False)
    )

    def check_xsrf_cookie(self):
        pass

    async def send_request(self, req, action, uuidcode=None, raise_exception=True):
        if not uuidcode:
            uuidcode = uuid.uuid4().hex

        self.log.debug(
            f"Communicate {action} with backend service ( {req.url} )",
            extra={
                "uuidcode": uuidcode,
                "action": action,
            },
        )
        tic = time.monotonic()
        try:
            resp = await self.fetch(req, action)
        except Exception as tic_e:
            if raise_exception:
                raise tic_e
            else:
                return {}
        else:
            return resp
        finally:
            toc = str(time.monotonic() - tic)
            self.log.info(
                f"Communicated {action} with backend service ( {req.url} ) (request duration: {toc})",
                extra={
                    "uuidcode": uuidcode,
                    "duration": toc,
                },
            )

    async def fetch(self, req, action):
        try:
            resp = await self.http_client.fetch(req)
        except HTTPClientError as e:
            if e.response:
                # Log failed response message for debugging purposes
                message = e.response.body.decode("utf8", "replace")
                try:
                    # guess json, reformat for readability
                    json_message = json.loads(message)
                except ValueError:
                    # not json
                    pass
                else:
                    # reformat json log message for readability
                    message = json.dumps(json_message, sort_keys=True, indent=1)
            else:
                # didn't get a response, e.g. connection error
                message = str(e)
            url = urlunparse(urlparse(req.url)._replace(query=""))
            self.log.error(
                f"Communication with backend failed: {e.code} {req.method} {url}: {message}.",
                extra={
                    "action": action,
                },
            )
            raise e
        else:
            if resp.body:
                return json.loads(resp.body.decode("utf8", "replace"))
            else:
                # empty body is None
                return None

    def get_req_prop_system(self, custom_config, system, uuidcode, auth_state=None):
        drf_service = (
            custom_config.get("systems", {}).get(system, {}).get("drf-service", None)
        )
        return self.get_req_prop(custom_config, drf_service, uuidcode, auth_state)

    def get_req_prop(self, custom_config, drf_service, uuidcode, auth_state=None):
        if auth_state:
            send_access_token = (
                custom_config.get("drf-services", {})
                .get(drf_service, {})
                .get("send_access_token", False)
            )
            access_token = auth_state["access_token"] if send_access_token else None
        else:
            access_token = None

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "uuidcode": uuidcode,
            "Authorization": os.environ.get(
                f"{drf_service.upper()}_AUTHENTICATION_TOKEN", None
            ),
        }
        if access_token:
            headers["access-token"] = access_token

        return {
            "headers": headers,
            "request_kwargs": custom_config.get("drf-services", {})
            .get(drf_service, {})
            .get("request_kwargs", {}),
            "urls": custom_config.get("drf-services", {})
            .get(drf_service, {})
            .get("urls", {}),
        }
