import asyncio
import datetime
import json

import jwt
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from jupyterhub.apihandlers import default_handlers
from jupyterhub.apihandlers.base import APIHandler
from tornado.httpclient import HTTPRequest

from ..misc import get_custom_config


class SpawnEventsUNICOREAPIHandler(APIHandler):
    def check_xsrf_cookie(self):
        pass

    async def post(self, user_name, server_name=""):
        user = self.find_user(user_name)
        if user is None:
            self.set_status(404)
            return
        if server_name not in user.spawners:
            self.set_status(404)
            return

        custom_config = get_custom_config()
        spawner = user.spawners[server_name]
        spawner_system = spawner.user_options.get("system", "")
        cert_url = (
            custom_config.get("unicore_updates", {})
            .get("certificate_urls", {})
            .get(spawner_system, False)
        )
        gateway_cert_path = custom_config.get("unicore_updates", {}).get(
            "gateway_cert_path", False
        )
        if cert_url:
            with requests.get(
                cert_url, headers={"accept": "text/plain"}, verify=gateway_cert_path
            ) as r:
                r.raise_for_status()
                cert = r.content

            # Validate certifica
            algorithms = custom_config.get("unicore_updates", {}).get(
                "algorithms", ["RS256"]
            )
            cert_obj = load_pem_x509_certificate(cert, default_backend())
            token = self.request.headers.get("Authorization", "Bearer -").split()[1]
            jwt.decode(token, cert_obj.public_key(), algorithms=algorithms)

        body = self.request.body.decode("utf8")
        body = json.loads(body) if body else {}
        self.log.info(
            "Unicore Status Update received",
            extra={
                "uuidcode": spawner.name,
                "username": user.name,
                "userid": user.id,
                "action": "unicoreupdate",
                "body": body,
            },
        )
        if body.get("status", "") in ["FAILED", "SUCCESSFUL", "DONE"]:
            # spawner.poll will check the current status via UnicoreMgr.
            # This will download the logs and show them to the user.
            # It will also cancel the current spawn attempt.
            self.log.debug(
                "Cancel spawner",
                extra={
                    "uuidcode": spawner.name,
                    "username": user.name,
                    "userid": user.id,
                },
            )

            async def get_event_and_stop():
                # First we want to get the error msg via spawner.poll, then
                # we will use this message as event for spawner.stop
                url = await spawner.get_request_url_poll()
                headers = await spawner.get_request_headers_poll()
                req = HTTPRequest(
                    url=url,
                    method="GET",
                    headers=headers,
                    **spawner.get_request_kwargs(),
                )
                resp_json = await spawner.send_request(
                    req, action="poll", raise_exception=False
                )
                if not resp_json:
                    # spawner.send_request may return None
                    resp_json = {}
                summary = resp_json.get("details", {}).get("error", "Start failed.")
                details = resp_json.get("details", {}).get(
                    "detailed_error", "No details available."
                )

                def get_event(spawner):
                    now = datetime.datetime.now().strftime("%Y_%m_%d %H:%M:%S.%f")[:-3]
                    event = {
                        "failed": True,
                        "progress": 100,
                        "html_message": f"<details><summary>{now}: {summary}</summary>{details}</details>",
                    }
                    return event

                await spawner.stop(cancel=True, event=get_event)

            if bool(spawner._spawn_pending or spawner.ready):
                asyncio.create_task(get_event_and_stop())
        else:
            bssStatus = body.get("bssStatus", "")
            # It's in Running (UNICORE wise) state. We can now check for bssStatus to get more details
            for key, bssDetails in (
                custom_config.get("unicore_updates", {}).get("bssStatus", {}).items()
            ):
                if key == bssStatus:
                    now = datetime.datetime.now().strftime("%Y_%m_%d %H:%M:%S.%f")[:-3]
                    summary = bssDetails.get("summary", f"Slurm status: {key}")
                    details = bssDetails.get(
                        "details",
                        "You'll receive more information, when your slurm job proceeds.",
                    )
                    progress = int(bssDetails.get("progress", 35))
                    event = {
                        "failed": False,
                        "progress": progress,
                        "html_message": f"<details><summary>{now}: {summary}</summary>{details}</details>",
                    }
                    if hasattr(spawner, "latest_events"):
                        spawner.latest_events.append(event)

        self.set_status(200)


default_handlers.append(
    (r"/api/users/progress/updateunicore/([^/]+)", SpawnEventsUNICOREAPIHandler)
)
default_handlers.append(
    (r"/api/users/progress/updateunicore/([^/]+)/([^/]+)", SpawnEventsUNICOREAPIHandler)
)
