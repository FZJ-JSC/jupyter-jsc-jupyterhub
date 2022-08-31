import datetime
import json
import os
import uuid

from tornado.httpclient import HTTPClientError
from tornado.httpclient import HTTPResponse


class BackendException(Exception):
    error = "Unexpected error."
    error_detail = ""
    jupyterhub_html_message = ""
    code = 0

    def __init__(self, error, error_detail="", jupyterhub_html_message="", code=500):
        self.error = error
        self.error_detail = error_detail
        self.jupyterhub_html_message = jupyterhub_html_message
        self.code = code
        super().__init__(f"{error} --- {error_detail}")


def drf_request_properties(
    drf_service, custom_config, app_log, uuidcode, access_token=None
):
    drf_config = custom_config.get("drf-services")
    authentication_token = os.environ.get(
        f"{drf_service.upper()}_AUTHENTICATION_TOKEN", None
    )
    if not authentication_token:
        app_log.critical(
            f"{drf_service.upper()}_AUTHENTICATION_TOKEN env variable not defined. Cannot communicate with {drf_service}."
        )
        return {}
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": authentication_token,
        "uuidcode": uuidcode,
    }
    if access_token:
        headers["access-token"] = access_token
    certificate_path = drf_config.get(drf_service, {}).get("certificate_path", False)
    ca_certs = certificate_path if certificate_path else None
    validate_cert = True if ca_certs else False
    request_timeout = drf_config.get(drf_service, {}).get("request_timeout", 20)
    urls = drf_config.get(drf_service, {}).get("urls", {})
    ret = {
        "headers": headers,
        "ca_certs": ca_certs,
        "validate_cert": validate_cert,
        "request_timeout": request_timeout,
        "urls": urls,
    }
    return ret


async def drf_request(
    req,
    app_log,
    auth_fetch,
    action="",
    username="",
    log_name="",
    parse_json=True,
    raise_exception=False,
):
    safe_url = req.url.split("?")[0]
    app_log.info(
        f"Communicate {action} with backend service {safe_url}",
        extra={
            "uuidcode": req.headers["uuidcode"],
            "log_name": log_name,
            "user": username,
            "action": action,
        },
    )
    try:
        resp = await auth_fetch(req, parse_json=parse_json)
        return resp
    except Exception as e:
        if getattr(e, 'code', 500) == 404:
            if raise_exception:
                raise e
            else:
                return {}
        error = "Jupyter-JSC backend service communication failed."
        error_detail = str(e)
        if isinstance(e, HTTPClientError):
            if len(e.args) > 2:
                orig_response = e.args[2]
                if isinstance(orig_response, HTTPResponse):
                    error_json = json.loads(orig_response.body.decode("utf-8"))
                    try:
                        error = error_json.get("error", error)
                        error_detail = error_json.get("detailed_error", error_detail)
                    except:
                        # returned json is a list not a dictionary
                        # for example for missing access_token key in header
                        error_detail = error_json[0]
        app_log.info(
            "Exception while communicating with backend drf service",
            extra={
                "uuidcode": req.headers["uuidcode"],
                "log_name": log_name,
                "user": username,
                "action": action,
                "error_msg": error,
                "error_msg_detail": error_detail,
            },
            exc_info=True,
        )
        if raise_exception:
            now = datetime.datetime.now().strftime("%Y_%m_%d %H:%M:%S.%f")[:-3]
            jupyterhub_html_message = (
                f"<details><summary>{now}: {error}</summary>{error_detail}</details>"
            )
            raise BackendException(error, error_detail, jupyterhub_html_message, getattr(e, 'code', 500))
    return {}
