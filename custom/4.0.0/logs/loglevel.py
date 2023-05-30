import copy
import json
import os
from uuid import uuid4

from jupyterhub.apihandlers import APIHandler
from jupyterhub.handlers import default_handlers
from jupyterhub.handlers.base import BaseHandler
from jupyterhub.scopes import needs_scope
from tornado import web
from tornado.httpclient import HTTPRequest

from ..apihandler.misc import RequestAPIHandler
from ..authenticator.api_services import create_ns
from ..misc import get_custom_config
from .extra_handlers import default_configurations
from .utils import create_logging_handler
from .utils import remove_logging_handler
from .utils import supported_formatter_classes
from .utils import supported_handler_classes


def get_config():
    try:
        with open(os.environ.get("LOGGING_CONFIG_FILE", "logging.json"), "r") as f:
            config = json.load(f)
    except:
        config = default_configurations
    return config


class JHubLogLevelAPIHandler(APIHandler):
    def check_xsrf_cookie(self):
        pass

    def is_valid_config(
        self, data, name, valid_values, handler=None, case_sensitive=True
    ):
        value = data.get("configuration", {}).get(name, None)
        if value and not case_sensitive:
            value = value.lower()
        if handler is None or handler == data["handler"]:
            if value is not None and value not in valid_values:
                error = (
                    f"Unsupported {name}: {value}. Supported {name}s: {valid_values}"
                )
                raise ValueError(error)

    def is_valid_config_type(self, data, name, valid_value_types, handler=None):
        if type(valid_value_types) != list:
            valid_value_types = [valid_value_types]
        value = data.get("configuration", {}).get(name, None)
        if handler is None or handler == data["handler"]:
            if value is not None and type(value) not in valid_value_types:
                error = f"{name} in configuration must be of type {valid_value_types} not {type(value)}"
                raise TypeError(error)

    def validate_data(self, data):
        if "handler" not in data.keys():
            raise Exception(["Missing key in input data: handler"])
        handler = data.get("handler")
        allowed_handlers = [h for h in supported_handler_classes]
        if handler not in allowed_handlers:
            self._errors = [
                f"Unsupported handler: {handler}. Supported handlers: {allowed_handlers}"
            ]
            raise Exception(self._errors)
        if "configuration" in data.keys():
            configuration_type = type(data["configuration"])
            if configuration_type != dict:
                self._errors = [
                    f"Configuration must be of type dict not {configuration_type}"
                ]
                raise Exception(self._errors)
        self.is_valid_config(
            data, "formatter", [f for f in supported_formatter_classes]
        )
        valid_levels = [
            0,
            5,
            10,
            20,
            30,
            40,
            50,
            99,
            "0",
            "5",
            "10",
            "20",
            "30",
            "40",
            "50",
            "99",
            "NOTSET",
            "TRACE",
            "DEBUG",
            "INFO",
            "WARN",
            "WARNING",
            "ERROR",
            "FATAL",
            "CRITICAL",
            "DEACTIVATE",
        ]
        self.is_valid_config(data, "level", valid_levels)
        self.is_valid_config(
            data, "stream", ["ext://sys.stdout", "ext://sys.stderr"], "stream"
        )
        self.is_valid_config_type(data, "filename", [str], "file")
        self.is_valid_config(
            data,
            "when",
            [
                "s",
                "m",
                "h",
                "d",
                "midnight",
                "w0",
                "w1",
                "w2",
                "w3",
                "w4",
                "w5",
                "w6",
            ],
            "file",
            False,
        )
        self.is_valid_config_type(data, "backupCount", [int], "file")
        self.is_valid_config_type(data, "mailhost", [str], "smtp")
        self.is_valid_config_type(data, "fromaddr", [str], "smtp")
        self.is_valid_config_type(data, "toaddrs", [list], "smtp")
        self.is_valid_config_type(data, "subject", [str], "smtp")
        self.is_valid_config_type(data, "address", [list], "syslog")
        self.is_valid_config(
            data,
            "socktype",
            ["ext://socket.SOCK_STREAM", "ext://socket.SOCK_DGRAM"],
            "syslog",
        )

    @needs_scope("access:services")
    async def get(self, handler=""):
        current_config = get_config()
        try:
            if handler:
                log_config = current_config.get(handler)
                data = {"handler": handler, "configuration": log_config}
            else:
                data = []
                for handler in current_config:
                    data.append(
                        {
                            "handler": handler,
                            "configuration": current_config.get(handler),
                        }
                    )
            # return data dictionary with handler and configuration
            # key to keep consistent with return dict from drf services
            self.write(json.dumps(data))
            self.set_status(200)
        except:
            self.set_status(400)

    @needs_scope("access:services")
    async def post(self):
        current_config = get_config()
        data = self.get_json_body()
        try:
            self.validate_data(data)
        except:
            self.set_status(400, self._errors)
            return
        handler = data.get("handler")
        if handler in current_config:
            # handler already exists
            self.set_status(400)
            return
        # get default config and overwrite as needed
        handler_config = copy.deepcopy(default_configurations[handler])
        for key, value in data.get("configuration").items():
            handler_config[key] = value
        create_logging_handler(current_config, handler, **handler_config)
        self.log.info(f"Created {handler} log handler", extra={"data": data})
        self.set_status(200)

    @needs_scope("access:services")
    async def patch(self, handler):
        current_config = get_config()
        data = self.get_json_body()
        try:
            self.validate_data(data)
        except:
            self.set_status(400, self._errors)
            return
        handler = data.get("handler")
        if handler not in current_config:
            self.set_status(400)
            return
        # get current config and overwrite as needed
        handler_config = copy.deepcopy(current_config[handler])
        for key, value in data.get("configuration").items():
            handler_config[key] = value
        remove_logging_handler(current_config, handler)
        create_logging_handler(current_config, handler, **handler_config)
        self.log.info(f"Updated {handler} log handler", extra={"data": data})
        self.set_status(200)

    @needs_scope("access:services")
    async def delete(self, handler):
        current_config = get_config()
        if handler not in current_config:
            self.set_status(400)
            return
        remove_logging_handler(current_config, handler)
        self.log.info(f"Removed {handler} log handler")
        self.set_status(200)


class DRFServiceLogLevelAPIHandler(RequestAPIHandler):
    async def _drf_request(self, service, handler="", method="GET", body=None):
        custom_config = get_custom_config()
        uuidcode = uuid4().hex
        action = f"loglevel_{method}"
        req_prop = self.get_req_prop(custom_config, service, uuidcode)

        log_url = req_prop.get("urls", {}).get("logs", "None")
        if handler:
            log_url = log_url + handler + "/"
        req = HTTPRequest(
            log_url,
            method=method,
            headers=req_prop["headers"],
            **req_prop.get("request_kwargs", {}),
        )
        if body:
            req.body = json.dumps(body)
        resp_json = await self.send_request(req, action, uuidcode)
        return resp_json

    @needs_scope("access:services")
    async def get(self, service, handler=""):
        resp = await self._drf_request(service, handler)
        self.write(json.dumps(resp))
        self.set_status(200)

    @needs_scope("access:services")
    async def post(self, service):
        await self._drf_request(service, method="POST", body=self.get_json_body())
        self.set_status(200)

    @needs_scope("access:services")
    async def patch(self, service, handler):
        if not handler:
            self.set_status(400)
            return
        await self._drf_request(
            service, handler, method="PUT", body=self.get_json_body()
        )
        self.set_status(200)

    @needs_scope("access:services")
    async def delete(self, service, handler):
        if not handler:
            self.set_status(400)
            return
        await self._drf_request(service, handler, method="DELETE")
        self.set_status(200)


class LoggingHandler(BaseHandler):
    @web.authenticated
    @needs_scope("access:services")
    async def get(self):
        user = self.current_user
        ns = await create_ns(user)
        ns.update(
            {
                "show_drf_logs": os.environ.get("SHOW_DRF_LOGS", "false").lower()
                in ["true", "1"]
            }
        )
        html = await self.render_template("logging.html", **ns)
        self.finish(html)


default_handlers.append((r"/api/logs/jhub/handler", JHubLogLevelAPIHandler))
default_handlers.append((r"/api/logs/jhub/handler/([^/]+)", JHubLogLevelAPIHandler))
default_handlers.append((r"/api/logs/([^/]+)/handler", DRFServiceLogLevelAPIHandler))
default_handlers.append(
    (r"/api/logs/([^/]+)/handler/([^/]+)", DRFServiceLogLevelAPIHandler)
)
default_handlers.append((r"/logging", LoggingHandler))
