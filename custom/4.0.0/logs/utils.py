import copy
import json
import logging
import os
import socket
import sys

from jsonformatter import JsonFormatter

logged_logger_name = os.environ.get("LOGGER_NAME", "JupyterHub")
logger_name = "JupyterHub"


class SafeToCopyFileHandler(logging.FileHandler):
    def __init__(self, filename):
        self.__filename = filename
        super().__init__(filename)

    def __deepcopy__(self, memodict={}):
        result = type(self)(filename=self.__filename)
        result.setLevel(self.level)
        result.setFormatter(self.formatter)
        return result


class ExtraFormatter(logging.Formatter):
    dummy = logging.LogRecord(None, None, None, None, None, None, None)
    ignored_extras = [
        "args",
        "asctime",
        "created",
        "exc_info",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "message",
        "module",
        "msecs",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "thread",
        "threadName",
    ]

    def format(self, record):
        extra_txt = ""
        for k, v in record.__dict__.items():
            if k not in self.dummy.__dict__ and k not in self.ignored_extras:
                extra_txt += " --- {}={}".format(k, v)
        message = super().format(record)
        return message + extra_txt


# Translate level to int
def get_level(level_str):
    if type(level_str) == int:
        return level_str
    elif level_str.upper() in logging._nameToLevel.keys():
        return logging._nameToLevel[level_str.upper()]
    elif level_str.upper() == "TRACE":
        return 5
    elif level_str.upper().startswith("DEACTIVATE"):
        return 99
    else:
        try:
            return int(level_str)
        except ValueError:
            pass
    raise NotImplementedError(f"{level_str} as level not supported.")


# supported classes
supported_handler_classes = {
    "stream": logging.StreamHandler,
    "file": logging.handlers.TimedRotatingFileHandler,
    "smtp": logging.handlers.SMTPHandler,
    "syslog": logging.handlers.SysLogHandler,
}

# supported formatters and their arguments
supported_formatter_classes = {"json": JsonFormatter, "simple": ExtraFormatter}
json_fmt = {
    "asctime": "asctime",
    "levelno": "levelno",
    "levelname": "levelname",
    "logger": logged_logger_name,
    "file": "pathname",
    "line": "lineno",
    "function": "funcName",
    "Message": "message",
}
simple_fmt = f"%(asctime)s logger={logged_logger_name} levelno=%(levelno)s levelname=%(levelname)s file=%(pathname)s line=%(lineno)d function=%(funcName)s : %(message)s"
supported_formatter_kwargs = {
    "json": {"fmt": json_fmt, "mix_extra": True},
    "simple": {"fmt": simple_fmt},
}


def create_logging_handler(config, handler_name, **configuration):
    configuration_copy = copy.deepcopy(configuration)

    formatter_name = configuration.pop("formatter")
    level = get_level(configuration.pop("level"))

    # catch some special cases
    for key, value in configuration.items():
        if key == "stream":
            if value == "ext://sys.stdout":
                configuration["stream"] = sys.stdout
            elif value == "ext://sys.stderr":
                configuration["stream"] = sys.stderr
        elif key == "socktype":
            if value == "ext://socket.SOCK_STREAM":
                configuration["socktype"] = socket.SOCK_STREAM
            elif value == "ext://socket.SOCK_DGRAM":
                configuration["socktype"] = socket.SOCK_DGRAM
        elif key == "address":
            configuration["address"] = tuple(value)

    # Create handler, formatter, and add it
    handler = supported_handler_classes[handler_name](**configuration)
    formatter = supported_formatter_classes[formatter_name](
        **supported_formatter_kwargs[formatter_name]
    )
    handler.name = handler_name
    handler.setLevel(level)
    handler.setFormatter(formatter)
    logger = logging.getLogger(logger_name)
    logger.addHandler(handler)

    current_handler_config = {}
    for key, value in configuration_copy.items():
        current_handler_config[key] = value
    config[handler_name] = current_handler_config

    with open(os.environ.get("LOGGING_CONFIG_FILE", "logging.json"), "w") as f:
        f.write(json.dumps(config, indent=2, sort_keys=True))

    if "filename" in configuration_copy:
        configuration_copy["file_name"] = configuration_copy["filename"]
        del configuration_copy["filename"]
    log = logging.getLogger(logger_name)
    log.debug(f"Logging handler added ({handler_name})", extra=configuration_copy)


def remove_logging_handler(config, handler_name):
    logger = logging.getLogger(logger_name)
    logger_handlers = logger.handlers
    logger.handlers = [x for x in logger_handlers if x.name != handler_name]

    del config[handler_name]
    with open(os.environ.get("LOGGING_CONFIG_FILE", "logging.json"), "w") as f:
        f.write(json.dumps(config, indent=2, sort_keys=True))
