import json
import logging
import os

from .utils import create_logging_handler
from .utils import ExtraFormatter
from .utils import SafeToCopyFileHandler

logger_name = os.environ.get("LOGGER_NAME", "JupyterHub")

log = logging.getLogger("JupyterHub")


def create_extra_handlers():
    # Remove default StreamHandler
    if len(log.handlers) > 0:
        log.removeHandler(log.handlers[0])

    # In trace will be sensitive information like tokens
    logging.addLevelName(5, "TRACE")

    def trace_func(self, message, *args, **kws):
        if self.isEnabledFor(5):
            # Yes, logger takes its '*args' as 'args'.
            self._log(5, message, args, **kws)

    logging.Logger.trace = trace_func
    log.setLevel(5)

    try:
        with open(os.environ.get("LOGGING_CONFIG_FILE", "logging.json"), "r") as f:
            config = json.load(f)
    except:
        config = default_configurations

    for name, configuration in config.items():
        create_logging_handler(config, name, **configuration)

    return []


default_configurations = {
    "stream": {
        "formatter": "simple",
        "level": 20,
        "stream": "ext://sys.stdout",
    },
    "file": {
        "formatter": "simple",
        "level": 20,
        "filename": "/tmp/file.log",
        "when": "midnight",
        "backupCount": 7,
    },
    # "smtp": {
    #     "formatter": "simple",
    #     "level": 20,
    #     "mailhost": "",
    #     "fromaddr": "",
    #     "toaddrs": [],
    #     "subject": "",
    # },
    "syslog": {
        "formatter": "json",
        "level": 20,
        "address": ["127.0.0.1", 514],
        "socktype": "ext://socket.SOCK_DGRAM",
    },
}
