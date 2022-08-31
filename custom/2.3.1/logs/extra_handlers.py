import json
import logging
import os

from .utils import ExtraFormatter, SafeToCopyFileHandler
from .utils import create_logging_handler

logger_name = os.environ.get("LOGGER_NAME", "JupyterHub")

log = logging.getLogger(logger_name)


def create_extra_handlers():
    if os.environ.get("LOGGING_METRICS_ENABLED", "false").lower() in ["true", "1"]:
        STRING_FORMAT_METRIC = "%(asctime)s;%(message)s"

        metricFormatter = ExtraFormatter(STRING_FORMAT_METRIC, "%Y_%m_%d-%H_%M_%S")
        metric_logger = logging.getLogger('Metrics')
        metric_logger.setLevel(20)

        from datetime import datetime
        now = datetime.now()
        current_time = now.strftime("%Y_%m_%d-%H_%M_%S")
        metric_filename = "{}-{}".format(os.environ.get(
            "LOGGING_METRICS_LOGFILE", "/mnt/logs/metrics.log"
        ), current_time)

        metric_filehandler = SafeToCopyFileHandler(metric_filename)
        metric_filehandler.setFormatter(metricFormatter)
        metric_filehandler.setLevel(20)
        metric_logger.addHandler(metric_filehandler)

    # Remove default StreamHandler
    console_handler = log.handlers[0]
    log.removeHandler(console_handler)

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
