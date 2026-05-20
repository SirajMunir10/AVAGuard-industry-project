import logging
import logging.config
import logging.handlers
import json
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    """Outputs log records as single-line JSON for log aggregators."""

    def format(self, record: logging.LogRecord) -> str:
        log_obj = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_obj)


def configure_logging(
    level: str = "INFO",
    json_output: bool = False,
    log_file: str = None
) -> None:
    """
    Configure logging for AVAGuard modules.
    Call ONCE at application startup only (CLI or Desktop entry point).
    Do NOT call from library code.

    Args:
        level: Log level ('DEBUG', 'INFO', 'WARNING', 'ERROR')
        json_output: True for JSON format, False for human-readable
        log_file: Optional path for rotating file output
    """
    handlers = {
        "console": {
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stderr",
            "formatter": "json" if json_output else "human",
        }
    }

    if log_file:
        handlers["file"] = {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": log_file,
            "maxBytes": 10 * 1024 * 1024,  # 10MB
            "backupCount": 5,
            "formatter": "json",
            "encoding": "utf-8",
        }

    config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "json": {"()": JSONFormatter},
            "human": {
                "format": "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S",
            },
        },
        "handlers": handlers,
        "root": {
            "level": level,
            "handlers": list(handlers.keys()),
        },
        "loggers": {
            "avaguard_core": {"level": level, "propagate": True},
            "avaguard":      {"level": level, "propagate": True},
            "django":        {"level": "WARNING", "propagate": True},
            "urllib3":       {"level": "WARNING", "propagate": True},
            "msal":          {"level": "WARNING", "propagate": True},
        },
    }

    logging.config.dictConfig(config)
