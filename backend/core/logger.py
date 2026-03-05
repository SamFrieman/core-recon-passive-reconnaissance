"""
CoreRecon Structured Logging
Replaces all print() statements with proper logging.
"""
import logging
import sys
import json
from datetime import datetime


class JSONFormatter(logging.Formatter):
    """Emit log records as JSON lines for structured log ingestion."""

    def format(self, record: logging.LogRecord) -> str:
        log_object = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Include any extra fields passed via logger.info("...", extra={...})
        for key, value in record.__dict__.items():
            if key not in (
                "msg", "args", "levelname", "levelno", "pathname", "filename",
                "module", "exc_info", "exc_text", "stack_info", "lineno",
                "funcName", "created", "msecs", "relativeCreated", "thread",
                "threadName", "processName", "process", "name", "message",
            ):
                log_object[key] = value

        if record.exc_info:
            log_object["exc"] = self.formatException(record.exc_info)

        return json.dumps(log_object)


def get_logger(name: str) -> logging.Logger:
    """Return a named logger with structured JSON output to stdout."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger


# Root application logger
log = get_logger("corerecon")
