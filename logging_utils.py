import logging
import time
from collections import deque
from datetime import datetime


# ring buffer of latest N log lines for the UI
LOG_BUFFER = deque(maxlen=2000)


class UIBufferHandler(logging.Handler):
    def __init__(self, level=logging.INFO):
        super().__init__(level)
        self.setFormatter(
            logging.Formatter(
                "%(levelname)s %(asctime)s %(name)s: %(message)s",
                datefmt="%H:%M:%S",
            )
        )

    def emit(self, record):
        try:
            msg = self.format(record)
            LOG_BUFFER.append({"id": time.time_ns(), "text": msg})
        except Exception:
            self.handleError(record)


def with_ctx(logger_name="malcrawl"):
    return logging.getLogger(logger_name)


def bind(logger, **extra):
    # Return a LoggerAdapter that injects extra fields
    return logging.LoggerAdapter(logger, extra)
