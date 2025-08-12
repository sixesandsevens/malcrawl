import logging


def with_ctx(logger_name="malcrawl"):
    return logging.getLogger(logger_name)


def bind(logger, **extra):
    # Return a LoggerAdapter that injects extra fields
    return logging.LoggerAdapter(logger, extra)
