import logging
import os

def logger_setup(logger_name: str | None = None) -> logging.Logger:
    logger = logging.getLogger(logger_name)
    log_level = getattr(logging, os.getenv("LOG_LEVEL", "INFO"), logging.INFO)
    logger.setLevel(level=log_level)

    return logger

logger = logger_setup()