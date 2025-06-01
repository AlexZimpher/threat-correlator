import logging
import os

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
LOG_LEVEL = logging.INFO  # Default log level if not overridden


def setup_logging():
    """
    Configure the root logger to log to console and, if specified,
    to a file (via THREATCORRELATOR_LOG_FILE environment variable).
    """
    logger = logging.getLogger()
    # Use level from env var if set, else default
    level = os.getenv("LOG_LEVEL", LOG_LEVEL)
    logger.setLevel(level)

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch_formatter = logging.Formatter(LOG_FORMAT)
    ch.setFormatter(ch_formatter)
    logger.addHandler(ch)

    # Optional file handler if THREATCORRELATOR_LOG_FILE is defined
    log_file = os.getenv("THREATCORRELATOR_LOG_FILE")
    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setLevel(level)
        fh_formatter = logging.Formatter(LOG_FORMAT)
        fh.setFormatter(fh_formatter)
        logger.addHandler(fh)
