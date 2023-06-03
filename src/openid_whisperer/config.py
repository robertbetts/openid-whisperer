""" Configuration module
"""
import logging
from logging import Formatter as LogFormatter
import sys

import os


IDP_SERVICE_HOST: str = os.getenv("IDP_SERVICE_HOST", "openid-whisperer")
IDP_SERVICE_BINDING: str = os.getenv("IDP_SERVICE_BINDING", "0.0.0.0")
IDP_SERVICE_PORT: int = int(os.getenv("IDP_SERVICE_PORT", "5000"))
IDP_BASE_URL: str = f"https://{IDP_SERVICE_HOST}:{IDP_SERVICE_PORT}"
FLASK_DEBUG: bool = bool(os.getenv("FLASK_DEBUG", "True"))


class Config:
    DEFAULT_LOGGING_FORMAT = \
        "[%(levelname)1.1s %(asctime)s.%(msecs)03d %(process)d %(module)s:%(lineno)d %(name)s] %(message)s"

    def __init__(self):
        self.logging = "debug"

    def initialize_logging(self):
        logger = logging.getLogger()
        logger.handlers = []
        channel = logging.StreamHandler(stream=sys.stdout)
        channel.setFormatter(LogFormatter(fmt=self.DEFAULT_LOGGING_FORMAT))
        logger.addHandler(channel)
        logger.setLevel(getattr(logging, self.logging.upper()))
        logging.getLogger("asyncio").setLevel(logging.INFO)
        logging.info('Logging initialized')


config = Config()
