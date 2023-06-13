""" Configuration module
"""
import logging
from logging import Formatter as LogFormatter
import sys
import os

from dotenv import load_dotenv
load_dotenv()

API_HOST: str = os.getenv("API_HOST", "10.95.55.84")
API_PORT: int = int(os.getenv("API_PORT", "5007"))
API_HOST_GW: str = os.getenv("API_HOST_GW", "192.168.56.102")
API_PORT_GW: int = int(os.getenv("API_PORT_GW", "8100"))

IDP_SERVICE_HOST: str = os.getenv("IDP_SERVICE_HOST", "openid-whisperer")
IDP_SERVICE_PORT: int = int(os.getenv("IDP_SERVICE_PORT", "5000"))
IDP_SERVICE_HOST_GW: str = os.getenv("IDP_SERVICE_HOST_GW", "openid-whisperer")
IDP_SERVICE_PORT_GW: int = int(os.getenv("IDP_SERVICE_PORT_GW", "8100"))

FLASK_DEBUG: bool = os.getenv("FLASK_DEBUG", "True").lower() == "true"
VALIDATE_CERTS: bool = os.getenv("VALIDATE_CERTS", "False").lower() != "false"

CLIENT_ID: str = os.getenv("CLIENT_ID", "PC-90274-SID-12655-DEV")
RESOURCE_URI: str = os.getenv("RESOURCE_URI", "URI:API:RS-104134-21171-mock-api-PROD")


class Config:
    DEFAULT_LOGGING_FORMAT = \
        "[%(levelname)1.1s %(asctime)s.%(msecs)03d %(process)d %(module)s:%(lineno)d %(name)s] %(message)s"

    def __init__(self):
        self.logging = "debug"
        self.api_host = API_HOST
        self.api_port = API_PORT
        self.gw_host = API_HOST_GW
        self.gw_port = API_PORT_GW
        self.identity_endpoint = f"https://{IDP_SERVICE_HOST}:{IDP_SERVICE_PORT}/adfs/"
        self.identity_endpoint_gw = f"https://{IDP_SERVICE_HOST_GW}:{IDP_SERVICE_PORT_GW}/adfs/"

        self.api_endpoint = f"https://{API_HOST}:{API_PORT}/adfs/"
        self.api_endpoint_gw = f"https://{API_HOST_GW}:{API_PORT_GW}/adfs/"


        self.redirect_url: str = f"https://{self.gw_host}:{self.gw_port}/mock-api/handleAccessToken"
        self.client_id: str = CLIENT_ID
        self.resource_uri: str = RESOURCE_URI
        self.audience = [self.client_id, self.resource_uri]

        self.validate_certs = VALIDATE_CERTS
        self.flask_debug = FLASK_DEBUG

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
