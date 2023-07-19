""" Configuration module shared across the sample apps that make use of OpenID for authorisation and authentication
"""
import logging
from logging import Formatter as LogFormatter
import sys
import os
from typing import Dict
from urllib.parse import urljoin, urlsplit, urlunsplit

from dotenv import load_dotenv, dotenv_values

dotenv_config: Dict[str, str] = {}
load_dotenv(".env", override=True, verbose=True)
dotenv_config.update(**dotenv_values(".env"))
for key, value in dotenv_config.items():
    print(f"{key}={value}")

API_SCHEME: str = os.getenv("API_SCHEME", "http").lower()
API_HOST: str = os.getenv("API_HOST", "localhost")
API_PORT: int = int(os.getenv("API_PORT", "5007"))
API_SCHEME_GW: str = os.getenv("API_SCHEME_GW", "http").lower()
API_HOST_GW: str = os.getenv("API_HOST_GW", "localhost")
API_PORT_GW: int = int(os.getenv("API_PORT_GW", "8100"))

ID_SERVICE_HOST: str = os.getenv("ID_SERVICE_HOST", "localhost")
ID_SERVICE_PORT: int = int(os.getenv("ID_SERVICE_PORT", "5000"))
ID_SERVICE_HOST_GW: str = os.getenv("ID_SERVICE_HOST_GW", "localhost")
ID_SERVICE_PORT_GW: int = int(os.getenv("ID_SERVICE_PORT_GW", "8100"))

FLASK_DEBUG: bool = os.getenv("FLASK_DEBUG", "True").lower() == "true"
VALIDATE_CERTS: bool = os.getenv("VALIDATE_CERTS", "False").lower() != "false"

# Settings targeted for use by a client app (resource owner) or an end user or end user credential holder
TENANT: str = os.getenv("TENANT", "adfs")
CLIENT_ID: str = os.getenv("CLIENT_ID", "CLIENT-90274-DEV")
SCOPE: str = os.getenv("SCOPE", "openid profile")
RESOURCE_URI: str = os.getenv("RESOURCE_URI", "URI:API:CLIENT-90274-API")


class Config:
    DEFAULT_LOGGING_FORMAT = "[%(levelname)1.1s %(asctime)s.%(msecs)03d %(process)d %(module)s:%(lineno)d %(name)s] %(message)s"

    def __init__(self) -> None:
        self.logging = "debug"

        self.identity_endpoint = (
            f"https://{ID_SERVICE_HOST}:{ID_SERVICE_PORT}/adfs/"
        )
        self.identity_endpoint_gw = (
            f"https://{ID_SERVICE_HOST_GW}:{ID_SERVICE_PORT_GW}/adfs/"
        )

        self.api_scheme = API_SCHEME
        self.api_scheme_gw = API_SCHEME_GW
        self.api_host = API_HOST
        self.api_host_gw = API_HOST_GW
        self.api_port = API_PORT
        self.api_port_gw = API_PORT_GW
        self.api_endpoint = urlunsplit(
            (self.api_scheme, f"{self.api_host}:{self.api_port}", "adfs", "", "")
        )
        self.api_endpoint_gw = urlunsplit(
            (self.api_scheme_gw, f"{self.api_host_gw}:{self.api_port_gw}", "adfs", "", "")
        )
        self.authorize_path: str = "/mock-api/handleAccessToken"
        self.logout_path: str = "/mock-api/handleAccessToken"

        self.tenant: str = TENANT
        self.client_id: str = CLIENT_ID
        self.scope: str = SCOPE
        self.resource_uri: str = RESOURCE_URI
        self.audience = [self.client_id, self.resource_uri]

        self.validate_certs = VALIDATE_CERTS
        self.flask_debug = FLASK_DEBUG

    def initialize_logging(self) -> None:
        logger = logging.getLogger()
        logger.handlers = []
        channel = logging.StreamHandler(stream=sys.stdout)
        channel.setFormatter(LogFormatter(fmt=self.DEFAULT_LOGGING_FORMAT))
        logger.addHandler(channel)
        logger.setLevel(getattr(logging, self.logging.upper()))
        logging.getLogger("asyncio").setLevel(logging.INFO)
        logging.info("Logging initialized")

    def get_authorize_cb(self, use_gw: bool = True):
        return self.make_external_url(self.authorize_path, use_gw)

    def make_external_url(self, service_url: str = None, use_gw: bool = True):
        """ Adjust the input service_url to have the correct scheme and network location. Assumed that by default,
        incoming requests will come in through the gateway unless use_gw is False
        """
        if not service_url:
            return self.api_endpoint_gw if use_gw else self.api_endpoint

        url_parts = urlsplit(service_url)
        if use_gw:
            netloc = f"{self.api_host_gw}:{self.api_port_gw}"
            service_url = urlunsplit(
                (self.api_scheme_gw, netloc, url_parts.path, url_parts.query, url_parts.fragment)
            )
        else:
            netloc = f"{self.api_host}:{self.api_port}"
            service_url = urlunsplit(
                (self.api_scheme_gw, netloc, url_parts.path, url_parts.query, url_parts.fragment)
            )

        return service_url


config = Config()
