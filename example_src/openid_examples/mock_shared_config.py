""" Configuration module shared across the sample apps that make use of OpenID for authorisation and authentication
"""
import logging
import os
from typing import Dict
from urllib.parse import urlunsplit

from dotenv import load_dotenv, dotenv_values

from openid_whisperer.utils.config_utils import initialize_logging as init_logging


dotenv_config: Dict[str, str] = {}
load_dotenv(".env", override=True, verbose=True)
dotenv_config.update(**dotenv_values(".env"))
for key, value in dotenv_config.items():
    print(f"{key}={value}")

API_SCHEME: str = os.getenv("API_SCHEME", "http").lower()
API_HOST: str = os.getenv("API_HOST", "localhost")
API_PORT: int = int(os.getenv("API_PORT", "5007"))

ID_SERVICE_HOST: str = os.getenv("ID_SERVICE_HOST", "localhost")
ID_SERVICE_PORT: int = int(os.getenv("ID_SERVICE_PORT", "5000"))
ID_SERVICE_TENANT: str = os.getenv("ID_SERVICE_TENANT", "adfs")

FLASK_DEBUG: bool = os.getenv("FLASK_DEBUG", "True").lower() == "true"
VALIDATE_CERTS: bool = os.getenv("VALIDATE_CERTS", "False").lower() != "false"

# Settings targeted for use by a client app (resource owner) or an end user or end user credential holder
TENANT: str = os.getenv("TENANT", "adfs")
CLIENT_ID: str = os.getenv("CLIENT_ID", "CLIENT-5700-DEV")
SCOPE: str = os.getenv("SCOPE", "openid profile")
RESOURCE_URI: str = os.getenv("RESOURCE_URI", "URI:API:CLIENT-5700-API")


class Config:
    DEFAULT_LOGGING_FORMAT = (
        "[%(levelname)1.1s %(asctime)s.%(msecs)03d %(process)d %(module)s:%(lineno)d %(name)s] %(message)s"
    )

    def __init__(self) -> None:
        self.logging = "debug"

        self.api_scheme = API_SCHEME
        self.api_host = API_HOST
        self.api_port = API_PORT
        self.api_endpoint = urlunsplit(
            (self.api_scheme, f"{self.api_host}:{self.api_port}", "", "", "")
        )

        self.tenant: str = TENANT
        self.client_id: str = CLIENT_ID
        self.identity_endpoint = f"https://{ID_SERVICE_HOST}:{ID_SERVICE_PORT}/{self.tenant}/"
        self.scope: str = SCOPE
        self.resource_uri: str = RESOURCE_URI
        self.audience = [self.client_id, self.resource_uri]

        self.validate_certs = VALIDATE_CERTS
        self.flask_debug = FLASK_DEBUG

    def initialize_logging(self) -> None:
        init_logging(log_level=self.logging)
        logging.getLogger("asyncio").setLevel(logging.INFO)


config = Config()
