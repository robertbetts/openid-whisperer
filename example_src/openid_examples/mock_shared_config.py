""" Configuration module shared across the sample apps that make use of OpenID for authorisation and authentication
"""
import logging
from logging import Formatter as LogFormatter
import sys
import os
from typing import Dict

from dotenv import load_dotenv, dotenv_values

dotenv_config: Dict[str, str] = {}
load_dotenv(".env", override=True)
dotenv_config.update(**dotenv_values(".env"))
ENVIRONMENT: str = os.getenv("ENVIRONMENT", "TEST")
dotenv_file: str = f".env_{ENVIRONMENT.upper()}"
load_dotenv(dotenv_file, override=True)
dotenv_config.update(**dotenv_values(dotenv_file))
print(f".env, {dotenv_file} loaded variables:")
for key, value in dotenv_config.items():
    print(f"{key}={value}")
print("\n")

NO_PROXY: str = os.getenv("NO_PROXY", "")
print(
    f"""In enterprise environments,the NO_PROXY setting significantly affects the operation
of these examples. make sure it is appropriate for your use case. Currently the setting is:
NO_PROXY={NO_PROXY}
"""
)

API_HOST: str = os.getenv("API_HOST", "10.95.55.84")
API_PORT: int = int(os.getenv("API_PORT", "5007"))
API_HOST_GW: str = os.getenv("API_HOST_GW", "192.168.56.102")
API_PORT_GW: int = int(os.getenv("API_PORT_GW", "8100"))

ID_SERVICE_HOST: str = os.getenv("ID_SERVICE_HOST", "openid-whisperer")
ID_SERVICE_PORT: int = int(os.getenv("ID_SERVICE_PORT", "5000"))
ID_SERVICE_HOST_GW: str = os.getenv("ID_SERVICE_HOST_GW", "openid-whisperer")
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
        self.api_host = API_HOST
        self.api_port = API_PORT
        self.gw_host = API_HOST_GW
        self.gw_port = API_PORT_GW
        self.identity_endpoint = f"https://{ID_SERVICE_HOST}:{ID_SERVICE_PORT}/adfs/"
        self.identity_endpoint_gw = (
            f"https://{ID_SERVICE_HOST_GW}:{ID_SERVICE_PORT_GW}/adfs/"
        )

        self.api_endpoint = f"https://{API_HOST}:{API_PORT}/adfs/"
        self.api_endpoint_gw = f"https://{API_HOST_GW}:{API_PORT_GW}/adfs/"

        self.redirect_url: str = (
            f"https://{self.gw_host}:{self.gw_port}/mock-api/handleAccessToken"
        )

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


config = Config()
