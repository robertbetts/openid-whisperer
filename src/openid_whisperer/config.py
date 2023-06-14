""" Configuration module for OpenID Whisperer
"""
import logging
from logging import Formatter as LogFormatter
from typing import Tuple, Optional
import sys
import os
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from dotenv import load_dotenv, dotenv_values
NO_PROXY_PRE: str = os.getenv("NO_PROXY", "")
load_dotenv(".env", override=True, interpolate=True)
ENVIRONMENT: str = os.getenv("ENVIRONMENT", "TEST")
dotenv_file: str = f".env_{ENVIRONMENT.lower()}"
load_dotenv(f"{dotenv_file}", override=True)
NO_PROXY: str = os.getenv("NO_PROXY", "")
print(f"Ensure an appropriate env var for NO_PROXY is set before starting. Currently is: {NO_PROXY}")
for key, value in dotenv_values().items():
    print(f"{key}={value}")

IDP_SERVICE_HOST_GW: str = os.getenv("IDP_SERVICE_HOST_GW", "192.168.56.102")
IDP_SERVICE_PORT_GW: str = os.getenv("IDP_SERVICE_PORT_GW", "8100")
IDP_SERVICE_HOST: str = os.getenv("IDP_SERVICE_HOST", "10.95.55.84")
IDP_SERVICE_BINDING: str = os.getenv("IDP_SERVICE_BINDING", "0.0.0.0")
IDP_SERVICE_PORT: int = int(os.getenv("IDP_SERVICE_PORT", "5000"))
IDP_BASE_URL: str = f"https://{IDP_SERVICE_HOST}:{IDP_SERVICE_PORT_GW}"
IDP_BASE_URL_GW = f"https://{IDP_SERVICE_HOST_GW}:{IDP_SERVICE_PORT_GW}/adfs/"
FLASK_DEBUG: bool = bool(os.getenv("FLASK_DEBUG", "True").lower() == "true")

CA_KEY_FILENAME: str = os.getenv("CA_KEY_FILENAME", "ca_key.pem")
CA_KEY_PASSWORD: str = os.getenv("CA_CERT_PASSWORD", "")
CA_CERT_FILENAME: str = os.getenv("CA_CERT_FILENAME", "ca_cert.pem")
ORG_KEY_FILENAME: str = os.getenv("ORG_KEY_FILENAME", "key.pem")
ORG_KEY_PASSWORD: str = os.getenv("ORG_KEY_PASSWORD", "")
ORG_CERT_FILENAME: str = os.getenv("ORG_CERT_FILENAME", "cert.pem")


def init_certs(
        ca_key_filename: str = CA_KEY_FILENAME,
        ca_cert_filename: str = CA_CERT_FILENAME,
        org_key_filename: str = ORG_KEY_FILENAME,
        org_cert_filename: str = ORG_CERT_FILENAME,
) -> Optional[Tuple[rsa.RSAPrivateKey, x509.Certificate, rsa.RSAPrivateKey, x509.Certificate]]:
    """ Loads from files, CA and Org private keys and certificates.
        filenames are defaulted to the environment variables:
        CA_KEY_FILENAME, CA_CERT_FILENAME, ORG_KEY_FILENAME, ORG_CERT_FILENAME
    """
    ca_key: PrivateKeyTypes
    org_key: PrivateKeyTypes
    with open(ca_key_filename, "rb") as ca_key_file:
        with open(ca_cert_filename, "rb") as ca_cert_file:
            with open(org_key_filename, "rb") as org_key_file:
                with open(org_cert_filename, "rb") as org_cert_file:
                    ca_key_password = CA_KEY_PASSWORD.encode() if CA_KEY_PASSWORD else None
                    ca_cert: x509.Certificate = x509.load_pem_x509_certificate(ca_cert_file.read(), default_backend())
                    ca_key = serialization.load_pem_private_key(
                        data=ca_key_file.read(),
                        backend=default_backend(),
                        password=ca_key_password
                    )
                    if not isinstance(ca_key, rsa.RSAPrivateKey):
                        raise Exception("Only RSA private keys supported")  # pragma: no cover
                    org_key_password = ORG_KEY_PASSWORD.encode() if ORG_KEY_PASSWORD else None
                    org_cert: x509.Certificate = x509.load_pem_x509_certificate(org_cert_file.read(), default_backend())
                    org_key = serialization.load_pem_private_key(
                        data=org_key_file.read(),
                        backend=default_backend(),
                        password=org_key_password
                    )
                    if not isinstance(org_key, rsa.RSAPrivateKey):
                        raise Exception("Only RSA private keys supported")  # pragma: no cover
                    return ca_key, ca_cert, org_key, org_cert


class Config:
    DEFAULT_LOGGING_FORMAT = \
        "[%(levelname)1.1s %(asctime)s.%(msecs)03d %(process)d %(module)s:%(lineno)d %(name)s] %(message)s"

    def __init__(self) -> None:
        self.logging = "debug"
        certificates = init_certs()
        if certificates is None:
            raise Exception("Unable to initialise private keys and certificates") # pragma: no cover
        self.ca_key: rsa.RSAPrivateKey = certificates[0]
        self.ca_cert: x509.Certificate = certificates[1]
        self.org_key: rsa.RSAPrivateKey = certificates[2]
        self.org_cert: x509.Certificate = certificates[3]

    def initialize_logging(self) -> None:
        logger = logging.getLogger()
        logger.handlers = []
        channel = logging.StreamHandler(stream=sys.stdout)
        channel.setFormatter(LogFormatter(fmt=self.DEFAULT_LOGGING_FORMAT))
        logger.addHandler(channel)
        logger.setLevel(getattr(logging, self.logging.upper()))
        logging.info('Logging initialized')


config = Config()
