""" Configuration module for OpenID Whisperer
"""
import logging
from logging import Formatter as LogFormatter
from typing import Tuple, Optional
import sys
import os
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from openid_whisperer.utils.config_utils import (
    load_environment_variables,
    default_config_type,
    get_bind_address,
    initialize_logging,
)

logger = logging.getLogger(__name__)
cached_config = None


class ConfigurationException(Exception):
    ...


class Config:
    default_config: default_config_type = {
        "instance_id": (str, uuid4().hex),
        "gateway_address": (str, "localhost:8100"),
        "bind_address": (get_bind_address, "0.0.0.0:8100,[::]:8100"),
        "log_level": (str, "DEBUG"),
        "ca_key_filename": (str, "certs/ca_key.pem"),
        "ca_key_password": (str, ""),
        "ca_cert_filename": (str, "certs/ca_cert.pem"),
        "org_key_filename": (str, "certs/key.pem"),
        "org_key_password": (str, ""),
        "org_cert_filename": (str, "certs/cert.pem"),
    }

    def __new__(cls, *args, **kwargs):
        instance = super().__new__(cls)
        for key, value in cls.default_config.items():
            _, default = value
            if not key.isidentifier():
                raise ValueError(
                    "default attribute %s, is not a valid identifier name", key
                )
            setattr(instance, key, default)
        return instance

    def __init__(
        self, defaults: default_config_type = {}, env_target: str | None = None
    ) -> None:
        self.init_defaults = {}
        self.init_defaults.update(defaults)
        self.env_target: str | None = env_target
        self.load_config()
        self.init_logging()
        self.init_certs()

    def load_config(self):
        load_environment_variables(env_target=self.env_target)
        config_to_initialise: default_config_type = self.default_config.copy()
        config_to_initialise.update(self.init_defaults)
        for key, value in config_to_initialise.items():
            try:
                if key not in self.default_config:
                    logging.error("Invalid config parameter %s, ignoring", key)
                    continue

                func, default = value
                env_var: str = os.environ.get(key.upper(), default)
                try:
                    setattr(self, key, func(env_var))
                except Exception as e:
                    logging.warning(
                        "Unable to set config parameter %s, using default value %s"
                        "\nError: %s",
                        key.upper(),
                        default,
                        e,
                    )
            except Exception as e:
                default = getattr(self, key)
                logging.error(
                    "Configuration error while Unable to for process environment variable %s"
                    "defaulting to %s \nError: %s",
                    key,
                    default,
                    e,
                )

    def init_logging(self, log_level: str | None = None):
        log_level = log_level if log_level else self.log_level
        initialize_logging(log_level=log_level)

    def init_certs(self) -> None:
        """Loads from files, CA and Org private keys and certificates. filenames are defaulted from
        the environment variables:
           CA_KEY_FILENAME, CA_CERT_FILENAME, ORG_KEY_FILENAME, ORG_CERT_FILENAME
        """
        ca_key: PrivateKeyTypes
        org_key: PrivateKeyTypes
        with open(self.ca_key_filename, "rb") as ca_key_file:
            with open(self.ca_cert_filename, "rb") as ca_cert_file:
                with open(self.org_key_filename, "rb") as org_key_file:
                    with open(self.org_cert_filename, "rb") as org_cert_file:
                        ca_key_password = (
                            self.ca_key_password.encode()
                            if self.ca_key_password
                            else None
                        )
                        ca_cert: x509.Certificate = x509.load_pem_x509_certificate(
                            ca_cert_file.read(), default_backend()
                        )
                        ca_key = serialization.load_pem_private_key(
                            data=ca_key_file.read(),
                            backend=default_backend(),
                            password=ca_key_password,
                        )
                        if not isinstance(ca_key, rsa.RSAPrivateKey):
                            raise ConfigurationException(
                                "Only RSA private keys supported"
                            )  # pragma: no cover
                        org_key_password = (
                            self.org_key_password.encode()
                            if self.org_key_password
                            else None
                        )
                        org_cert: x509.Certificate = x509.load_pem_x509_certificate(
                            org_cert_file.read(), default_backend()
                        )
                        org_key = serialization.load_pem_private_key(
                            data=org_key_file.read(),
                            backend=default_backend(),
                            password=org_key_password,
                        )
                        if not isinstance(org_key, rsa.RSAPrivateKey):
                            raise ConfigurationException(
                                "Only RSA private keys supported"
                            )  # pragma: no cover

                        self.ca_key: rsa.RSAPrivateKey = ca_key
                        self.ca_cert: x509.Certificate = ca_cert
                        self.org_key: rsa.RSAPrivateKey = org_key
                        self.org_cert: x509.Certificate = org_cert


def get_cached_config(*args, **kwargs) -> Config:
    """if an already cached config exists, then return an instance of that and if not then
    initialise a new instance of the Config class.
    """
    global cached_config
    if cached_config is None:
        cached_config = Config(*args, **kwargs)
    return cached_config


ID_SERVICE_HOST_GW: str = os.getenv("ID_SERVICE_HOST_GW", "localhost")
ID_SERVICE_PORT_GW: str = os.getenv("ID_SERVICE_PORT_GW", "8100")
ID_SERVICE_HOST: str = os.getenv("ID_SERVICE_HOST", "localhost")
ID_SERVICE_BINDING: str = os.getenv("ID_SERVICE_BINDING", "0.0.0.0")
ID_SERVICE_PORT: int = int(os.getenv("ID_SERVICE_PORT", "5000"))
IDP_BASE_URL: str = f"https://{ID_SERVICE_HOST}:{ID_SERVICE_PORT_GW}"
IDP_BASE_URL_GW = f"https://{ID_SERVICE_HOST_GW}:{ID_SERVICE_PORT_GW}/adfs/"
FLASK_DEBUG: bool = bool(os.getenv("FLASK_DEBUG", "True").lower() == "true")

# CA_KEY_FILENAME: str = os.getenv("CA_KEY_FILENAME", "certs/root_ca_key.pem")
# CA_KEY_PASSWORD: str = os.getenv("CA_CERT_PASSWORD", "")
# CA_CERT_FILENAME: str = os.getenv("CA_CERT_FILENAME", "certs/root_ca_cert.pem")
# ORG_KEY_FILENAME: str = os.getenv("ORG_KEY_FILENAME", "certs/key.pem")
# ORG_KEY_PASSWORD: str = os.getenv("ORG_KEY_PASSWORD", "")
# ORG_CERT_FILENAME: str = os.getenv("ORG_CERT_FILENAME", "certs/cert.pem")
