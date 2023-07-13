""" Configuration module for Openid_whisperer
"""
import importlib.resources
import logging
import os
from uuid import uuid4
from typing import Type, Optional, Tuple, TextIO, Any, Dict, Iterable

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from openid_whisperer.utils.common import boolify
from openid_whisperer.utils.config_utils import (
    load_environment_variables,
    default_config_type,
    initialize_logging,
)

_cached_config: Optional["Config"] = None


class ConfigurationException(Exception):
    ...


class Config:
    default_config: default_config_type = {
        "instance_id": (str, uuid4().hex),
        "log_level": (str, "info"),
        "flask_debug": (boolify, False),
        "validate_certs": (boolify, False),
        "id_service_prefix": (str, "/adfs"),
        "id_service_port": (int, 5005),
        "id_service_host": (str, "localhost"),
        "id_service_bind": (str, "0.0.0.0"),
        "id_service_port_gw": (int, 5005),
        "id_service_host_gw": (str, "localhost"),
        "validate_users": (boolify, False),
        "json_user_file": (str, ""),
        "session_expiry_seconds": (int, 0),
        "maximum_login_attempts": (int, 0),
        "ca_cert_filename": (str, ""),
        "org_key_filename": (str, ""),
        "org_key_password": (str, ""),
        "org_cert_filename": (str, ""),
    }

    # General configuration parameters
    env_target: str | None
    log_level: str
    flask_debug: bool
    validate_certs: bool

    # Networking related configuration
    id_service_prefix: str
    id_service_port: int
    id_service_host: str
    id_service_bind: str
    id_service_port_gw: str
    id_service_host_gw: str

    # Credential related configuration
    validate_users: bool
    json_user_file: str
    session_expiry_seconds: int
    maximum_login_attempts: int

    # Credential and Web API related configuration. If not all the configuration entries
    # for these filenames are entered, then the demo certs in this package are used.
    ca_cert_filename: str  # this entry is not mandatory
    org_key_filename: str
    org_key_password: str
    org_cert_filename: str

    # These class properties are initialised by self.init_certs()
    ca_cert: Optional[x509.Certificate]
    org_key: rsa.RSAPrivateKey
    org_cert: x509.Certificate

    def __new__(cls, *args, **kwargs):
        instance = super().__new__(cls)
        init_config = {}
        init_config.update(cls.default_config)
        if "defaults" in kwargs and isinstance(kwargs["defaults"], dict):
            init_config.update(kwargs["defaults"])
        for key, value in init_config.items():
            _, default = value
            if not key.isidentifier():
                raise ValueError(f"Configuration property {key}, is not valid.")
            setattr(instance, key, default)
        return instance

    def __init__(
        self, defaults: default_config_type | None = None, env_target: str | None = None
    ) -> None:
        defaults = {} if defaults is None else defaults
        self.env_target = env_target

        self.ca_cert_filename: str = ""
        self.org_key_filename: str = ""
        self.org_key_password: str = ""
        self.org_cert_filename: str = ""

        self.init_defaults = {}
        self.init_defaults.update(defaults)
        self.load_config()
        self.init_logging()

        # Checking for the required certificate/key file pair, if not found then default
        # to the package provided demo certificate files, including a ca cert file.
        if not os.path.exists(self.org_key_filename) or not os.path.exists(
            self.org_cert_filename
        ):
            if self.org_key_filename and not os.path.exists(self.org_key_filename):
                logging.critical(f"Private key file not found: {self.org_key_filename}")
            if self.org_cert_filename and not os.path.exists(self.org_cert_filename):
                logging.critical(
                    f"Certificate file not found: {self.org_cert_filename}"
                )
            logging.critical("Defaulting to packaged demo certificate/key pair")
            with importlib.resources.files("openid_whisperer") as module_resource:
                self.ca_cert_filename = os.path.join(
                    module_resource, "demo_certs", "ca_cert.pem"
                )
                self.org_key_filename = os.path.join(
                    module_resource, "demo_certs", "key.pem"
                )
                self.org_cert_filename = os.path.join(
                    module_resource, "demo_certs", "cert.pem"
                )

        self.init_certs()

    @property
    def id_provider_base_url(self) -> str:
        """This url must be accessible to the client interacting with the identity provider"""
        return f"https://{self.id_service_host}:{self.id_service_port}"

    @property
    def id_provider_base_url_external(self) -> str:
        """This url must be accessible to the end user interacting with the identity provider"""
        return f"https://{self.id_service_host_gw}:{self.id_service_port_gw}"

    def load_config(self) -> None:
        load_environment_variables(env_target=self.env_target)
        config_to_initialise: default_config_type = self.default_config.copy()
        config_to_initialise.update(self.init_defaults)
        for key, value in config_to_initialise.items():
            func, default = value
            env_var: str = os.environ.get(key.upper(), default)
            try:
                key_value = func(env_var)
                setattr(self, key, key_value)
                logging.critical(f"{key.upper()}: {key_value}")
            except Exception as e:
                logging.warning(
                    "Unable to set config parameter %s, using default value %s"
                    "\nError: %s",
                    key,
                    default,
                    e,
                )

    def init_logging(self, log_level: str | None = None) -> None:
        log_level = log_level if log_level else self.log_level
        initialize_logging(log_level=log_level, logger_name="openid_whisperer")

    def init_certs(self) -> None:
        """Loads CA certificate and Org private key and certificate from PEM formatted files.

        Filenames are configured from the environment variables:
           CA_CERT_FILENAME, ORG_KEY_FILENAME, ORG_CERT_FILENAME

        If any of the files are missing, none of the certificates or private key are instantiated.
        """

        def load_cert_pair(
            cert_file: TextIO,
            key_file: Optional[TextIO] = None,
            key_password: Optional[str] = None,
        ) -> Tuple[x509.Certificate, Optional[rsa.RSAPrivateKey]]:
            cert: x509.Certificate = x509.load_pem_x509_certificate(
                cert_file.read(), default_backend()
            )
            if key_file is not None:
                key_password = key_password.encode() if key_password else None
                key = serialization.load_pem_private_key(
                    data=key_file.read(),
                    backend=default_backend(),
                    password=key_password,
                )
                if not isinstance(key, rsa.RSAPrivateKey):
                    raise ConfigurationException(
                        "Only RSA private keys supported"
                    )  # pragma: no cover
            else:
                key = None
            return cert, key

        self.ca_cert = None
        if self.ca_cert_filename:
            with open(self.ca_cert_filename, "rb") as ca_cert_file:
                self.ca_cert, _ = load_cert_pair(ca_cert_file, None, None)

        with open(self.org_key_filename, "rb") as org_key_file:
            with open(self.org_cert_filename, "rb") as org_cert_file:
                self.org_cert, self.org_key = load_cert_pair(
                    org_cert_file, org_key_file, self.org_key_password
                )


def get_cached_config(*args, **kwargs) -> Config:
    """Returns a cached instance of Config, if one does not exist, then instantiate a new instance to the config cache.
    :param args: positional arguments to instantiate Config
    :param kwargs: Key-word arguments to instantiate Config
    """
    global _cached_config
    if _cached_config is None:
        _cached_config = Config(*args, **kwargs)
        return _cached_config
    else:
        return _cached_config
