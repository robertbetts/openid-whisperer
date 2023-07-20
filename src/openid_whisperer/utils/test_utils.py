""" Common functions referenced for unit testing

** PLEASE REFRAIN FROM IMPORTING pytest or other non-testing required modules here

"""
from typing import Optional, Any, Tuple, Dict
import atexit
import os
import datetime
import tempfile
import ssl
from ssl import SSLContext
import ipaddress

from cryptography import x509
from cryptography.x509.general_name import GeneralName
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import (
    PublicKeyTypes,
)
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificatePublicKeyTypes,
)

from openid_whisperer.utils.common import package_get_logger

logger = package_get_logger(__name__)


def create_self_signed_certificate_pair(
    organization_name: str,
    common_name: Optional[str] = None,
    expiry_date: Optional[datetime.datetime] = None,
    **options: Dict[str, Any]
) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Returns a private key and self-signed certificate. As this function is designed to support unit testing,
    the expiry is defaulted to 10 minutes, unless specified otherwise.

    :param organization_name:
    :param common_name:
    :param expiry_date:
    :param options:
        key-values for additional certificate attributes
    """

    # Generate an RSA private key
    key: rsa.RSAPrivateKey = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    common_name = common_name if common_name else organization_name.replace(" ", "-")
    expiry_seconds: int = 3600  # 10 minutes
    expiry_date = (
        expiry_date
        if expiry_date
        else datetime.datetime.utcnow() + datetime.timedelta(seconds=expiry_seconds)
    )

    # TODO: inspect options to add additional certificate attributes
    _ = options

    # Provide Issuer details for root certificate, root certs usually have the same subject and issuer
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    # Create self-signed CA certificate valid for 10 years
    cert: x509.Certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(expiry_date)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256(), default_backend())
    )

    return cert, key


def add_mock_client_secret_key(
    openid_api: str,
    client_id: str,
    public_key_id: str,
    public_key: Any,
    issuer_reference: Optional[str] = None,
    algorithm: Optional[str] = None,
):
    issuer_reference = issuer_reference if issuer_reference else client_id
    algorithm = algorithm if algorithm else "RS256"
    client_key_info = {
        "key_id": public_key_id,
        "key_issuer": issuer_reference,
        "algorithm": algorithm,
        "public_key": public_key,
    }
    try:
        openid_api.token_store.add_client_secret(client_id=client_id, **client_key_info)
    except KeyError:
        logger.debug("client secret key already added")
