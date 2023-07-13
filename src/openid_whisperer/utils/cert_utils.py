""" Certificate Generation and Utility Functions
"""
import logging
import atexit
import os
import tempfile
from typing import Optional, List, Type, Callable
import ssl
from ssl import SSLContext

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)


class CertUtilsException(Exception):
    ...


def get_server_cert_chain(
    certificate: x509.Certificate,
    private_key: rsa.RSAPrivateKey,
    issuer_certs: Optional[List[x509.Certificate]] = None,
) -> str:
    """Combine the server certificate and matching private key
    if certificate or private_key are not passed in, then the context
    is initialised from the module auto generated private key and certificate.
    """
    cert_data: str = certificate.public_bytes(
        encoding=serialization.Encoding.PEM
    ).decode("utf-8")
    primary_key_data: str = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    issuer_data: str = ""
    if issuer_certs is not None:
        issuer_data += "\n"
        for issuer_cert in issuer_certs:
            issuer_data += (
                issuer_cert.public_bytes(encoding=serialization.Encoding.PEM).decode(
                    "utf-8"
                )
                + "\n"
            )

    return f"{primary_key_data}\n{cert_data}{issuer_data}"


def get_ssl_context(
    certificate: x509.Certificate,
    private_key: rsa.RSAPrivateKey,
    issuer_certs: Optional[List[x509.Certificate]] = None,
    verify: bool = True,
) -> SSLContext:
    """Create a ssl_context for SSL server with no client cert verification
    if a certificate or private_key is not passed in, then the context
    is initialised from the module to auto generated a private key and certificate.
    """
    ca_data: str = get_server_cert_chain(certificate, private_key, issuer_certs)
    cert_handle, cert_file = tempfile.mkstemp()
    atexit.register(os.remove, cert_file)
    os.write(cert_handle, ca_data.encode())
    os.close(cert_handle)

    context: SSLContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # only disable verification if verify is explicitly set to False
    if not verify:
        context.check_hostname = False
    context.load_cert_chain(cert_file)
    return context


def dump_cert_and_ca_bundle(
    private_key: rsa.RSAPrivateKey,
    certificate: x509.Certificate,
    ca_certificate: Optional[x509.Certificate] = None,
    location: Optional[str] = None,
    cert_filename: Optional[str] = None,
    primary_key_filename: Optional[str] = None,
    ca_chain_filename: Optional[str] = None,
    overwrite_existing_files: bool = False,
) -> None:
    """Create files for the private_key, certificate and certificate chain
    in PEM format. cert.pem, key.pem, cert-chain.pem
    Only overwrite files when overwrite_existing_files is True
    """

    cert_filename = cert_filename if cert_filename else "cert.pem"
    primary_key_filename = primary_key_filename if primary_key_filename else "key.pem"
    ca_chain_filename = ca_chain_filename if ca_chain_filename else "cert-chain.pem"
    if location:
        cert_filename = os.path.join(location, cert_filename)
        primary_key_filename = os.path.join(location, primary_key_filename)
        ca_chain_filename = os.path.join(location, ca_chain_filename)

    cert_data: bytes = certificate.public_bytes(encoding=serialization.Encoding.PEM)
    if ca_certificate:
        ca_cert_data: bytes = ca_certificate.public_bytes(
            encoding=serialization.Encoding.PEM
        )

    if overwrite_existing_files is False and os.path.exists(cert_filename):
        logger.warning("certificate exists, skipping. %s", cert_filename)
    else:
        with open(cert_filename, "wt") as f:
            f.write(cert_data.decode("utf-8"))
            if ca_certificate:
                f.write("\n")
                f.write(ca_cert_data.decode("utf-8"))

    primary_key_data: bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    if overwrite_existing_files is False and os.path.exists(primary_key_filename):
        logger.warning("primary key exists, skipping. %s", primary_key_filename)
    else:
        with open(primary_key_filename, "wt") as f:
            f.write(primary_key_data.decode("utf-8"))

    if overwrite_existing_files is False and os.path.exists(ca_chain_filename):
        logger.warning("certificate chain exists, skipping. %s", ca_chain_filename)
    elif ca_certificate:
        with open(ca_chain_filename, "a") as output:
            output.write("\n")
            output.write(ca_cert_data.decode("utf-8"))
            output.write("\n")
            output.write(cert_data.decode("utf-8"))
