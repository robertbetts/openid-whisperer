""" Certificate Generation and Utility Functions
"""
import logging
import atexit
import os
import datetime
import tempfile
from typing import Optional, List, Tuple
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

logger = logging.getLogger(__name__)

COUNTRY_NAME: str = "UK"
STATE_OR_PROVINCE_NAME: str = "Scotland"
LOCALITY_NAME: str = "Glasgow"
ORGANIZATION_NAME_CA: str = "Identity Certification Authority"
COMMON_NAME_CA: str = "ID CA"

ORGANIZATION_NAME: str = "Service Provider"
COMMON_NAME: str = "Service Provider"


def generate_ca_key_and_certificate(
    country_name: str = COUNTRY_NAME,
    state_name: str = STATE_OR_PROVINCE_NAME,
    locality_name: str = LOCALITY_NAME,
    organization_name: str = ORGANIZATION_NAME_CA,
    common_name: str = COMMON_NAME_CA,
) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Generate a private key and self-signed certificate for a given CA organisation"""
    # Generate an RSA private key
    ca_key: rsa.RSAPrivateKey = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    certificate_expiry_days: int = 3650  # 10 years

    # Provide Issuer details for root certificate, root certs usually have the same subject and issuer
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_name),
            x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    # Create self-signed CA certificate valid for 10 years
    ca_cert: x509.Certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(
            datetime.datetime.utcnow()
            + datetime.timedelta(days=certificate_expiry_days)
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256(), default_backend())
    )

    return ca_key, ca_cert


def make_and_sign_new_org_csr(
    org_key: rsa.RSAPrivateKey,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    host_names: str | List[str] | None,
    country_name: str = COUNTRY_NAME,
    state_name: str = STATE_OR_PROVINCE_NAME,
    locality_name: str = LOCALITY_NAME,
    organization_name: str = ORGANIZATION_NAME,
    common_name: str = COMMON_NAME,
) -> x509.Certificate:
    """Create CSR and generate a new certificate using the given private
    key. Sign the certificate using the CA cert and key provided.
    """
    # Set the certificate details for the org
    new_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_name),
            x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    # Create and sign the certificate for the org using the ca certificate
    # and key as the signing authority and make valid for 30 days

    certificate_expiry_days: int = 30

    alternative_names: List[str] | None
    if isinstance(host_names, str):
        alternative_names = [item.strip() for item in host_names.split(",")]
    else:
        alternative_names = host_names

    certificate_serial_number: int = x509.random_serial_number()
    issuer_public_key: PublicKeyTypes = ca_cert.public_key()
    if not isinstance(issuer_public_key, rsa.RSAPublicKey):
        raise Exception(
            f"Invalid ca_cert public key type {type(issuer_public_key)}"
        )  # pragma: no cover
    org_public_key: CertificatePublicKeyTypes = org_key.public_key()
    org_csr: x509.CertificateBuilder = (
        x509.CertificateBuilder()
        .subject_name(new_subject)
        .issuer_name(ca_cert.issuer)
        .public_key(org_key.public_key())
        .serial_number(certificate_serial_number)
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(
            datetime.datetime.utcnow()
            + datetime.timedelta(days=certificate_expiry_days)
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_public_key),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(org_public_key), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=True,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=True,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=False
        )
    )
    if alternative_names:
        subject_alternative_names: List[GeneralName] = []
        for name in alternative_names:
            try:
                subject_alternative_names.append(
                    x509.IPAddress(ipaddress.ip_address(name))
                )
                logger.info(
                    "certificate alternate name %s, represents and ip address.", name
                )
            except ValueError:
                subject_alternative_names.append(x509.DNSName(name))

        org_csr = org_csr.add_extension(
            x509.SubjectAlternativeName(subject_alternative_names),
            critical=False,
        )
    org_cert: x509.Certificate = org_csr.sign(
        ca_key, hashes.SHA256(), default_backend()
    )
    return org_cert


def check_sha256_certificate(
    certificate: x509.Certificate, issuer_certificate: x509.Certificate
) -> bool:
    """Validates and SHA256 (PKCS1v15) signed certificate, returns True when valid.
    If validation fails, then and InvalidSignature exception is raised.

    For reference, PSS is an alternate padding implementation, a note however
    if that OAEP is the preferred This is the recommended padding algorithm
    for RSA encryption.

    padding_input = padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH)

    padding_input = padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )
    """
    public_key = issuer_certificate.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise Exception("Only RSA keys supported")  # pragma: no cover
    padding_input = padding.PKCS1v15()
    public_key.verify(
        signature=certificate.signature,
        data=certificate.tbs_certificate_bytes,
        padding=padding_input,
        algorithm=hashes.SHA256(),
    )
    return True


def generate_org_key_and_certificate(
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    org_key: Optional[rsa.RSAPrivateKey] = None,
    host_names: str | None = None,
    country_name: str = COUNTRY_NAME,
    state_name: str = STATE_OR_PROVINCE_NAME,
    locality_name: str = LOCALITY_NAME,
    organization_name: str = ORGANIZATION_NAME,
    common_name: str = COMMON_NAME,
) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Generate a private key and certificate for a given service organisation, signed using the
    CA private key and certificate provided
    """
    if org_key is None:
        org_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

    # Set the certificate details for the org
    org_cert = make_and_sign_new_org_csr(
        org_key=org_key,
        ca_key=ca_key,
        ca_cert=ca_cert,
        host_names=host_names,
        country_name=country_name,
        state_name=state_name,
        locality_name=locality_name,
        organization_name=organization_name,
        common_name=common_name,
    )

    return org_key, org_cert


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
    ca_certificate: x509.Certificate,
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
    ca_cert_data: bytes = ca_certificate.public_bytes(
        encoding=serialization.Encoding.PEM
    )
    if overwrite_existing_files is False and os.path.exists(cert_filename):
        logger.warning("certificate exists, skipping. %s", cert_filename)
    else:
        with open(cert_filename, "wt") as f:
            f.write(cert_data.decode("utf-8"))
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
    else:
        with open(ca_chain_filename, "a") as output:
            output.write("\n")
            output.write(ca_cert_data.decode("utf-8"))
            output.write("\n")
            output.write(cert_data.decode("utf-8"))
