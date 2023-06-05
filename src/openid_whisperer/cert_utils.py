""" Certificate generation and signing
"""
import atexit
import os
import datetime
import tempfile
from typing import Optional, List
import ssl
from ssl import SSLContext

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from openid_whisperer.config import IDP_SERVICE_HOST


COUNTRY_NAME: str = "UK"
STATE_OR_PROVINCE_NAME: str = "Scotland"
LOCALITY_NAME: str = "Glasgow"
ORGANIZATION_NAME_CA: str = "Glen Whisperer Identity Certification Authority"
COMMON_NAME_CA: str = "GlenW CA"

ORGANIZATION_NAME_IDP: str = "Glen Whisperer Identity Provider"
COMMON_NAME_IDP: str = "GlenW IDP"

# Generate an RSA private key
root_key: rsa.RSAPrivateKey = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Provide Issuer details for root certificate, root certs usually have the same subject and issuer
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, COUNTRY_NAME),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, STATE_OR_PROVINCE_NAME),
    x509.NameAttribute(NameOID.LOCALITY_NAME, LOCALITY_NAME),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANIZATION_NAME_CA),
    x509.NameAttribute(NameOID.COMMON_NAME, COMMON_NAME_CA),
])

# Create self-signed CA certificate valid for 10 years
ca_cert: x509.Certificate = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    root_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    datetime.datetime.utcnow() + datetime.timedelta(days=3650)  # 10 year expiry
).add_extension(
    x509.BasicConstraints(ca=True, path_length=None), critical=True
).sign(root_key, hashes.SHA256(), default_backend())

# Now generate a certificate for the identity service, signed by using the self-signed
# CA certificate First create a private key
cert_key: rsa.RSAPrivateKey = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Set the details for the identity provider
new_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, COUNTRY_NAME),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, STATE_OR_PROVINCE_NAME),
    x509.NameAttribute(NameOID.LOCALITY_NAME, LOCALITY_NAME),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANIZATION_NAME_IDP),
    x509.NameAttribute(NameOID.COMMON_NAME, COMMON_NAME_IDP),
])

# Create and sign the certificate for the openid identity service using the root cert
# as the signing authority valid for 30 days
identity_provider_serial_number: int = x509.random_serial_number()
cert: x509.Certificate = x509.CertificateBuilder().subject_name(
    new_subject
).issuer_name(
    ca_cert.issuer
).public_key(
    cert_key.public_key()
).serial_number(
    identity_provider_serial_number
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    datetime.datetime.utcnow() + datetime.timedelta(days=30)
).add_extension(
    x509.SubjectAlternativeName([x509.DNSName(IDP_SERVICE_HOST)]),
    critical=False,
).sign(root_key, hashes.SHA256(), default_backend())


def get_server_cert_chain(
        certificate: Optional[x509.Certificate] = None,
        private_key: Optional[rsa.RSAPrivateKey] = None,
        issuer_certs: Optional[List[x509.Certificate]] = None
        ) -> str:
    """ Combine the server certificate and matching private key
        if certificate or private_key are not passed in, then the context
        is initialised from the module auto generated private key and certificate.
    """
    certificate = certificate if certificate else cert
    private_key = private_key if private_key else cert_key
    issuer_certs = issuer_certs if isinstance(issuer_certs, List) else [ca_cert]
    cert_data: str = certificate.public_bytes(
        encoding=serialization.Encoding.PEM
    ).decode("utf-8")
    primary_key_data: str = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")
    issuer_data: str = ""
    for issuer_cert in issuer_certs:
        issuer_data += issuer_cert.public_bytes(
            encoding=serialization.Encoding.PEM
        ).decode("utf-8") + "\n"

    return f"{primary_key_data}\n{cert_data}\n{issuer_data}"


def get_ssl_context(
        certificate: Optional[x509.Certificate] = None,
        private_key: Optional[rsa.RSAPrivateKey] = None,
        issuer_certs: Optional[List[x509.Certificate]] = None,
        verify: bool = True
        ) -> SSLContext:
    """ Create a ssl_context for SSL server with no client client cert verification
        if a certificate or private_key is not passed in, then the context
        is initialised from the module to auto generated a private key and certificate.
    """
    certificate = certificate if certificate else cert
    private_key = private_key if private_key else cert_key
    issuer_certs = issuer_certs if isinstance(issuer_certs, List) else [ca_cert]

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


def dump_cert_and_ca_bundle(out_location: str):
    """Create files for the certificate, private key and certificate chain
       in PEM format. certp.pem, key.pem, cert-chain.pem"""
    cert_file = os.path.join(out_location, "cert.pem")
    primary_key_file = os.path.join(out_location, "key.pem")
    ca_chain_file = os.path.join(out_location, "cert-chain.pem")

    cert_data: bytes = cert.public_bytes(
        encoding=serialization.Encoding.PEM
    )
    ca_cert_data: bytes = ca_cert.public_bytes(
        encoding=serialization.Encoding.PEM
    )
    with open(cert_file, "wt") as f:
        f.write(cert_data.decode("utf-8"))
        f.write("\n")
        f.write(ca_cert_data.decode("utf-8"))

    primary_key_data: bytes = cert_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(primary_key_file, "wt") as f:
        f.write(primary_key_data.decode("utf-8"))

    with open(ca_chain_file, "a") as output:
        output.write("\n")
        output.write(ca_cert_data.decode("utf-8"))
        output.write("\n")
        output.write(cert_data.decode("utf-8"))
