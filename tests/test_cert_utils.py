import tempfile
import os
from cryptography.exceptions import InvalidSignature
import pytest

from openid_whisperer import cert_utils


def test_ssl_context(config):
    certificate = config.org_cert
    private_key = config.org_key
    issuer_certs = [config.ca_cert]
    _ = cert_utils.get_ssl_context(certificate, private_key, issuer_certs)
    _ = cert_utils.get_ssl_context(certificate, private_key, issuer_certs, verify=False)


def test_certificate_dump(config):
    with tempfile.TemporaryDirectory() as temp_dir_name:
        cert_utils.dump_cert_and_ca_bundle(
            private_key=config.org_key,
            certificate=config.org_cert,
            ca_certificate=config.ca_cert,
            location=temp_dir_name)
        assert os.path.exists(os.path.join(temp_dir_name, "cert.pem"))
        assert os.path.exists(os.path.join(temp_dir_name, "key.pem"))
        assert os.path.exists(os.path.join(temp_dir_name, "cert-chain.pem"))

        # Test existing files
        cert_utils.dump_cert_and_ca_bundle(
            private_key=config.org_key,
            certificate=config.org_cert,
            ca_certificate=config.ca_cert,
            location=temp_dir_name)

        # Test file overwriting
        cert_utils.dump_cert_and_ca_bundle(
            private_key=config.org_key,
            certificate=config.org_cert,
            ca_certificate=config.ca_cert,
            location=temp_dir_name,
            overwrite_existing_files=True,
        )


def test_generate_key_and_certificate():
    # Test CA
    ca_certs = cert_utils.generate_ca_key_and_certificate()
    issuer = ca_certs[1].issuer.rfc4514_string()
    subject = ca_certs[1].subject.rfc4514_string()
    # logging.info(f"issuer: {issuer}")
    # logging.info(f"subject: {subject}")
    assert issuer == subject
    assert issuer == "CN=ID CA,O=Identity Certification Authority,L=Glasgow,ST=Scotland,C=UK"

    # Test Org
    hostnames = "app-host, openid-host, 10.44.55.66"
    certs = cert_utils.generate_org_key_and_certificate(*ca_certs, host_names=hostnames)
    issuer = certs[1].issuer.rfc4514_string()
    subject = certs[1].subject.rfc4514_string()
    # logging.info(f"issuer: {issuer}")
    # logging.info(f"subject: {subject}")
    assert issuer == "CN=ID CA,O=Identity Certification Authority,L=Glasgow,ST=Scotland,C=UK"
    assert subject == "CN=Service Provider,O=Service Provider,L=Glasgow,ST=Scotland,C=UK"

    # Test certificate Validation
    cert_utils.check_sha256_certificate(certs[1], ca_certs[1])
    with pytest.raises(InvalidSignature):
        invalid_ca_certs = cert_utils.generate_ca_key_and_certificate()
        cert_utils.check_sha256_certificate(certs[1], invalid_ca_certs[1])


    # Test Hostname inputs
    hostnames = ["app-host", "10.44.55.66"]
    certs = cert_utils.generate_org_key_and_certificate(*ca_certs, host_names=hostnames)
    hostnames = None
    certs = cert_utils.generate_org_key_and_certificate(*ca_certs, host_names=hostnames)
