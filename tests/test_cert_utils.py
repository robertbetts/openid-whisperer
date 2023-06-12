import tempfile
import os

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
