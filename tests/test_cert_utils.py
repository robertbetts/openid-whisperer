import tempfile
import os

from openid_whisperer import cert_utils


def test_ssl_context():
    certificate = cert_utils.cert
    private_key = cert_utils.cert_key
    issuer_certs = [cert_utils.ca_cert]
    _ = cert_utils.get_ssl_context(certificate, private_key, issuer_certs)
    _ = cert_utils.get_ssl_context(certificate, private_key, issuer_certs, verify=False)


def test_certificate_dump():
    with tempfile.TemporaryDirectory() as temp_dir_name:
        cert_utils.dump_cert_and_ca_bundle(location=temp_dir_name)
        assert os.path.exists(os.path.join(temp_dir_name, "cert.pem"))
        assert os.path.exists(os.path.join(temp_dir_name, "key.pem"))
        assert os.path.exists(os.path.join(temp_dir_name, "cert-chain.pem"))
