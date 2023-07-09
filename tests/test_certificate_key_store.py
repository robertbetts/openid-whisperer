from openid_whisperer.utils.token_store_utils import TokenIssuerCertificateStore


def test_init_certificate_store(config):
    cert_store = TokenIssuerCertificateStore(
        ca_key_filename=config.ca_key_filename,
        ca_key_password=config.ca_key_password,
        ca_cert_filename=config.ca_cert_filename,
        org_key_filename=config.org_key_filename,
        org_key_password=config.org_key_password,
        org_cert_filename=config.org_cert_filename,
    )
