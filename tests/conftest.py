import pytest
import secrets
import string

from openid_whisperer import main
from openid_whisperer.config import get_cached_config
from openid_whisperer.openid_interface import OpenidApiInterface
from openid_whisperer.openid_blueprint import openid_api_interface
from openid_whisperer.utils.token_utils import public_keys_from_x509_certificates


@pytest.fixture
def app():
    app = main.app()
    yield app


@pytest.fixture
def config():
    yield get_cached_config()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def openid_api():
    openid_api_interface.issuer_reference = "uri:pytest:issuer:name:openid-whisperer"
    yield openid_api_interface


@pytest.fixture
def internal_jwks_keys(openid_api: OpenidApiInterface):
    return openid_api.token_store.get_keys()


@pytest.fixture
def endpoint_jwks_keys(openid_api: OpenidApiInterface):
    return public_keys_from_x509_certificates(openid_api.token_store.get_keys())


@pytest.fixture
def input_scenario_one():
    client_id = "ID_12345"
    scope = "openid profile"
    resource = "TEST:URI:RS-104134-21171-test-api"
    nonce = "".join(secrets.choice(string.ascii_letters) for _ in range(16))
    return {
        "client_id": client_id,
        "client_secret": "client_secret",
        "tenant": "adfs",
        "scope": scope,
        "resource": resource,
        "username": "enduser@domain",
        "password": "password1234",
        "nonce": nonce,
        "kmsi": "",
        "mfa_code": "",
    }
