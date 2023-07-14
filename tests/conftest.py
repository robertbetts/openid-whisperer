import logging
import pytest
import secrets
import string

from openid_whisperer import main
from openid_whisperer.config import get_cached_config
from openid_whisperer.openid_interface import OpenidApiInterface
from openid_whisperer.openid_blueprint import openid_api_interface
from openid_whisperer.utils.token_utils import public_keys_from_x509_certificates

logging.getLogger("faker.factory").setLevel(logging.WARNING)


@pytest.fixture
def app():
    app = main.app()
    yield app


@pytest.fixture
def config():
    _config = get_cached_config()
    yield _config


@pytest.fixture
def client(app):
    _test_client = app.test_client()
    return _test_client


@pytest.fixture
def openid_api():
    openid_api_interface.issuer_reference = "uri:pytest:issuer:name:openid-whisperer"
    yield openid_api_interface


@pytest.fixture(scope="function")
def broken_openid_api():
    original_validate_client = openid_api_interface.validate_client
    original_get_keys = openid_api_interface.token_store.get_keys

    # Force runtime error when checking client_id validation
    def broken_validate_client(client_id: str, client_secret: str | None = None):
        _ = (client_id, client_secret)
        assert "This is broken" == "very broken"

    openid_api_interface.validate_client = broken_validate_client

    # Force runtime errors when accessing the token store from the openid_interface
    def get_keys():
        assert "This is broken" == "very broken"

    openid_api_interface.token_store.get_keys = get_keys

    yield openid_api_interface

    openid_api_interface.validate_client = original_validate_client
    openid_api_interface.token_store.get_keys = original_get_keys


@pytest.fixture
def endpoint_jwks_keys(openid_api: OpenidApiInterface):
    return public_keys_from_x509_certificates(openid_api.token_store.get_keys())


@pytest.fixture
def input_scenario_one():
    tenant = "/adfs"
    client_id = "CLIENT-90274-DEV"
    scope = "openid profile"
    resource = "URI:API:CLIENT-90274-API"
    nonce = "".join(secrets.choice(string.ascii_letters) for _ in range(16))
    redirect_uri = "http://test/api/handleAccessToken"
    return {
        "client_id": client_id,
        "client_secret": "client_secret",
        "tenant": tenant,
        "scope": scope,
        "resource": resource,
        "username": "enduser@domain",
        "password": "password1234",
        "nonce": nonce,
        "kmsi": "",
        "mfa_code": "",
        "redirect_uri": redirect_uri,
    }
