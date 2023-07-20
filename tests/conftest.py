import logging
import pytest
import secrets
import string
from uuid import uuid4

from openid_whisperer import main
from openid_whisperer.config import get_cached_config
from openid_whisperer.openid_interface import OpenidApiInterface
from openid_whisperer.openid_blueprint import openid_api_interface
from openid_whisperer.utils.test_utils import create_self_signed_certificate_pair, add_mock_client_secret_key
from openid_whisperer.utils.token_utils import public_keys_from_x509_certificates

logging.getLogger("faker.factory").setLevel(logging.WARNING)


@pytest.fixture
def config():
    _config = get_cached_config()
    yield _config


@pytest.fixture
def app():
    app = main.app()
    yield app


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
        raise Exception("broken_validate_client")

    openid_api_interface.validate_client = broken_validate_client

    # Force runtime errors when accessing the token store from the openid_interface
    def get_keys():
        raise Exception("broken_key_keys")

    openid_api_interface.token_store.get_keys = get_keys

    yield openid_api_interface

    openid_api_interface.validate_client = original_validate_client
    openid_api_interface.token_store.get_keys = original_get_keys


@pytest.fixture
def endpoint_jwks_keys(openid_api: OpenidApiInterface):
    return public_keys_from_x509_certificates(openid_api.token_store.get_keys())


@pytest.fixture
def api_a_settings(openid_api):
    client_id = "CLIENT-API-A"
    algorithm = "RS256"
    key_id = uuid4().hex
    # cert, key = create_self_signed_certificate_pair(
    #     organization_name=client_id,
    #     common_name=None,
    #     expiry_date=None
    # )
    cert = openid_api.token_store.token_issuer_certificate
    key = openid_api.token_store.token_issuer_private_key

    add_mock_client_secret_key(
        openid_api=openid_api,
        client_id=client_id,
        public_key_id=key_id,
        public_key=key.public_key(),
        issuer_reference=client_id,
        algorithm=algorithm
    )
    token_endpoint_url = "https://idp/oauth/token"
    token_response = openid_api.token_store.create_client_secret_token(
        identity_provider_id="identity_provider_id",
        ip_client_id=client_id,
        client_secret=openid_api.token_store.token_issuer_private_key,
        token_endpoint_url=token_endpoint_url,
        token_key_id=key_id,
        token_expiry=600,  # 10 minutes
        token_algorithm=algorithm,
        token_id=uuid4().hex,
    )
    client_secret = token_response["token"]
    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "key_id": key_id,
        "client_cert": cert,
        "client_private_key": key,
        "algorithm": algorithm,
        "resource": "URI:API:CLIENT-API-A-RESOURCE",
        "roles": "URI:API:CLIENT-API-A-READ,URI:API:CLIENT-API-A-WRITE,URI:API:CLIENT-API-A-ADMIN",
        "redirect_uri": "http://test-api-a/api/handleAccessToken",
    }


@pytest.fixture
def api_b_settings():
    client_id = "CLIENT-API-B"
    algorithm = "RS256"
    key_id = uuid4().hex
    # cert, key = create_self_signed_certificate_pair(
    #     organization_name=client_id,
    #     common_name=None,
    #     expiry_date=None
    # )
    cert = openid_api.token_store.token_issuer_certificate
    key = openid_api.token_store.token_issuer_private_key

    add_mock_client_secret_key(
        openid_api=openid_api,
        client_id=client_id,
        public_key_id=key_id,
        public_key=key.public_key(),
        issuer_reference=client_id,
        algorithm=algorithm
    )
    token_endpoint_url = "https://idp/oauth/token"
    token_response = openid_api.token_store.create_client_secret_token(
        identity_provider_id="identity_provider_id",
        ip_client_id=client_id,
        client_secret=openid_api.token_store.token_issuer_private_key,
        token_endpoint_url=token_endpoint_url,
        token_key_id=key_id,
        token_expiry=600,  # 10 minutes
        token_algorithm=algorithm,
        token_id=uuid4().hex,
    )
    client_secret = token_response["token"]
    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "key_id": key_id,
        "client_cert": cert,
        "client_private_key": key,
        "algorithm": algorithm,
        "resource": "URI:API:CLIENT-API-B-RESOURCE",
        "roles": "URI:API:CLIENT-API-B-READ,URI:API:CLIENT-API-B-WRITE,URI:API:CLIENT-API-B-ADMIN",
        "redirect_uri": "http://test-api-b/api/handleAccessToken",
    }

@pytest.fixture
def enduser_aaa():
    return {
        "username": "user_aaa@domain",
        "password": "user_aaa_%s" % "".join(secrets.choice(string.ascii_letters) for _ in range(8)),
    }


@pytest.fixture
def api_a_enduser_aaa(enduser_aaa):
    api_user = enduser_aaa.copy()
    api_user.update({
        "scope": "openid profile",
        "roles": "URI:API:CLIENT-API-A-READ,URI:API:CLIENT-API-A-WRITE,URI:API:CLIENT-API-A-ADMIN",
    })
    return api_user


@pytest.fixture
def api_b_enduser_aaa(enduser_aaa):
    api_user = enduser_aaa.copy()
    api_user.update({
        "scope": "openid profile",
        "roles": "URI:API:CLIENT-API-B-READ,URI:API:CLIENT-API-B-WRITE",
    })
    return api_user


@pytest.fixture
def flow_session_state():
    nonce = "".join(secrets.choice(string.ascii_letters) for _ in range(16))
    state = "".join(secrets.choice(string.ascii_letters) for _ in range(16))
    return {
        "nonce": nonce,
        "state": state,
    }


@pytest.fixture
def scenario_api_a(api_a_settings, api_a_enduser_aaa, flow_session_state):
    scenario_info = {}
    scenario_info.update(api_a_settings)
    scenario_info.update(api_a_enduser_aaa)
    scenario_info.update(flow_session_state)
    scenario_info.update({
        "tenant": "adfs",
    })
    return scenario_info


@pytest.fixture
def scenario_api_b(api_b_settings, api_b_enduser_aaa, flow_session_state):
    scenario_info = {}
    scenario_info.update(api_b_settings)
    scenario_info.update(api_b_enduser_aaa)
    scenario_info.update(flow_session_state)
    scenario_info.update({
        "tenant": "adfs",
    })
    return scenario_info
