import hashlib

from openid_whisperer.utils.common import get_audience
from openid_whisperer.utils.token_utils import validate_access_token


def test_pkce_flow(scenario_api_a, openid_api):
    code_challenge_method = "plain"
    code_challenge = "my code challenge"

    authenticate_code_input = {
        "tenant": scenario_api_a["tenant"],
        "response_type": "code",
        "response_mode": "query",
        "redirect_uri": scenario_api_a["redirect_uri"],
        "client_id": scenario_api_a["client_id"],
        "client_secret": scenario_api_a["client_secret"],
        "resource": scenario_api_a["resource"],
        "username": scenario_api_a["username"],
        "password": scenario_api_a["password"],
        "nonce": scenario_api_a["nonce"],
        "scope": scenario_api_a["scope"],
        "code_challenge_method": code_challenge_method,
        "code_challenge": code_challenge,
        "user_code": None,
        "kmsi": None,
        "mfa_code": None,
    }
    authorize_response = openid_api.post_authorize(**authenticate_code_input)
    assert isinstance(authorize_response, dict)

    # Get access_token using authentication_code
    token_response = openid_api.get_token(
        tenant=scenario_api_a["tenant"],
        grant_type="authorization_code",
        client_id=scenario_api_a["client_id"],
        client_secret=scenario_api_a["client_secret"],
        client_assertion="",
        client_assertion_type="",
        refresh_token="",
        token_type="",
        requested_token_use="",
        assertion="",
        expires_in="",
        access_token="",
        device_code="",
        code=authorize_response["authorization_code"],
        username="",
        password="",
        nonce="",
        scope="",
        resource="",
        redirect_uri="",
        code_verifier=code_challenge,
    )
    assert "access_token" in token_response


def test_device_code_flow(scenario_api_a, endpoint_jwks_keys, openid_api):
    devicecode_request_inputs = {
        "tenant": scenario_api_a["tenant"],
        "base_url": "",
        "client_id": scenario_api_a["client_id"],
        "client_secret": scenario_api_a["client_secret"],
        "scope": scenario_api_a["scope"],
        "nonce": scenario_api_a["nonce"],
        "code_challenge_method": "plain",
    }
    response = openid_api.get_devicecode_request(**devicecode_request_inputs)

    assert (
        f"{devicecode_request_inputs['tenant']}/oauth2/authorize?"
        in response["verification_uri"]
    )
    assert (
        response["device_code"]
        == hashlib.sha256(response["user_code"].encode("ascii")).hexdigest()
    )
    redirect_uri = "http://test/api/handleAccessToken"
    authentication_response = openid_api.post_authorize(
        tenant=scenario_api_a["tenant"],
        response_type="code",
        response_mode="query",
        redirect_uri=redirect_uri,
        client_id=scenario_api_a["client_id"],
        client_secret=scenario_api_a["client_secret"],
        resource=scenario_api_a["resource"],
        username=scenario_api_a["username"],
        password=scenario_api_a["password"],
        nonce=scenario_api_a["nonce"],
        scope=scenario_api_a["scope"],
        code_challenge_method="plain",
        code_challenge=None,
        user_code=response["user_code"],
    )
    assert isinstance(authentication_response, dict)

    print(response)
    # Get access_token using authentication_code
    response = openid_api.get_token(
        tenant=scenario_api_a["tenant"],
        grant_type="urn:ietf:params:oauth:grant-type:device_code",
        client_id=scenario_api_a["client_id"],
        client_secret=scenario_api_a["client_secret"],
        client_assertion="",
        client_assertion_type="",
        refresh_token="",
        token_type="",
        requested_token_use="",
        assertion="",
        expires_in="",
        access_token="",
        device_code=response["device_code"],
        code="",
        username="",
        password="",
        nonce="",
        scope="",
        resource="",
        redirect_uri="",
        code_verifier="",
    )
    access_token = response["access_token"]

    audience = get_audience(scenario_api_a["scope"], scenario_api_a["resource"])
    # audience = [scenario_api_a["client_id"]]
    claims = validate_access_token(
        access_token=access_token,
        jwks_keys=endpoint_jwks_keys,
        algorithms=["RS256"],
        audience=audience,
        issuer=None,
    )
    assert scenario_api_a["client_id"] in claims["appid"]
