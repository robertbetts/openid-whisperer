import hashlib

from openid_whisperer.openid_lib import (
    devicecode_request,
    get_access_token_from_authorisation_code,
    split_scope_and_resource,
    authenticate_with_code_response,
)
from openid_whisperer.utils.token_utils import validate_access_token


def test_pkce_flow(input_scenario_one):
    code_challenge_method = "plain"
    code_challenge = ""

    authenticate_code_input = {
        "client_id": input_scenario_one["client_id"],
        "resource": input_scenario_one["resource"],
        "username": input_scenario_one["username"],
        "user_secret": input_scenario_one["password"],
        "nonce": input_scenario_one["nonce"],
        "scope": input_scenario_one["scope"],
        "code_challenge_method": code_challenge_method,
        "code_challenge": code_challenge,
        "user_code": None,
        "kmsi": None,
        "mfa_code": None,
    }
    authentication_code = authenticate_with_code_response(**authenticate_code_input)
    assert isinstance(authentication_code, str)

    # Get access_token using authentication_code
    response = get_access_token_from_authorisation_code(authentication_code)
    access_token = response["access_token"]


def test_device_code_flow(input_scenario_one, endpoint_jwks_keys, openid_api):
    devicecode_request_inputs = {
        "tenant": input_scenario_one["tenant"],
        "base_url": "",
        "client_id": input_scenario_one["client_id"],
        "client_secret": input_scenario_one["client_secret"],
        "scope": input_scenario_one["scope"],
        "nonce": input_scenario_one["nonce"],
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
        tenant=input_scenario_one["tenant"],
        response_type="code",
        response_mode="query",
        redirect_uri=redirect_uri,
        client_id=input_scenario_one["client_id"],
        client_secret=input_scenario_one["client_secret"],
        resource=input_scenario_one["resource"],
        username=input_scenario_one["username"],
        password=input_scenario_one["password"],
        nonce=input_scenario_one["nonce"],
        scope=input_scenario_one["scope"],
        code_challenge_method="plain",
        code_challenge=None,
        user_code=response["user_code"],
    )
    assert isinstance(authentication_response, dict)


    print(response)
    # Get access_token using authentication_code
    response = openid_api.get_token(
        tenant=input_scenario_one["tenant"],
        grant_type="device_code",
        client_id=input_scenario_one["client_id"],
        client_secret=input_scenario_one["client_secret"],
        refresh_token="",
        token_type="",
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

    _, audience = split_scope_and_resource(
        input_scenario_one["scope"], input_scenario_one["resource"]
    )
    audience = [input_scenario_one["client_id"]]
    claims = validate_access_token(
        access_token=access_token,
        jwks_keys=endpoint_jwks_keys,
        algorithms=["RS256"],
        audience=audience,
        issuer=None,
    )
    assert input_scenario_one["client_id"] in claims["appid"]
