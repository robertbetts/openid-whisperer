import hashlib

from openid_whisperer.openid_lib import devicecode_request, authenticate_code, get_access_token_from_authorisation_code, split_scope_and_resource, authenticate_code
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
        "mfa_code": None
    }
    authentication_code = authenticate_code(**authenticate_code_input)
    assert isinstance(authentication_code, str)

    # Get access_token using authentication_code
    response = get_access_token_from_authorisation_code(authentication_code)
    access_token = response["access_token"]


def test_device_code_flow(input_scenario_one):
    devicecode_request_inputs = {
        "base_url": "",
        "tenant": input_scenario_one["tenant"],
        "client_id": input_scenario_one["client_id"],
        "scope": input_scenario_one["scope"],
        "nonce": input_scenario_one["nonce"],
        "code_challenge_method": "plain",
    }
    response = devicecode_request(**devicecode_request_inputs)

    assert (
        f"{devicecode_request_inputs['tenant']}/oauth2/authorize?"
        in response["verification_uri"]
    )
    assert (
        response["device_code"]
        == hashlib.sha256(response["user_code"].encode("ascii")).hexdigest()
    )

    authentication_code = authenticate_code(
        client_id=input_scenario_one["client_id"],
        resource=input_scenario_one["resource"],
        username=input_scenario_one["username"],
        user_secret=input_scenario_one["password"],
        nonce=input_scenario_one["nonce"],
        scope=input_scenario_one["scope"],
        code_challenge_method="plain",
        code_challenge=None,
        user_code=response["user_code"],
    )
    assert isinstance(authentication_code, str)

    # Get access_token using authentication_code
    response = get_access_token_from_authorisation_code(authentication_code)
    access_token = response["access_token"]

    _, audience = split_scope_and_resource(input_scenario_one["scope"], input_scenario_one["resource"])
    audience = [input_scenario_one["client_id"]]
    claims = validate_access_token(access_token=access_token, algorithms=["RS256"], audience=audience, issuer=None)
    assert input_scenario_one["client_id"] in claims['appid']
