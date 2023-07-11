""" token unittests
"""
from uuid import uuid4
from typing import Dict, Any

from openid_whisperer.utils.token_utils import (
    validate_access_token,
    validate_jwt_token,
)
from openid_whisperer.utils.common import (
    generate_s256_hash,
    validate_s256_hash,
    get_audience,
)
from openid_whisperer.openid_interface import OpenidApiInterface


def test_hash_codes():
    uuid = uuid4().hex
    authorisation_code = generate_s256_hash(uuid)
    assert validate_s256_hash(uuid, authorisation_code)


def test_authorisation_code(
    input_scenario_one: Dict[str, Any],
    openid_api: OpenidApiInterface,
    endpoint_jwks_keys: Dict[str, Any],
):
    user_claims = openid_api.credential_store.get_user_scope_claims(
        username=input_scenario_one["username"],
        scope=input_scenario_one["scope"],
    )
    assert isinstance(user_claims, dict)
    assert len(user_claims) > 1
    audience = get_audience(
        client_id=input_scenario_one["client_id"],
        scope=input_scenario_one["scope"],
        resource=input_scenario_one["resource"],
    )
    assert isinstance(audience, list)
    assert len(audience) > 1
    authorisation_code, token_response = openid_api.token_store.create_new_token(
        client_id=input_scenario_one["client_id"],
        issuer=openid_api.issuer_reference,
        sub=input_scenario_one["username"],
        user_claims=user_claims,
        audience=audience,
        nonce=input_scenario_one["nonce"],
    )

    token_response = openid_api.token_store.token_requests.get(authorisation_code, None)
    assert token_response is not None
    algorithms = [openid_api.token_store.token_issuer_algorithm]
    claims = validate_access_token(
        access_token=token_response["access_token"],
        jwks_keys=endpoint_jwks_keys,
        algorithms=algorithms,
        audience=input_scenario_one["resource"],
        issuer=openid_api.issuer_reference,
    )
    assert (
        claims["aud"]
        == [input_scenario_one["resource"], input_scenario_one["client_id"]]
        and claims["iss"] == openid_api.issuer_reference
        and claims["appid"] == input_scenario_one["client_id"]
        and claims["nonce"] == input_scenario_one["nonce"]
    )
    # Test proxy function of validate_access_token
    claims = validate_jwt_token(
        access_token=token_response["access_token"],
        jwks_keys=endpoint_jwks_keys,
        algorithms=algorithms,
        audience=input_scenario_one["resource"],
        issuer=openid_api.issuer_reference,
    )
    assert (
        claims["aud"]
        == [input_scenario_one["resource"], input_scenario_one["client_id"]]
        and claims["iss"] == openid_api.issuer_reference
        and claims["appid"] == input_scenario_one["client_id"]
        and claims["nonce"] == input_scenario_one["nonce"]
    )
