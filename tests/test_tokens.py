""" token unittests
"""

from openid_whisperer.openid_lib import (
    create_authorisation_code,
    get_access_token_from_authorisation_code,
    authenticate_token,
)
from openid_whisperer.openid_lib import ISSUER
from openid_whisperer.utils.token_utils import validate_access_token


def test_authorisation_code():
    client_id = "ID_12345"
    resource = "MOCK:URI:RS-104134-21171-api"
    domain = "my-domain"
    username = "my-name"
    domain_username = f"{username}@{domain}"
    nonce = "XX"
    scope = "openid profile"
    code_challenge = None
    authorisation_code = create_authorisation_code(
        client_id=client_id,
        resource=resource,
        username=domain_username,
        nonce=nonce,
        scope=scope,
        code_challenge=code_challenge,
    )
    assert authorisation_code is not None

    access_token = get_access_token_from_authorisation_code(authorisation_code)
    assert access_token is not None
    algorithms = ["RS256"]
    claims = validate_access_token(access_token=access_token["access_token"], algorithms=algorithms, audience=resource, issuer=ISSUER)
    assert (
        claims["aud"] == [resource, client_id]
        and claims["iss"] == ISSUER
        and claims["appid"] == client_id
        and claims["nonce"] == nonce
        and claims["username"] == domain_username
    )


def test_authenticate_token():
    client_id = "ID_54321"
    resource = "MOCK:URI:RS-104134-21171-api"
    domain = "my-domain"
    username = "my-name"
    domain_username = f"{username}@{domain}"
    user_secret = "XXX"
    nonce = "YY"
    scope = "openid profile"
    access_token = authenticate_token(
        client_id=client_id,
        resource=resource,
        username=domain_username,
        user_secret=user_secret,
        nonce=nonce,
        scope=scope,
    )
    assert access_token is not None
    algorithms = ["RS256"]
    claims = validate_access_token(access_token=access_token["access_token"], algorithms=algorithms, audience=resource, issuer=ISSUER)
    assert (
        claims["aud"] == [resource, client_id]
        and claims["iss"] == ISSUER
        and claims["appid"] == client_id
        and claims["nonce"] == nonce
        and claims["username"] == domain_username
    )
