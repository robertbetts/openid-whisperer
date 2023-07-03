""" token unittests
"""
import json
import base64
from typing import Dict, Any
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import math
import jwt

from openid_whisperer.openid_lib import (
    create_authorisation_code,
    get_access_token_from_authorisation_code,
    get_keys,
    authenticate_token,
)
from openid_whisperer.openid_lib import ISSUER


def validate_access_token(access_token: str, audience: str, issuer: str):
    at_list = access_token.split(".")
    # Adjust the left padding to avoid the base64 padding error
    token_header = at_list[0].ljust(int(math.ceil(len(at_list[0]) / 4)) * 4, "=")
    header = json.loads(base64.b64decode(token_header).decode("utf-8"))
    tok_x5t = header["x5t"]

    idp_keys: Dict[str, Any] = {}

    # Loop through keys to create dictionary
    for key in get_keys()["keys"]:
        x5t = key["x5t"]
        x5c = key["x5c"][0]
        temp_cer = x5c.replace("\/", "/")
        ret_char = "\r\n"
        cer_len = len(temp_cer)
        count = 64

        ins_extra_ret = True if (len(temp_cer) % 64 != 0) else False

        for _ in range(int(cer_len / 64)):
            temp_cer = temp_cer[:count] + ret_char + temp_cer[count:]
            count = count + 64 + len(ret_char)

        temp_cer = temp_cer + ret_char if ins_extra_ret else temp_cer

        tok_sign_cer = (
            "-----BEGIN CERTIFICATE-----\r\n" + temp_cer + "-----END CERTIFICATE-----"
        )

        cert = x509.load_pem_x509_certificate(tok_sign_cer.encode(), default_backend())
        public_key = cert.public_key()

        # now set the idp_keys discretionary entry
        idp_keys[x5t] = public_key

    claims = jwt.decode(
        access_token,
        idp_keys[tok_x5t],
        audience=audience,
        issuer=issuer,
        algorithms=["RS256"],
    )
    return claims


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
    claims = validate_access_token(
        access_token=access_token["access_token"], audience=resource, issuer=ISSUER
    )
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
    claims = validate_access_token(
        access_token=access_token["access_token"], audience=resource, issuer=ISSUER
    )
    assert (
        claims["aud"] == [resource, client_id]
        and claims["iss"] == ISSUER
        and claims["appid"] == client_id
        and claims["nonce"] == nonce
        and claims["username"] == domain_username
    )
