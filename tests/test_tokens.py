""" token unittests
"""
import logging
import json
import base64
from typing import Dict, Any
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import math
import jwt

from openid_whisperer.openid_lib import create_authorisation_code,\
    get_access_token_from_authorisation_code, get_keys, \
    authenticate_token
from openid_whisperer.openid_lib import ISSUER


def validate_access_token(access_token: str, audience: str, issuer: str):
    at_list = access_token.split(".")
    # Adjust the left padding to avoid the base64 padding error
    token_header = at_list[0].ljust(int(math.ceil(len(at_list[0]) / 4)) * 4, '=')
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

        if len(temp_cer) % 64 != 0:
            ins_extra_ret = True
        else:
            ins_extra_ret = False

        for _ in range(int(cer_len/64)):
            temp_cer = temp_cer[:count] + ret_char + temp_cer[count:]
            count = count + 64 + len(ret_char)

        if ins_extra_ret:
            temp_cer = temp_cer + ret_char

        tok_sign_cer = "-----BEGIN CERTIFICATE-----\r\n" + \
                       temp_cer + \
                       "-----END CERTIFICATE-----"

        cert = x509.load_pem_x509_certificate(
            tok_sign_cer.encode(),
            default_backend())
        public_key = cert.public_key()

        # now set the idp_keys discretionary entry
        idp_keys[x5t] = public_key

    try:
        claims = jwt.decode(
            access_token,
            idp_keys[tok_x5t],
            audience=audience,
            issuer=issuer,
            algorithms=["RS256"])
        return claims

    except jwt.ExpiredSignatureError as err:
        logging.error('Token has expired. Please log in again.: %s', err)
        raise

    except jwt.InvalidTokenError as err:
        logging.error('Invalid token. Please log in again. : %s', err)
        raise


def test_authorisation_code():
    client_id = "ID_12345"
    resource = "MOCK:URI:RS-104134-21171-mockapi-PROD"
    domain = "my-domain"
    username = "my-name"
    domain_name = f"{domain}\\{username}"
    nonce = "XX"
    scope = "openid profile"
    authorisation_code = create_authorisation_code(
        client_id=client_id,
        resource=resource,
        username=domain_name,
        nonce=nonce,
        scope=scope)
    if authorisation_code is None:
        raise Exception("invalid authorisation code")
    else:
        access_token = get_access_token_from_authorisation_code(authorisation_code)
        if access_token is None:
            raise Exception("invalid access token")
        else:
            claims = validate_access_token(
                access_token=access_token["access_token"],
                audience=resource,
                issuer=ISSUER)
            assert claims["aud"] == [client_id, resource] and\
                   claims["iss"] == ISSUER and\
                   claims["appid"] == client_id and \
                   claims["nonce"] == nonce and \
                   claims["username"] == username


def test_authenticate_token():
    client_id = "ID_54321"
    resource = "MOCK:URI:RS-104134-21171-mockapi-TEST"
    domain = "my-domain"
    username = "my-name"
    domain_name = f"{domain}\\{username}"
    user_secret = "XXX"
    nonce = "YY"
    scope = "openid profile"
    access_token = authenticate_token(
        client_id=client_id,
        resource=resource,
        username=domain_name,
        user_secret=user_secret,
        nonce=nonce,
        scope=scope)
    if access_token is None:
        raise Exception("invalid access token")
    else:
        claims = validate_access_token(
            access_token=access_token["access_token"],
            audience=resource,
            issuer=ISSUER)
        assert claims["aud"] == [client_id, resource] and \
               claims["iss"] == ISSUER and \
               claims["appid"] == client_id and \
               claims["nonce"] == nonce and \
               claims["username"] == username
