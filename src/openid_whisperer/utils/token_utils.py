import base64
import hashlib
import json
import math
from typing import Dict, Any, List

import jwt
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from openid_whisperer.openid_lib import get_keys


def urlsafe_b64decode(s: str) -> bytes:
    s += b"=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def urlsafe_b64encode(s: str) -> bytes:
    return base64.urlsafe_b64encode(s).rstrip(b"=")


def generate_s256_code_challenge(code_verifier: str) -> str:
    """Returns S256 code_challenge hash of the input code_verifier."""
    code_verifier_hash = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return urlsafe_b64encode(code_verifier_hash).decode("utf-8")


def validate_s256_code_challenge(code_verifier: str, code_challenge: str) -> bool:
    """Returns True is the s256 hash of code_verifier is the same as the code_challenge"""
    return generate_s256_code_challenge(code_verifier) == code_challenge


def validate_access_token(access_token: str, audience: str, issuer: str, algorithms: List[str]) -> bool:
    """ Returns True or False depending on the validity of the input access_token.

    :param access_token: encoded token string
    :param audience: the scope / permission claims required to be present in the token
    :param issuer: the name of the token signature signer to validate
    :param algorithms: token signature encryption methods
    :return: bool, whether a valid access token
    """
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
        temp_cer = x5c.replace("\/", "/")  # TODO: investigate why this fails certain code / lint checks
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

        # Set the idp_keys discretionary entry
        idp_keys[x5t] = public_key

    claims = jwt.decode(
        access_token,
        idp_keys[tok_x5t],
        audience=audience,
        issuer=issuer,
        algorithms=algorithms,
    )
    return claims
