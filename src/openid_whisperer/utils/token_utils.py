import base64
import hashlib
import json
import math
from calendar import timegm
from datetime import datetime, timezone
from typing import Dict, Any, List, overload, Optional

import jwt
from cryptography import x509
from cryptography.hazmat.backends import default_backend


@overload
def urlsafe_b64decode(s: str) -> bytes:
    """Stub for urlsafe_b64decode DO NOT REMOVE"""
    pass


@overload
def urlsafe_b64decode(s: bytes) -> bytes:
    """Stub for urlsafe_b64decode DO NOT REMOVE"""
    pass


def urlsafe_b64decode(s):
    """Implementation of urlsafe_b64decode"""
    s = s.decode if isinstance(s, bytes) else s
    s += "b" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


@overload
def urlsafe_b64encode(s: str) -> bytes:
    """Stub for urlsafe_b64encode DO NOT REMOVE"""
    pass


@overload
def urlsafe_b64encode(s: bytes) -> bytes:
    """Stub for urlsafe_b64encode DO NOT REMOVE"""
    pass


def urlsafe_b64encode(s):
    """Implementation of urlsafe_b64encode"""
    s = s if isinstance(s, bytes) else s.encode()
    return base64.urlsafe_b64encode(s).rstrip(b"=")


def generate_s256_hash(s: str) -> str:
    """Returns S256 code_challenge hash of the input string s."""
    code_verifier_hash = hashlib.sha256(s.encode("ascii")).digest()
    return urlsafe_b64encode(code_verifier_hash).decode("utf-8")


def validate_s256_hash(s: str, code: str) -> bool:
    """Returns True is the s256 hash of code_verifier is the same as the code_challenge"""
    return generate_s256_hash(s) == code


def get_now_seconds_epoch() -> int:
    """returns seconds between 1 January 1970 and now"""
    return timegm(datetime.now(tz=timezone.utc).utctimetuple())


def get_seconds_epoch(time_now: datetime) -> int:
    """returns seconds between 1 January 1970 and time_now"""
    return timegm(time_now.utctimetuple())


def public_keys_from_x509_certificates(keys: Dict[str, Any]) -> Dict[str, Any]:
    """Returns a dictionary of public key objects generated from x509 certificates. The certificate
    information would typically be sourced from a token or identity providers /get_keys endpoint.
    """
    jwks_keys = {}
    # Loop through keys to create dictionary
    for key in keys["keys"]:
        x5t = key["x5t"]
        x5c = key["x5c"][0]
        temp_cer = x5c.replace(
            "\/", "/"
        )  # TODO: investigate why this fails certain code / lint checks
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
        jwks_keys[x5t] = public_key

    return jwks_keys


def validate_access_token(
    access_token: str,
    jwks_keys: Dict[str, Any],
    algorithms: List[str],
    audience: Optional[List[str]] = None,
    issuer: Optional[str] = None,
) -> List[any]:
    """Returns a list of claim from a verified access_token.

    :param access_token: encoded token string
    :param jwks_keys: dictionary of key_id and public_key objects
    :param algorithms: token signature encryption methods
    :param audience: the scope / permission claims required to be present in the token
    :param issuer: the name of the token signature signer to validate
    :return: Dict
    """
    token_parts = access_token.split(".")

    # Adjust the left padding to avoid the base64 padding error
    token_header = token_parts[0].ljust(
        int(math.ceil(len(token_parts[0]) / 4)) * 4, "="
    )
    header = json.loads(base64.b64decode(token_header).decode("utf-8"))
    tok_x5t = header["x5t"]
    public_key = jwks_keys[tok_x5t]
    # TODO: Experiment below with passing in the public key str or bytes for the public key
    claims = jwt.decode(
        jwt=access_token,
        key=public_key,
        audience=audience,
        issuer=issuer,
        algorithms=algorithms,
    )
    return claims


def validate_jwt_token(
    access_token: str,
    jwks_keys: List[Any],
    algorithms: List[str],
    audience: Optional[List[str]] = None,
    issuer: Optional[str] = None,
) -> List[any]:
    """Proxy function for validate_access_token"""
    return validate_access_token(
        access_token=access_token,
        jwks_keys=jwks_keys,
        algorithms=algorithms,
        audience=audience,
        issuer=issuer,
    )
