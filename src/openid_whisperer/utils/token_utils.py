import base64
import json
import math
from typing import Dict, Any, List, Optional

import jwt
from cryptography import x509
from cryptography.hazmat.backends import default_backend


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
            f"-----BEGIN CERTIFICATE-----\r\n{temp_cer}-----END CERTIFICATE-----"
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
) -> List[Any]:
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
    jwks_keys: Dict[str, Any],
    algorithms: List[str],
    audience: Optional[List[str]] = None,
    issuer: Optional[str] = None,
) -> List[Any]:
    """Proxy function for validate_access_token"""
    return validate_access_token(
        access_token=access_token,
        jwks_keys=jwks_keys,
        algorithms=algorithms,
        audience=audience,
        issuer=issuer,
    )
