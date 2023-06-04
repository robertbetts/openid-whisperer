""" Primary oAuth Library

    Functions to support OAuth 2.0 provider that is capable of Authenticating the End-User and providing Claims to a
    Relaying Party about the Authentication event and the End-User.

    Following specification direction from OpenID:
    https://openid.net/specs/openid-connect-core-1_0.html

    Initial specifications taken from:
    https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/overview/ad-fs-openid-connect-oauth-flows-scenarios
"""
from datetime import datetime, timedelta, timezone
import hashlib
import base64
from uuid import uuid4
from typing import Dict, Any, Optional
from calendar import timegm
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from cryptography.hazmat.primitives import serialization
from cryptography import x509

import jwt
from jwt.utils import to_base64url_uint

from openid_whisperer import cert_utils

EXPIRES_SECONDS: int = 600
ALGORITHM: str = "RS256"
KEY_ID: str = "idp-key-id"
KEY: rsa.RSAPrivateKey = cert_utils.cert_key
CERTIFICATE: x509.Certificate = cert_utils.cert
ISSUER: str = f"urn:whisperer:openid:issuer:{cert_utils.identity_provider_serial_number}"

authorisation_codes: Dict[str, Any] = {}
access_tokens: Dict[str, Any] = {}


def get_now_seconds_epoch() -> int:
    """ returns seconds between 1 January 1970 and now
    """
    return timegm(datetime.now(tz=timezone.utc).utctimetuple())


def get_seconds_epoch(time_now: datetime) -> int:
    """ returns seconds between 1 January 1970 and time_now
    """
    return timegm(time_now.utctimetuple())


def get_keys() -> Dict[str, Any]:
    """ returns public key info
    """
    pn_n: str = ""
    pn_e: str = ""
    public_key: CertificatePublicKeyTypes = CERTIFICATE.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        public_numbers: rsa.RSAPublicNumbers = public_key.public_numbers()
        pn_n = to_base64url_uint(public_numbers.n).decode("ascii")
        pn_e = to_base64url_uint(public_numbers.e).decode("ascii")
    public_cert: bytes = CERTIFICATE.public_bytes(
                    encoding=serialization.Encoding.DER
                )
    x5c: str = base64.b64encode(public_cert).decode("ascii")
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": ALGORITHM,
                "kid": KEY_ID,
                "x5t": KEY_ID,
                "n": pn_n,
                "e": pn_e,
                "x5c": [x5c],
            }
        ]
    }


def create_access_token_response(
        payload: Dict[str, Any],
        headers: Dict[str, Any] | None = None
        ) -> Dict[str, Any]:
    """ return an access_token response dictionary with the keys below.

    access_token	The requested access token. The app can use this token to 
                    authenticate to the secured resource(Web API).
    token_type	Indicates the token type value. The only type that AD FS 
                supports is Bearer.expires_in	How long the access token is 
                valid (in seconds).
    refresh_token	An OAuth 2.0 refresh token. The app can use this token to 
                    acquire more access tokens after the current access token 
                    expires. Refresh_tokens are long-lived, and can be used to 
                    retain access to resources for extended periods of time.
    refresh_token_expires_in	How long the refresh token is valid (in 
                                seconds).
    id_token	A JSON Web Token (JWT). The app can decode the segments of this 
                token to request information about the user who signed in. The 
                app can cache the values and display them, but it shouldn't 
                rely on them for any authorization or security boundaries.
    """
    headers = headers if isinstance(headers, dict) else {}

    access_token = \
        jwt.encode(payload, KEY, algorithm=ALGORITHM, headers=headers)
    expires_in = datetime.utcnow() + timedelta(seconds=EXPIRES_SECONDS)
    refresh_token = ""
    refresh_token_expires_in = \
        datetime.utcnow() + timedelta(seconds=EXPIRES_SECONDS)
    access_token_response = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": get_seconds_epoch(expires_in),
        "refresh_token": refresh_token,
        "refresh_token_expires_in":
            get_seconds_epoch(refresh_token_expires_in),
        "id_token": access_token,
    }
    access_tokens[access_token] = access_token_response
    return access_token_response


def get_client_id_information(
        client_id: str,
        resource: str,
        username: str,
        nonce: str,
        scope: str,
        ) -> Dict[str, Any] | None:
    """ Retrieve user information for the user identified by username within 
        the scope the application identified by client_id
        If there is no valid scope for username within the application 
        client_id then return None
    """
    payload: Dict[str, Any] | None = None
    if client_id and username:
        _ = scope
        username_parts = username.split("\\", 1)
        if len(username_parts) > 1:
            username = username_parts[1]

        auth_time = datetime.utcnow()
        expires_in = auth_time + timedelta(seconds=EXPIRES_SECONDS)
        payload = {
            "iss": ISSUER,
            "sub": uuid4().hex,
            "aud": [client_id, resource],
            "exp": get_seconds_epoch(expires_in),
            "iat": get_seconds_epoch(auth_time),
            "auth_time": auth_time.isoformat(sep=" "),
            "nonce": nonce,
            "appid": client_id,
            "username": username,
            "Email": "name.surname@mock-company.com",
            "ver": "1.0",
        }
    return payload


def create_authorisation_code(
        client_id: str,
        resource: str,
        username: str,
        nonce: str,
        scope: str,
        expiry_timeout: int = 600
        ) -> Optional[str]:
    """ create an authorisation code to pass back to authorisation requester 
        which will allow them to request a valid access token
    """
    authorisation_code: str | None = None
    if client_id and username:
        authorisation_code = hashlib.sha256(uuid4().hex.encode()).hexdigest()
        expires_in = datetime.utcnow() + timedelta(seconds=expiry_timeout)
        authorisation_codes[authorisation_code] = {
            "authorisation_code": authorisation_code,
            "expires_in": int(expires_in.timestamp()),
            "client_id": client_id,
            "resource": resource,
            "username": username,
            "nonce": nonce,
            "scope": scope,
        }
    return authorisation_code


def get_access_token_from_authorisation_code(
        code: str
        ) -> Dict[str, Any] | None:
    """ Search for code in issued authorisation codes, if found then create and
        return an access token response
    """
    response = None
    auth_request_info = authorisation_codes.get(code)
    if auth_request_info:
        payload = get_client_id_information(auth_request_info["client_id"],
                                            auth_request_info["resource"],
                                            auth_request_info["username"],
                                            auth_request_info["nonce"],
                                            auth_request_info["scope"],)
        if payload:
            headers = {
                "typ": "JWT",
                "kid": KEY_ID,
                "x5t": KEY_ID,
            }
            response = create_access_token_response(payload, headers)
    return response


def authenticate(
        client_id: str,
        resource: str,
        username: str,
        user_secret: str,
        mfa_code: str | None = None
        ) -> bool:
    """ Using client_id, resource, username and user_secret, mfa_code to 
        authenticate a user and return True or False
    """
    _, _ = resource, mfa_code
    response = False
    if client_id and username and user_secret:
        response = True
    return response


def authenticate_token(
        client_id: str,
        resource: str,
        username: str,
        user_secret: str,
        nonce: str,
        scope: str,
        kmsi: str | None = None,
        mfa_code: str | None = None
        ) -> Dict[str, Any] | None:
    """ Using client_id, resource, username, user_secret, kmsi and mfa_code to
        authenticate a user and return an access_token_response
        if authentication fails then , return None
    """
    _, _ = kmsi, mfa_code
    response = None
    if authenticate(client_id, resource, username, user_secret):
        payload = get_client_id_information(client_id, resource, username, nonce, scope)
        if payload:
            headers = {
                "kid": KEY_ID,
                "x5t": KEY_ID,
            }
            response = create_access_token_response(payload, headers)
    return response


def authenticate_code(client_id: str, resource: str,
                      username: str, user_secret: str,
                      nonce: str,
                      scope: str,
                      kmsi: str | None = None,
                      mfa_code: str | None = None) -> Optional[str]:
    """ Using client_id, username, resource, user_secret and mfs_code to
        authenticate a user and return an authentication code
        if authentication fails then , return None
    """
    _ = kmsi
    response: str | None = None
    if authenticate(client_id, resource, username, user_secret, mfa_code):
        response = create_authorisation_code(client_id, resource, username, nonce, scope)
    return response
