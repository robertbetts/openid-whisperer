""" Primary oAuth Library

    Functions to support OAuth 2.0 provider that is capable of Authenticating the End-User and providing Claims to a
    Relaying Party about the Authentication event and the End-User.

    Following specification direction from OpenID:
    https://openid.net/specs/openid-connect-core-1_0.html

    Initial specifications taken from:
    https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/overview/ad-fs-openid-connect-oauth-flows-scenarios
"""
import logging
from datetime import datetime, timedelta, timezone
import hashlib
import base64
from urllib.parse import urljoin, quote
from uuid import uuid4
from typing import Dict, Any, Optional, List
import string
import secrets
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
UNIT_TESTING: bool = False

authorisation_codes: Dict[str, Any] = {}
access_tokens: Dict[str, Any] = {}

# for tracking device_code flow
device_code_requests: Dict[str, Any] = {}  # Indexed by user_code
device_user_codes: Dict[str, str] = {}  # Indexed by device_code

scopes_supported = [
    "user_impersonation",
    "offline_access",
    "profile",
    "email",
    "openid",
]
claims_supported: List[str] = [
    "aud",
    "iss",
    "iat",
    "exp",
    "auth_time",
    "nonce",
    "at_hash",
    "c_hash",
    "sub",
    "upn",
    "unique_name",
    "pwd_url",
    "pwd_exp",
    "mfa_auth_time",
    "sid",
    "nbf",
]
token_endpoint_auth_signing_alg_values: List[str] = [ALGORITHM]
id_token_signing_alg_values: List[str] = [ALGORITHM]
access_token_issuer = ISSUER


def split_scope_and_resource(scope: str, resource: str) -> tuple(List[str]):
    resource_list = [resource] if resource else []
    scope_list = []
    for item in scope.split(" "):
        if item in scopes_supported:
            if item not in scope_list:
                scope_list.append(item)
        else:
            resource_list.append(item)
    logging.debug(f"scope: {scope_list}")
    logging.debug(f"resource: {resource_list}")
    return scope_list, resource_list


def get_openid_configuration(base_url: str, tenant: str) -> Dict[str, Any]:
    openid_configuration: Dict[str, Any] = {
        "access_token_issuer": access_token_issuer,
        "as_access_token_token_binding_supported": False,
        "as_refresh_token_token_binding_supported": False,
        "authorization_endpoint": urljoin(base_url, f"{tenant}/oauth2/authorize"),
        "capabilities": ["kdf_ver2"],
        "claims_supported": claims_supported,
        "device_authorization_endpoint": urljoin(base_url, f"{tenant}/oauth2/devicecode"),
        "end_session_endpoint": urljoin(base_url, f"{tenant}/oauth2/logout"),
        "frontchannel_logout_session_supported": True,
        "frontchannel_logout_supported": True,
        "grant_types_supported": ["authorization_code",
                                  "refresh_token",
                                  "client_credentials",
                                  "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                  "implicit",
                                  "password",
                                  "srv_challenge",
                                  "urn:ietf:params:oauth:grant-type:device_code",
                                  "device_code"],
        "id_token_signing_alg_values_supported": id_token_signing_alg_values,
        "issuer": urljoin(base_url, f"{tenant}"),
        "jwks_uri": urljoin(base_url, f"{tenant}/discovery/keys"),
        "microsoft_multi_refresh_token": True,
        "op_id_token_token_binding_supported": False,
        "resource_access_token_token_binding_supported": False,
        "response_modes_supported": ["query", "fragment", "form_post"],
        "response_types_supported": ["code",
                                     "id_token",
                                     "code id_token",
                                     "id_token token",
                                     "code token",
                                     "code id_token token"],
        "rp_id_token_token_binding_supported": False,
        "scopes_supported": scopes_supported,
        "subject_types_supported": ["pairwise"],
        "token_endpoint": urljoin(base_url, f"{tenant}/oauth2/token"),
        "token_endpoint_auth_methods_supported": ["client_secret_post",
                                                  "client_secret_basic",
                                                  "private_key_jwt",
                                                  "windows_client_authentication"],
        "token_endpoint_auth_signing_alg_values_supported": token_endpoint_auth_signing_alg_values,
        "userinfo_endpoint": urljoin(base_url, f"{tenant}/userinfo")
    }
    return openid_configuration


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

        Specifications for standard industry claims can be found here:
            https://www.iana.org/assignments/jwt/jwt.xhtml#claims

    """
    payload: Dict[str, Any] | None = None
    if client_id and username:
        _ = scope
        username_parts = username.split("\\", 1)
        username = username_parts[1] if len(username_parts) > 1 else username

        auth_time = datetime.utcnow()
        expires_in = auth_time + timedelta(seconds=EXPIRES_SECONDS)
        _, audience = split_scope_and_resource(scope, resource)
        audience.append(client_id)
        payload = {
            "iss": ISSUER,
            "sub": uuid4().hex,
            "aud": audience,
            "exp": get_seconds_epoch(expires_in),
            "iat": get_seconds_epoch(auth_time),
            "auth_time": auth_time.isoformat(sep=" "),
            "nonce": nonce,
            "appid": client_id,
            "username": username,
            "email": "name.surname@mock-company.com",
            "ver": "1.0",
        }
        logging.debug(payload)
    return payload


def create_authorisation_code(
        client_id: str,
        resource: str,
        username: str,
        nonce: str,
        scope: str,
        code_challenge: str | None = None,
        expiry_timeout: int = 600
        ) -> Optional[str]:
    """ Create an authorisation code to pass back to authorisation requester
        which will allow them to request a valid access token

        When a value for code_challenge is entered, then we are supporting the device code
        authentication flow.
    """
    authorisation_code: str | None = None
    if client_id and username:
        if code_challenge:
            # user_codes: Dict[str, Any] = {}  # Indexed by user_code
            # device_user_code: Dict[str, str] = {}  # Indexed by device_code
            device_code_request = device_code_requests.pop(code_challenge, None)
            if device_code_request is None:
                raise Exception(f"no device code request found for {code_challenge}")

            authorisation_code = device_code_request["device_code"]
            # TODO: Check validity and expiry
        else:
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


def devicecode_request(
        base_url: str,
        tenant: str,
        client_id: str,
        scope: str,
        resource: Optional[str] = None) -> Dict[str, Any]:
    """ Generate a time limited user code, that can be authenticated against in order to create
        a valid token
    """

    # code that will be used to retrieve the token
    device_code = hashlib.sha256(uuid4().hex.encode()).hexdigest()

    # code the user will have to enter when authorising
    # if a user code exists, then generate a new code
    while True:
        user_code = ''.join(secrets.choice(string.digits) for i in range(8))
        if user_code not in device_code_requests:
            break

    expires_in = datetime.utcnow() + timedelta(minutes=15)
    response_type = "code"
    auth_link = urljoin(base_url, f"{tenant}/oauth2/authorize")
    auth_link += "?scope={}&response_type={}&client_id={}&resource={}".format(
            scope, response_type, client_id, resource
        )
    auth_link += "&prompt=login&code_challenge_method=plain"

    response = {
        "device_code": device_code,
        "user_code": user_code,
        "verification_uri":  quote(auth_link),
        "expires_in": int(expires_in.timestamp()),
        "interval": 5,
        "message": f"Enter the following code: {user_code} at this link, {auth_link}"
    }
    device_code_requests[user_code] = response
    device_user_codes[device_code] = user_code
    return response


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


def authenticate_code(client_id: str,
                      resource: str,
                      username: str,
                      user_secret: str,
                      nonce: str,
                      scope: str,
                      code_challenge: str | None = None,
                      kmsi: str | None = None,
                      mfa_code: str | None = None) -> Optional[str]:
    """ Using client_id, username, resource, user_secret and mfa_code to
        authenticate a user and return an authentication code
        if authentication fails then return None
    """
    _ = kmsi
    response: str | None = None
    if authenticate(client_id, resource, username, user_secret, mfa_code):
        response = create_authorisation_code(client_id, resource, username, nonce, scope, code_challenge)
    return response
