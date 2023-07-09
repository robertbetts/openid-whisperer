""" OpenID Library to Support the following authentication flows:
        * username and password flow
        * authorisation code flow
        * device code flow

    Supports OpenID 1.0 provider capable of authenticating and end-user and providing claims to a
    relaying party about the authentication event and the end-user.

    Specifications from OpenID:
    https://openid.net/specs/openid-connect-core-1_0.html

    Specifications referenced from Microsoft:
    https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/overview/ad-fs-openid-connect-oauth-flows-scenarios
"""
import json
import logging
from datetime import datetime, timedelta
import hashlib
from urllib.parse import urljoin
from uuid import uuid4
from typing import Dict, Any, Optional, List
import string
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509

import jwt

# Module configuration Information and default values
from openid_whisperer.config import get_cached_config
from openid_whisperer.openid_types import DeviceCodeRequestResponse
from openid_whisperer.utils.token_utils import (
    generate_s256_hash,
    get_seconds_epoch,
    get_now_seconds_epoch,
)


class OpenidException(Exception):
    def __init__(self, error_code: str, error_description: str):
        Exception.__init__(self, f"{error_code}: {error_description}")
        self.error_code: str = error_code
        self.error_description: str = error_description

    def to_dict(self) -> Dict[str, str]:
        return {
            "error": self.error_code,
            "error_code": self.error_code,
            "error_description": self.error_description,
        }


config = get_cached_config()
EXPIRES_SECONDS: int = 600
ALGORITHM: str = "RS256"
KEY_ID: str = "idp-key-id"
KEY: rsa.RSAPrivateKey = config.org_key
CERTIFICATE: x509.Certificate = config.org_cert
ISSUER: str = f"urn:whisperer:openid:issuer:{CERTIFICATE.serial_number}"


# Module authentication flow state tracking
authorization_codes: Dict[str, Any] = {}
access_tokens: Dict[str, Any] = {}
refresh_tokens: Dict[str, Any] = {}
code_challenges: Dict[str, Any] = {}  # Any: (code_challenge, code_challenge_method)

# Module device_code flow state tracking
device_code_requests: Dict[str, Any] = {}  # device_requests Indexed by device_code
user_device_codes: Dict[str, str] = {}  # device_codes Indexed by user_code
device_authorization_codes: Dict[
    str, str
] = {}  # authorization_codes Indexed by device_code


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


def split_scope_and_resource(scope: str, resource: str) -> tuple[List[str], List[str]]:
    resource_list = [resource] if resource else []
    scope_list = []
    for item in scope.split(" "):
        if item in scopes_supported:
            if item not in scope_list:
                scope_list.append(item)
        else:
            resource_list.append(item)
    return scope_list, resource_list


def get_openid_configuration(tenant: str, base_url: str) -> Dict[str, Any]:
    openid_configuration: Dict[str, Any] = {
        "access_token_issuer": access_token_issuer,
        "as_access_token_token_binding_supported": False,
        "as_refresh_token_token_binding_supported": False,
        "authorization_endpoint": urljoin(base_url, f"{tenant}/oauth2/authorize"),
        "capabilities": ["kdf_ver2"],
        "claims_supported": claims_supported,
        "device_authorization_endpoint": urljoin(
            base_url, f"{tenant}/oauth2/devicecode"
        ),
        "end_session_endpoint": urljoin(base_url, f"{tenant}/oauth2/logout"),
        "frontchannel_logout_session_supported": True,
        "frontchannel_logout_supported": True,
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "implicit",
            "password",
            "srv_challenge",
            "urn:ietf:params:oauth:grant-type:device_code",
            "device_code",
        ],
        "id_token_signing_alg_values_supported": id_token_signing_alg_values,
        "issuer": urljoin(base_url, f"{tenant}"),
        "jwks_uri": urljoin(base_url, f"{tenant}/discovery/keys"),
        "microsoft_multi_refresh_token": True,
        "op_id_token_token_binding_supported": False,
        "resource_access_token_token_binding_supported": False,
        "response_modes_supported": ["query", "fragment", "form_post"],
        "response_types_supported": [
            "code",
            "id_token",
            "code id_token",
            "id_token token",
            "code token",
            "code id_token token",
        ],
        "rp_id_token_token_binding_supported": False,
        "scopes_supported": scopes_supported,
        "subject_types_supported": ["pairwise"],
        "token_endpoint": urljoin(base_url, f"{tenant}/oauth2/token"),
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "client_secret_basic",
            "private_key_jwt",
            "windows_client_authentication",
        ],
        "token_endpoint_auth_signing_alg_values_supported": token_endpoint_auth_signing_alg_values,
        "userinfo_endpoint": urljoin(base_url, f"{tenant}/userinfo"),
    }
    return openid_configuration


def create_access_token_response(
    payload: Dict[str, Any], headers: Dict[str, Any] | None = None
) -> Dict[str, Any]:
    """Returns an access_token response dictionary with the keys below.

    access_token	The requested access token. The app can use this token to
                    authenticate to the secured resource(Web API).
    token_type	Indicates the token type value. The only type currently
                supported is Bearer.
    expires_in	How long the access token is valid (in seconds).
    refresh_token	An OAuth 2.0 refresh token. The app can use this token to
                    acquire more access tokens after the current access token
                    expires. Refresh_tokens are long-lived, and can be used to
                    retain access to resources for extended periods of time.
    refresh_token_expires_in	How long the refresh token is valid (in seconds).
    id_token	A JSON Web Token (JWT). The app can decode the segments of this
                token to request information about the user who signed in. The
                app can cache the values and display them, but it shouldn't
                rely on them for any authorization or security boundaries.
    """
    headers = headers if isinstance(headers, dict) else {}

    access_token = jwt.encode(payload, KEY, algorithm=ALGORITHM, headers=headers)
    expires_in = datetime.utcnow() + timedelta(seconds=EXPIRES_SECONDS)
    refresh_token = ""
    refresh_token_expires_in = datetime.utcnow() + timedelta(seconds=EXPIRES_SECONDS)
    access_token_response = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": get_seconds_epoch(expires_in),
        "refresh_token": refresh_token,
        "refresh_token_expires_in": get_seconds_epoch(refresh_token_expires_in),
        "id_token": access_token,
    }
    access_tokens[access_token] = access_token_response
    return access_token_response


def get_end_user_information(
    client_id: str, scope: str, resource: str, username: str, nonce: str
) -> Dict[str, Any] | None:
    """Retrieve user information for the end user identified by client_id and username

    # TODO: rename this function to something like get_access_token or get get_identity_token

    Specifications for standard industry claims found here:
        https://www.iana.org/assignments/jwt/jwt.xhtml#claims
    """
    payload: Dict[str, Any] | None = None
    if client_id and username:
        auth_time = datetime.utcnow()
        expires_in = auth_time + timedelta(seconds=EXPIRES_SECONDS)
        _, audience = split_scope_and_resource(scope, resource)
        audience.append(client_id)
        payload = {
            "iss": ISSUER,
            "sub": username,
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


def create_jwt_token(
    issuer_key: rsa.RSAPrivateKey,
    issuer_cert: x509.Certificate,
    client_id: str,
    scope: str,
    resource: str,
    username: str,
    nonce: str,
) -> Dict[str, Any]:
    """
    KEY, algorithm=ALGORITHM
    :param issuer_key:
    :param issuer_cert:
    :param client_id:
    :param scope:
    :param resource:
    :param username:
    :param nonce:
    :return:
    """
    auth_time = datetime.utcnow()
    expires_in = auth_time + timedelta(seconds=EXPIRES_SECONDS)
    _, audience = split_scope_and_resource(scope, resource)
    audience.append(client_id)
    claims = {
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
    headers = {
        "kid": private_key_id,
        "x5t": private_key_id,
    }
    return jwt.encode(claims, issuer_key, algorithm=ALGORITHM, headers=headers)


def create_authorisation_code(
    client_id: str,
    scope: str,
    resource: str,
    username: str,
    nonce: str,
    code_challenge_method: Optional[str] = None,
    code_challenge: Optional[str] = None,
    user_code: Optional[str] = None,
    expiry_timeout: int = 600,
) -> Optional[str]:
    """Returns an authorization_code for an access_token to an authorization requester."""
    device_code: str | None = None
    if user_code:
        device_code = user_device_codes.pop(user_code, None)
        if device_code is None:
            raise OpenidException(
                "device_code_missing_error",
                f"Invalid user code {user_code}",
            )
        logging.debug(
            "authorization_code issued relating to device code request from user_code: %s",
            user_code,
        )
        device_code_request = device_code_requests[device_code]
        time_now = get_now_seconds_epoch()
        if device_code_request["expires_in"] <= time_now:
            raise OpenidException(
                "device_code_request_timeout",
                f"device code request for user code {user_code} has timed out",
            )
        # TODO: Check the validity of the device code request

    expires_in = datetime.utcnow() + timedelta(seconds=expiry_timeout)
    authorization_code_request = {
        "expires_in": get_seconds_epoch(expires_in),
        "client_id": client_id,
        "resource": resource,
        "username": username,
        "nonce": nonce,
        "scope": scope,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
    }
    authorization_code = generate_s256_hash(json.dumps(authorization_code_request))
    if code_challenge_method != "code_challenge":
        logging.debug(
            "authorization_code issued from code challenge: %s, %s -> %s",
            code_challenge_method,
            code_challenge,
            authorization_code,
        )
    if device_code:
        device_authorization_codes[device_code] = authorization_code
        logging.debug(
            "linking device_code to authorization_code: %s -> %s",
            device_code,
            authorization_code,
        )
    authorization_codes[authorization_code] = authorization_code_request

    return authorization_code


def devicecode_request(
    base_url: str,
    tenant: str,
    client_id: str,
    scope: str,
    resource: Optional[str] = None,
    nonce: Optional[str] = None,
    response_type: Optional[str] = None,
    code_challenge_method: Optional[str] = None,
    prompt: Optional[str] = None,
) -> DeviceCodeRequestResponse:
    """Generate a time limited user code, that can be authenticated against in order to create
    a valid token

    FYI, verification_uri_complete is returned by this function, however there is no
    current support for validating user_codes and authenticating the end user through
    a single HTTP GET request.
    """

    # code the user will have to enter when authorising
    # if a user code exists, then generate a new code
    user_code: str
    while True:
        user_code = "".join(secrets.choice(string.digits) for _ in range(8))
        if user_code not in user_device_codes:
            break

    device_code = hashlib.sha256(user_code.encode("ascii")).hexdigest()

    expires_in = datetime.utcnow() + timedelta(minutes=15)

    # Defaults for device code end user inputs
    nonce = nonce if nonce else ""
    response_type = response_type if response_type else "code"
    code_challenge_method = code_challenge_method if code_challenge_method else "plain"
    prompt = prompt if prompt else "login"

    auth_link = urljoin(base_url, f"{tenant}/oauth2/authorize")
    auth_link = (
        f"{auth_link}?response_type={response_type}&client_id={client_id}&scope={scope}"
        f"&resource={resource}&prompt={prompt}&code_challenge_method={code_challenge_method}"
        f"&nonce={nonce}"
    )
    auth_link_complete = f"{auth_link}&user_code={user_code}"

    device_code_request = {
        "code_challenge_method": code_challenge_method,
        "device_code": device_code,
        "user_code": user_code,
        "verification_uri": auth_link,
        "verification_uri_complete": auth_link_complete,
        "expires_in": get_seconds_epoch(expires_in),
        "interval": 5,
        "message": f"Enter the following code: {user_code} at this link, {auth_link}",
    }
    device_code_requests[device_code] = device_code_request
    user_device_codes[user_code] = device_code
    return device_code_request


def get_access_token_from_authorisation_code(
    authorisation_code: str,
) -> Dict[str, Any] | None:
    """Search for the given code amongst the issued authorisation codes and if present, then create
    and return an access token.
    """
    response = None
    auth_request_info = authorization_codes.get(authorisation_code)
    if auth_request_info:
        payload = get_end_user_information(
            auth_request_info["client_id"],
            auth_request_info["scope"],
            auth_request_info["resource"],
            auth_request_info["username"],
            auth_request_info["nonce"],
        )
        if payload:
            headers = {
                "typ": "JWT",
                "kid": KEY_ID,
                "x5t": KEY_ID,
            }
            response = create_access_token_response(payload, headers)
    return response


def authenticate_end_user(
    client_id: str,
    resource: str,
    username: str,
    user_secret: str,
    mfa_code: str | None = None,
) -> bool:
    """Using (username and user_secret, mfa_code) to authenticate against a (client_id, resource),
    and return True or False

    This always returns True there are non-empty strings for the parameters: client_id, username, user_secret
    """
    _, _ = resource, mfa_code
    response = False
    if client_id and username and user_secret:
        response = True
    return response


def authenticate_with_token_response(
    response_type: str,
    client_id: str,
    resource: str,
    username: str,
    user_secret: str,
    nonce: str,
    scope: str,
    kmsi: str | None = None,
    mfa_code: str | None = None,
) -> Dict[str, Any] | None:
    """Returns an access token after authenticating against client_id, resource, username,
    user_secret, kmsi and mfa_code
    if authentication fails return None
    """
    _, _, _ = kmsi, mfa_code, response_type
    response = None
    if authenticate_end_user(client_id, resource, username, user_secret, mfa_code):
        payload = get_end_user_information(client_id, scope, resource, username, nonce)
        if payload:
            headers = {
                "kid": KEY_ID,
                "x5t": KEY_ID,
            }
            response = create_access_token_response(payload, headers)
    return response


def authenticate_with_code_response(
    client_id: str,
    resource: str,
    username: str,
    user_secret: str,
    nonce: str,
    scope: str,
    code_challenge_method: str | None = None,
    code_challenge: str | None = None,
    user_code: str | None = None,
    kmsi: str | None = None,
    mfa_code: str | None = None,
) -> Optional[str]:
    """Returns an access_token after authenticating the end user and validating a user_code or code_challenge
    if authentication or validation fails, then an OpenidException is raised

    # TODO: Add extend input to receive redirect_uri and pass on to create_authorisation_code
    """
    _ = kmsi
    response: str | None = None
    if not authenticate_end_user(client_id, resource, username, user_secret, mfa_code):
        raise OpenidException(
            "authentication_error",
            "Unable to authenticate the end user, while processing code challenge",
        )

    access_token = create_authorisation_code(
        client_id=client_id,
        scope=scope,
        resource=resource,
        username=username,
        nonce=nonce,
        code_challenge_method=code_challenge_method,
        code_challenge=code_challenge,
        user_code=user_code,
    )
    if access_token is None:
        raise OpenidException(
            "authorization_error", "error validating the code challenge"
        )

    return access_token
