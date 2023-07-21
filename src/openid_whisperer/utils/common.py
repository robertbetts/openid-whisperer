""" Module with package wide utility functions and constants.
"""

import base64
import hashlib
import logging
from calendar import timegm
from datetime import datetime, timezone
from typing import Dict, overload, List, Optional

LOGGER_NAME = "openid_whisperer"

SCOPE_PROFILES = [
    "user_impersonation",
    "offline_access",
    "profile",
    "email",
    "address",
    "phone",
    "openid",
]
RESPONSE_TYPES_SUPPORTED: List[str] = [
    "code",
    "id_token",
    "code id_token",
    "id_token token",
    "code token",
    "code id_token token",
]
RESPONSE_MODES_SUPPORTED: List[str] = [
    "fragment",
    "query",
    "form_post"
]
GRANT_TYPES_SUPPORTED: List[str] = [
    "authorization_code",
    "refresh_token",
    "client_credentials",  # assumed in context of client-assertion-type
    # "jwt-bearer",  # assumed in context of grant-type
    "implicit",
    "password",
    "srv_challenge",
    "device_code",  # equivalent to urn:ietf:params:oauth:grant-type:device_code
    "urn:ietf:params:oauth:grant-type:device_code",
    "urn:ietf:params:oauth:grant-type:jwt-bearer",
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
]


def package_get_logger(module_name: str | None = None) -> logging.Logger:
    """Returns a logger named with a module's parent path. If module_name is None, then return
    the value of LOGGER_NAME.
    This function operates on the assumption that __name__ would be passed in when called.

    special case: if len(name.split(".")) == 1, then use name as input.

    :param module_name:
    :return:
    """
    module_name = module_name if module_name else LOGGER_NAME
    name_parts = module_name.split(".")
    if len(name_parts) == 1:
        logger_name = module_name
    else:
        logger_name = ".".join(name_parts[:-1])
    logger_instance = logging.getLogger(logger_name)
    return logger_instance


class GeneralPackageException(Exception):
    """Exception Recipe for API error responses"""

    def __init__(self, error: str, error_description: str):
        Exception.__init__(self, f"{error}: {error_description}")
        self.error: str = error
        self.error_description: str = error_description

    def to_dict(self) -> Dict[str, str]:
        return {
            "error": self.error,
            "error_description": self.error_description,
        }


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


@overload
def urlsafe_b64encode(s: str) -> bytes:
    """Stub for urlsafe_b64encode DO NOT REMOVE"""
    pass


@overload
def urlsafe_b64encode(s: bytes) -> bytes:
    """Stub for urlsafe_b64encode DO NOT REMOVE"""
    pass


def urlsafe_b64encode(s) -> bytes:
    """Implementation of urlsafe_b64encode"""
    s = s if isinstance(s, bytes) else s.encode()
    return base64.urlsafe_b64encode(s).rstrip(b"=")


@overload
def urlsafe_b64decode(s: str) -> bytes:
    """Stub for urlsafe_b64decode DO NOT REMOVE"""
    pass


@overload
def urlsafe_b64decode(s: bytes) -> bytes:
    """Stub for urlsafe_b64decode DO NOT REMOVE"""
    pass


def urlsafe_b64decode(s) -> bytes:
    """Implementation of urlsafe_b64decode"""
    s = s.decode if isinstance(s, bytes) else s
    s += "b" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def stringify(value: str | None) -> str:
    """returns a string representation of the input value, turning None into an empty string"""
    if value is None:
        return ""
    else:
        return value


def boolify(value: str | None) -> bool:
    """returns a boolean representation of the input value, turning "1", "true" into True"""
    if str(value).lower() in ("1", "true"):
        return True
    else:
        return False


def get_audience(
    client_id: str, scope: str, resource: Optional[str] = None
) -> List[str]:
    """Returns a list of resources, a token holder is authorised for. As scope is used to both specify
    claim fields included in the token and resources to be authorised, the standard SCOPE_PROFILES are excluded from
    the returned audience list.

    data cleanup rules: comma values are replaced by spaces, all preceding and training spaces are removed from
    the returned audience items.

    :param client_id:
    :param scope: space separated string of profile scopes and resource references
    :param resource: a list of resource names
    :return:
    """
    resource = resource if resource else ""
    resource_list = (
        resource
        if isinstance(resource, list)
        else [item.strip() for item in resource.replace(",", " ").split(" ")]
    )
    scope = scope if scope else "openid"
    scope_list = [item.strip() for item in scope.replace(",", " ").split(" ")]
    resource_list.extend(scope_list)
    audience = {client_id}
    for item in resource_list:
        if item != "" and item.lower() not in SCOPE_PROFILES:
            audience.add(item)
    return list(audience)


def validate_grant_type(grant_type: str) -> str:
    """Returns an echo of grant_type if it is valid and supported

    OpenidException is raised for validation and processing errors

    Parameters
    ----------
    grant_type:
        required str
    """
    error_message: str | None = None
    if grant_type is None or grant_type == "":
        error_message = "An empty input for grant_type is not supported"
    elif grant_type not in GRANT_TYPES_SUPPORTED:
        error_message = f"The grant_type of '{grant_type}' is not supported"

    if error_message is None and grant_type not in (
        "authorization_code",
        "password",
        "client_credentials",
        "refresh_token",
        "device_code",  # associated with urn:ietf:params:oauth:grant-type:device_code
        "urn:ietf:params:oauth:grant-type:device_code",
        "jwt-bearer",  # associated with urn:ietf:params:oauth:grant-type:jwt-bearer
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
    ):
        error_message = f"The grant_type of '{grant_type}' is not implemented"

    if error_message is not None:
        from openid_whisperer.openid_interface import OpenidApiInterfaceException
        raise OpenidApiInterfaceException("api_validation_error", error_message)

    return grant_type
