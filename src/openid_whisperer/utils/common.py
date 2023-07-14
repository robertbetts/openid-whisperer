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
RESPONSE_MODES_SUPPORTED: List[str] = ["fragment", "query", "form_post"]
GRANT_TYPES_SUPPORTED: List[str] = [
    "authorization_code",
    "refresh_token",
    "client_credentials",
    "jwt-bearer",
    "urn:ietf:params:oauth:grant-type:jwt-bearer",
    "implicit",
    "password",
    "srv_challenge",
    "urn:ietf:params:oauth:grant-type:device_code",
    "device_code",
]


def package_get_logger(name: str | None = None) -> logging.Logger:
    """Returns a logger as appropriate for the package, name is None then returns LOGGER_NAME
    This function has been designed with the assumption that __name__ would be passed in when
    called.

    Assuming name will be a package.path.module_name, we only want to report in terms of the path not the
    module name.

    :param name:
    :return:
    """
    name = name if name else LOGGER_NAME
    name_parts = name.split(".")
    if len(name_parts) == 1:
        logger_name = name
    else:
        logger_name = ".".join(name_parts[:-1])
    logger_instance = logging.getLogger(logger_name)
    return logger_instance


class GeneralPackageException(Exception):
    """Exception Recipe for API error responses"""

    def __init__(self, error_code: str, error_description: str):
        Exception.__init__(self, f"{error_code}: {error_description}")
        self.error_code: str = error_code
        self.error_description: str = error_description

    def to_dict(self) -> Dict[str, str]:
        return {
            "error_code": self.error_code,
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
    audience: List[str] = [resource] if resource else []
    audience.append(client_id)
    scope = scope if scope else "openid"
    for item in scope.split(" "):
        aud = item.strip()
        if item not in SCOPE_PROFILES and item != "":
            audience.append(aud)
    return audience
