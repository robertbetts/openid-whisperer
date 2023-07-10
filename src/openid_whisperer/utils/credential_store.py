from typing import Dict, Any, Optional

from openid_whisperer.utils.common import (
    GeneralPackageException,
    get_now_seconds_epoch,
    generate_s256_hash,
)


class UserCredentialStoreException(GeneralPackageException):
    """Exception raised when UserCredentialStore requirements are not met, other runtime
    exceptions are passed through.
    """


class UserCredentialStore:
    """A class that provides end user management for an identity provider

    maximum_login_attempts of None or <=0 enables infinite authentication attempts
    """

    def __init__(self, **kwargs: Dict[str, Any]) -> None:
        self.validate_user: bool | None = None
        self.validate_password: bool | None = None
        self.json_users: str | None = None
        self.session_expiry_seconds: int | None = None
        self.maximum_login_attempts: int | None = None

        # Update class properties from kwargs
        for key, value in kwargs.items():
            setattr(self, key, value)

        self.end_user_db: Dict[str, Dict[str, Any]] = {}
        self.authenticated_session: Dict[
            str, float
        ] = {}  # login_time_stamp indexed by username
        self.failed_login_attempts: Dict[str, int] = {}  # Indexed by username

    def logoff(self, tenant: str, username: str) -> None:
        """Remove an authenticated_session if one exists for the user, if one does not exist then do nothing

        :param tenant:
        :param username:
        """
        # Future feature placeholder parameters
        _ = tenant

        self.authenticated_session.pop(username, None)

    def count_failed_authentication(self, username: str) -> bool:
        self.failed_login_attempts[username] = (
            self.failed_login_attempts.setdefault(username, 0) + 1
        )
        return False

    def authenticate(
        self,
        tenant: str,
        username: str,
        password: str,
        mfa_code: Optional[str] = None,
        kmsi: Optional[bool] = None,
    ) -> bool:
        """Returns True or False where the end user has been authenticated.

            Returning no reason for a failed authentication attempt is deliberate

            An existing session will be extended by session_expiry_seconds when a user authenticates

        :param tenant:
        :param username:
        :param password:
        :param mfa_code:
        :param kmsi:
        :return:
        """
        # Future feature placeholder parameters
        _ = tenant, mfa_code, kmsi

        if not username:
            return self.count_failed_authentication(username)

        if self.maximum_login_attempts and self.maximum_login_attempts > 0:
            if (
                self.failed_login_attempts.get(username, 0)
                > self.maximum_login_attempts
            ):
                return self.count_failed_authentication(username)

        # Mock user credentials require a non-zero length password
        if not password:
            return self.count_failed_authentication(username)

        if self.validate_user:
            user = self.end_user_db.get(username)
            if user is None:
                return False
            user_password = user["password"]
            if self.validate_password and (
                not user_password or generate_s256_hash(password) != user_password
            ):
                return self.count_failed_authentication(username)

        # existing session will be extended by session_expiry_seconds
        self.authenticated_session[username] = get_now_seconds_epoch()

        return True

    @classmethod
    def get_user_scope_claims(
        cls, username: str, scope: str, nonce: str
    ) -> Dict[str, Any]:
        _ = scope
        email_user = username.replace("@", "-")
        openid_claims_payload = {
            "nonce": nonce,
            "username": username,
            "email": f"{email_user}@mock-company.com",
        }
        return openid_claims_payload
