import logging
from typing import Dict, Any, Optional, List
import datetime
import hashlib
import secrets
from urllib.parse import urljoin
import string

from openid_whisperer.utils.common import GeneralPackageException
from openid_whisperer.utils.credential_store_utils import UserCredentialStore
from openid_whisperer.utils.token_store_utils import TokenIssuerCertificateStore
from openid_whisperer.utils.token_utils import get_seconds_epoch

logger = logging.getLogger(__name__)

SCOPE_PROFILES = [
    "user_impersonation",
    "offline_access",
    "profile",
    "email",
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


class OpenidApiInterfaceException(GeneralPackageException):
    """Exception raised when OpenidApiInterface requirements are not met, other runtime
    exceptions are passed through.
    """


def stringify(value: str | None) -> str:
    """returns a string representation of the input value, turning None into an empty string"""
    if value is None:
        return ""
    else:
        return value


def get_audience(
    client_id: str, scope: str, resource: Optional[str] = None
) -> List[str]:
    audience: List[str] = [resource] if resource else []
    audience.append(client_id)
    for item in scope.split(" "):
        aud = item.strip()
        if item not in SCOPE_PROFILES:
            audience.append(aud)
    return audience


def validate_response_type(response_type: str) -> str:
    """Returns response_type if response_type input is valid and is supported, else Raises an OpenidException

    Parameters
    ----------
    response_type:
        required, assumed to be a lowercase string
    """
    response_type_list = [
        item.strip() for item in response_type.split(" ") if item != ""
    ]
    response_type_list.sort()
    response_type_check = " ".join(response_type_list)
    if response_type_check not in RESPONSE_TYPES_SUPPORTED:
        raise OpenidApiInterfaceException(
            "auth_processing_error",
            f"Invalid response_type '{response_type}'. A call to /.well-known/openid-configuration will "
            "provide information on supported response types",
        )
    return response_type_check


def validate_response_mode(response_type: str, response_mode: str) -> str:
    """Returns an adjusted response_mode. where response_mode is an empty string, it is adjusted
    to the defaulted mode for the given response_type.
    Where there is an unsupported response_mode or invalid response_type/response_mode combination,
    an OpenidException is raised

    Parameters
    ----------
    response_type:
         required, assumed to be a lowercase string
    response_mode:
        required, assumed to be a lowercase string
    """
    error_message: str | None = None
    # Check for supported response_type / response_mode combinations
    # Check code first, the presence of code dictates Hybrid Flow
    if "code" in response_type and response_mode not in ("query", "form_post"):
        if response_mode == "":
            response_mode = "query"
        else:
            error_message = (
                f"Invalid response_mode of {response_mode} for request_type "
                f"{response_type}. response_mode 'query' expected."
            )
    elif "token" in response_type and response_mode not in ("fragment", "form_post"):
        if response_mode == "":
            response_mode = "fragment"
        else:
            error_message = (
                f"Invalid response_mode of {response_mode} for request_type "
                f"{response_type}. response_mode 'fragment' expected."
            )
    # General response_mode validity check
    if response_mode not in RESPONSE_MODES_SUPPORTED:
        error_message = f"Unsupported response_mode of {response_mode}."

    if error_message:
        raise OpenidApiInterfaceException("auth_processing_error", error_message)

    return response_mode


def validate_grant_type(grant_type: str) -> str:
    """Returns a tuple of (adjusted_grant_type, error_message)
    Where the input grant_typ is in the forman of an urn e.g."urn:ietf:params:oauth:grant-type:jwt-bearer",
    grant type is updated to only the grant_type reference.

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
    elif grant_type.startswith("urn:ietf:params:oauth:grant-type:"):
        grant_type = grant_type.split(":")[-1].strip()

    if error_message is None and grant_type not in (
        "device_code",
        "authorization_code",
        "password",
    ):
        error_message = f"The grant_type of '{grant_type}' not as yet implemented"

    if error_message is not None:
        raise OpenidApiInterfaceException("auth_processing_error", error_message)

    return grant_type


class OpenidApiInterface:
    def __init__(self, **kwargs) -> None:
        self.issuer_reference: str | None = None
        self.devicecode_expires_in: int | None = None
        # Update class properties from kwargs
        for key, value in kwargs.items():
            setattr(self, key, value)
        if self.issuer_reference is None or self.issuer_reference == "":
            self.issuer_reference = "urn:issuer:name:openid-whisperer"
        if self.devicecode_expires_in is None or self.devicecode_expires_in <= 0:
            self.devicecode_expires_in = 15 * 60

        self.credential_store = UserCredentialStore()
        self.token_store = TokenIssuerCertificateStore()

        self.devicecode_requests: Dict[
            str, Any
        ] = {}  # device_requests Indexed by device_code
        self.devicecode_user_codes: Dict[
            str, str
        ] = {}  # device_codes Indexed by user_code
        self.devicecode_authorization_codes: Dict[
            str, Any
        ] = {}  # authorization_codes Indexed by device_code

    @classmethod
    def validate_client(
        cls, client_id: str, client_secret: Optional[str] = None
    ) -> bool:
        """Returns True or False depending on where client_id validated. Validation currently
        is a non-empty string for client_id
        """
        _ = client_secret
        if isinstance(client_id, str) and client_id != "":
            return True
        return False

    def get_authorize(
        self,
        tenant: str,
        response_type: str,
        client_id: str,
        scope: str,
        resource: str,
        response_mode: str,
        redirect_uri: str,
        state: str,
        nonce: str,
        prompt: str,
        rcode: str,
        code_challenge_method: str,
        code_challenge: str,
    ) -> Dict[str, Any]:
        """Handles all GET requests to /{tenant}/oauth/authorize"""
        _ = tenant, rcode  # interface variables provided for future features

        response_type = validate_response_type(response_type)
        response_mode = validate_response_mode(response_type, response_mode)
        if not self.validate_client(client_id):
            raise OpenidApiInterfaceException(
                "auth_processing_error", "A valid client_id is required"
            )

        """ resource is a legacy of ADFS, an in order to move to the OpenID Specification
            entitlements referenced in resource is treated as additional scope. 
        """
        scope = scope if scope else ""
        if resource not in scope:
            scope = f"{scope} {resource}"
            # Do not reference resource again in this function, use scope

        if "openid" not in scope:
            scope = f"openid {scope}"

        requires_user_code = False
        requires_pkce = False
        if code_challenge_method is not None and code_challenge_method != "":
            if code_challenge is not None and code_challenge != "":
                requires_user_code = False
                requires_pkce = True
            else:
                requires_user_code = True

        return {
            "action": "",
            "termination_reply": "",
            "client_id": client_id,
            "scope": scope,
            "nonce": nonce,
            "state": state,
            "redirect_uri": redirect_uri,
            "response_mode": response_mode,
            "response_type": response_type,
            "prompt": prompt,
            "requires_mfa": False,
            "allows_kmsi": "False",
            "code_challenge_method": code_challenge_method,
            "code_challenge": code_challenge,
            "requires_user_code": requires_user_code,
            "requires_pkce": requires_pkce,
            "submit_label": "Sing In",
        }

    def post_authorize(
        self,
        tenant: str,
        response_type: str,
        response_mode: str,
        client_id: str,
        client_secret: str,
        scope: str,
        redirect_uri: str,
        nonce: str,
        username: str,
        **kwargs: Optional[Any],
    ) -> Dict[str, Any]:
        """Processes the information from a post submission to the authorize endpoint

        TODO: Complete validation code_challenge s256 checks and originating redirect_uri
        """
        _ = (
            tenant,
            client_secret,
            response_mode,
        )  # interface variables provided for future features

        # raises OpenidApiInterfaceException on failed validation
        response_type = validate_response_type(response_type)

        if not self.validate_client(client_id):
            raise OpenidApiInterfaceException(
                "client_auth_error",
                "Unable to validate the referring client application.",
            )

        password = stringify(kwargs.get("password"))
        mfa_code = stringify(kwargs.get("mfa_code"))
        kmsi = stringify(kwargs.get("kmsi"))

        if not self.credential_store.authenticate(
            username=username, password=password, mfa_code=mfa_code, kmsi=kmsi
        ):
            raise OpenidApiInterfaceException(
                "authentication_error", "Valid credentials are required"
            )

        """With the device code flow, user_code and client_id are critical inputs supported by
        the end user credentials. Inputs like code_challenge_method can be retrieved by using the
        client_id and user_code as a lookup against the original device code request.
        """
        code_challenge_method: str = stringify(kwargs.get("code_challenge_method"))
        code_challenge: str = stringify(kwargs.get("code_challenge"))
        user_code: str = stringify(kwargs.get("user_code"))

        resource: str = stringify(kwargs.get("resource"))

        if "code" in response_type:
            """The response for response_type or "code" is typically a redirect, except for the devicecode flow.
            response_mode indicates the redirect url modification style or a form post reply (not implemented).
            With a devicecode flow, after this authentication step, the user would be presented with a HTML response.

            response_mode = validate_response_mode(response_type, response_mode)
            """

            """ The presence of a user_code indicates devicecode flow, retrieval of the original devicecode request 
            is need to complete the request authorisation process for the devicecode flow. 
            """
            device_code: str | None = None
            if user_code:
                device_code = self.devicecode_user_codes.pop(user_code, None)
                if device_code is None:
                    raise OpenidApiInterfaceException(
                        "devicecode_error",
                        "Invalid user code.",
                    )
                logger.debug("device code retrieved from user_code")

                devicecode_request = self.devicecode_requests.pop(device_code, None)
                # TODO: Check details of original devicecode request against, the provided inputs to this function

            """ With authentication successful for end user code response or device_code flow, a token is generated 
            that will be later retrieved by the client application.
            """
            # TODO: if scope is blank default to "openid" and update scope with client_id and resource
            user_claims = self.credential_store.get_user_scope_claims(
                username=username, scope=scope, nonce=nonce
            )
            audience = get_audience(client_id=client_id, scope=scope, resource=resource)

            authorization_code, token_response = self.token_store.create_new_token(
                client_id=client_id,
                issuer=self.issuer_reference,
                sub=username,
                user_claims=user_claims,
                audience=audience,
            )
            if device_code:
                device_authorization = {
                    "expires_in": token_response["expires_in"],
                    "client_id": client_id,
                    "code_challenge": code_challenge,
                    "code_challenge_method": code_challenge_method,
                    "redirect_uri": redirect_uri,
                    "authorization_code": authorization_code,
                }
                self.devicecode_authorization_codes[device_code] = device_authorization

            return {
                "authorization_code": authorization_code,
            }

        else:  # if "token" in response_type:
            # Endpoint response for a response_type of "token" is JSON

            # TODO: if scope is blank default to "openid" and update scope with client_id and resource
            user_claims = self.credential_store.get_user_scope_claims(
                username=username, scope=scope, nonce=nonce
            )
            audience = get_audience(client_id=client_id, scope=scope, resource=resource)

            authorization_code, token_response = self.token_store.create_new_token(
                client_id=client_id,
                issuer=self.issuer_reference,
                sub=username,
                user_claims=user_claims,
                audience=audience,
            )
            return token_response

    def get_devicecode_request(
        self,
        tenant: str,
        base_url: str,
        client_id: str,
        client_secret: str,
        scope: str,
        resource: Optional[str] = None,
        nonce: Optional[str] = None,
        response_type: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
        prompt: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate a time limited device_code for the requesting client applications and a user code,
        that an end user authenticated with in order to create a valid token
        """

        if not self.validate_client(client_id, client_secret):
            raise OpenidApiInterfaceException(
                "auth_processing_error", "A valid client_id is required"
            )

        user_code: str
        while True:
            user_code = "".join(secrets.choice(string.digits) for _ in range(8))
            if user_code not in self.devicecode_user_codes:
                break

        device_code = hashlib.sha256(user_code.encode("ascii")).hexdigest()

        # Defaults for device code end user inputs
        nonce = nonce if nonce else ""
        response_type = response_type if response_type else "code"
        code_challenge_method = (
            code_challenge_method if code_challenge_method else "plain"
        )
        prompt = prompt if prompt else "login"

        auth_link = urljoin(base_url, f"{tenant}/oauth2/authorize")
        auth_link = (
            f"{auth_link}?response_type={response_type}&client_id={client_id}&scope={scope}"
            f"&resource={resource}&prompt={prompt}&code_challenge_method={code_challenge_method}"
            f"&nonce={nonce}"
        )
        auth_link_complete = f"{auth_link}&user_code={user_code}"
        expires_in = datetime.datetime.utcnow() + datetime.timedelta(
            seconds=self.devicecode_expires_in
        )

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
        self.devicecode_requests[device_code] = device_code_request
        self.devicecode_user_codes[user_code] = device_code
        return device_code_request

    def get_token(
        self,
        tenant: str,
        grant_type: str,
        client_id: str,
        refresh_token: str,
        token_type: str,
        expires_in: int | str,
        access_token: str,
        client_secret: str,
        device_code: str,
        code: str,
        username: str,
        password: str,
        nonce: str,
        scope: str,
        resource: str,
        redirect_uri: str,
        code_verifier: str,
    ) -> Dict[str, Any]:
        """Returns a token included within a dictionary containing details of the issued token. Other JSON error
        responses could also be returned e.g. pending, unsuccessful, error.

        OpenidException could also be raised for various validation and processing errors
        """
        _ = (
            tenant,
            redirect_uri,
            code_verifier,
            refresh_token,
            token_type,
            expires_in,
            access_token,
        )  # interface variables provided for future features

        if not self.validate_client(client_id, client_secret):
            raise OpenidApiInterfaceException(
                "auth_processing_error", "A valid client_id is required"
            )

        # OpenidApiInterfaceException is raised below for an invalid grant_type
        grant_type = validate_grant_type(grant_type)

        token_response: Dict[str, Any] | None = None

        if grant_type == "device_code":
            devicecode_request = self.devicecode_requests.get(device_code, None)
            # TODO: check devicecode_request and handle additional unsuccessful
            #  error states, request expiry, authorization_declined etc.

            device_authorization = self.devicecode_authorization_codes.pop(
                device_code, None
            )
            if device_authorization is None:
                raise OpenidApiInterfaceException(
                    "devicecode_authorization_pending",
                    "End user authentication and user_code input has not been completed.",
                )

            """ The token is created when the end user validates the user code provided to them, the
                authorisation code is created and linked to the token at that time.
            """
            # TODO: Check for revoked tokens, device code request / token expiry etc.

            token_response = self.token_store.token_requests.get(
                device_authorization["authorization_code"], None
            )
            if token_response is None:
                raise OpenidApiInterfaceException(
                    "token_error",
                    "Token issued for end user devicecode flow, has been revoked.",
                )

        elif grant_type == "refresh_token":
            # TODO: Implement for grant_type, "on-behalf-of flow"
            raise OpenidApiInterfaceException(
                "bad_token_request", f"grant_type '{grant_type}' not implemented"
            )

        elif grant_type == "authorization_code":
            """Client application submits a parameter name code to reference a previously received authentication_code
            for a token that has been created and is ready for issue out of the token store.
            """
            # TODO: check redirect_uri validation is required
            # TODO: check what todo with code_verifier

            token_response = self.token_store.token_requests.pop(code)
            if token_response is None:
                raise OpenidApiInterfaceException(
                    "token_error",
                    "Token issued for end user devicecode flow, has been revoked.",
                )

        elif grant_type == "password":
            """End user information is provided as part of the request to issue a new token. There is no existing
            authentication flow related to this request.
            """

            if not self.credential_store.authenticate(
                username=username,
                password=password,
            ):
                raise OpenidApiInterfaceException(
                    "authentication_error", "Valid credentials are required"
                )

            # TODO: if scope is blank default to "openid" and update scope with client_id and resource
            user_claims = self.credential_store.get_user_scope_claims(
                username=username, scope=scope, nonce=nonce
            )
            audience = get_audience(client_id=client_id, scope=scope, resource=resource)

            _, token_response = self.token_store.create_new_token(
                client_id=client_id,
                issuer=self.issuer_reference,
                sub=username,
                user_claims=user_claims,
                audience=audience,
            )

        if token_response is None:
            raise OpenidApiInterfaceException(
                "token_error",
                "Invalid token request",
            )
        return token_response
