import logging
from typing import Dict, Any, List, Optional, TypedDict

from openid_whisperer import openid_lib
from openid_whisperer.openid_lib import OpenidException


class AuthTemplateInput(TypedDict):
    termination_reply: str
    action: str
    client_id: str
    scope: str
    nonce: str
    state: str
    redirect_uri: str
    response_mode: str
    response_type: str
    prompt: str
    requires_mfa: str
    allows_kmsi: str
    code_challenge_method: str
    code_challenge: str
    requires_user_code: bool
    requires_pkce: bool
    submit_label: str


logger = logging.getLogger(__name__)

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


def stringify(value: str | None) -> str:
    """returns a string representation of the input value, turning None into an empty string"""
    if value is None:
        return ""
    else:
        return value


def validate_client_id(client_id: str) -> str:
    """Returns client_id if successfully validating client_id else raises an
    OpenidException if unsuccessful
    """
    if client_id is None or client_id == "":
        raise OpenidException(
            "client_id_error", "Unable to validate the referring client application."
        )
    else:
        return client_id


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
        raise OpenidException(
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
        raise OpenidException("auth_processing_error", error_message)

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
        raise OpenidException("auth_processing_error", error_message)

    return grant_type


def initiate_end_user_authentication(
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
) -> AuthTemplateInput:
    """Returns a dictionary of values required to direct the end user through the required authentication flow

    OpenidException is raised for validation and processing errors

    If a value for code_challenge_method is present, then it is assumed that this request
    forms part of a device code authorisation flow. If there is an accompanied code_challenge
    then treat the request as a PKCE flow.

    FYI, verification_uri_complete is provided to the client application during a device code request,
    however there is no current support for validating user_codes and authenticating the end user through
    a single HTTP GET request.

    # TODO: Using prompt to direct additional form based flow requirements
    # TODO: Functionality is not as yet provided to check for existing authenticated session's based on incoming
            device / browser hitting the authorize endpoint.
    # TODO: It is the intention to support kerberos identity tokens

    POST only inputs:
    kmsi: optional
        Keep me signed in (yes/no)
    mfa: optional
        multi factor authentication code
    username:
        credentials to identify the end user
    user_secret:
        authentication secret to aid in verifying the asserted user

    Parameters
    ----------
    client_id: required
        The client identifier of an initiating application
    response_type: required
        Defines type of authorization flow. Must include "id_token" for end user sign-in.
        It may also include the response_type "token". Using token here allows your app
        to receive an access token immediately from the authorize endpoint without having
        to make a second request to the token endpoint.
    response_mode: optional
        Specifies the method that should be used to send the resulting token back
        to client_id. This value is defaulted to fragment.
        Possible values are query, fragment or form_post. The draft extension — JWT
        Secured Authorization Response Mode for OAuth 2.0 defines additional
        response modes, query.jwt, fragment.jwt, form_post.jwt or jwt.
    redirect_uri: required
        The redirect_uri for the client_id, where authentication responses can be sent.
    nonce: required
        A value included in the request, generated by the client_id that is to be
        included in the resulting id_token as a claim.
        The client_id can then verify this value to mitigate token replay
        attacks. The value is typically a randomized, unique string that
        can be used to identify the origin of the request. Only required
        when an id_token is requested.
    prompt: optional
        Space separated string specifying user prompts for re-authentication and
        consent. Values could be "none", "login", "consent" or "select_account"
    scope: optional
        A space-separated list of scopes and must include "openid". If
        scope is empty, it is defaulted to "openid"
    resource: optional
        A uri belonging the client_id indicating a permission context. Note: When
        using MSAL client library, then resource parameter isn't sent. Instead,
        the resource uri is sent as a part of the scope parameter:
            scope = [resource uri]//[scope values e.g., openid]
            With MS Active Directory, if resource isn't passed here or as part of
            scope, It then uses a default resource urn:microsoft:userinfo. The
            userinfo resource contains policies such as MFA, Issuance or
            authorization policy, can't be customized.
    state: optional
        An optional value included in the authentication request that must be
        returned with the token response. It can be any string, usually a
        randomly generated unique value and is typically used for preventing
        cross-site request forgery attacks. The state is also used to encode
        information about the user's state in the client_id application before
        the authentication request occurred, such as the page or view they were on.
    state: optional
        If a state value is included in the request, the same value should appear
        in the response. The client_id should verify that the state values in the
        request and following response are identical.
    rcode: optional
        The authorization_code that the client_id requested, it uses the
        authorization code to request an access token against the target
        resource. Authorization_codes are short-lived, typically expiring after
        about 10 minutes.
    code_challenge_method: optional
        str, “plain” (default) or “S256”. Can be used if code_challenge is
        sent. Defaults to “plain”. Needs to be sent if S256 is used as
        code_challenge method.
    code_challenge: optional
        str, A high entropy random challenge. A challenge generated by the client,
        if sent, the code_verifier must be sent on the token call. *Required
        when client must do PKCE (RFC7636).

    """

    _ = rcode  # interface variables provided for future features

    response_type = validate_response_type(response_type)
    response_mode = validate_response_mode(response_type, response_mode)
    if client_id == "":
        raise OpenidException("auth_processing_error", "A valid client_id is required")

    """ resource is a legacy of ADFS, an in order to move to the OpenID Specification
        entitlements referenced in resource is treated as additional scope. 
    """
    scope = scope if scope else ""
    if resource not in scope:
        scope = f"{scope} {resource}"
        # Do not reference resource again in this function, use scope

    if "openid" not in scope:
        scope = f"openid {scope}"

    action: str = ""

    # It is as this point where prompt can influence the direction of the flow, ignoring STP authentication
    # options and for example force a request for MFA code or entire new authentication process.

    requires_mfa = False
    requires_user_code = False
    requires_pkce = False
    if code_challenge_method is not None and code_challenge_method != "":
        if code_challenge is not None and code_challenge != "":
            requires_user_code = False
            requires_pkce = True
        else:
            requires_user_code = True

    allows_kmsi = False
    submit_label = "Sign In"

    response: AuthTemplateInput = {
        "termination_reply": "",
        "action": action,
        "client_id": client_id,
        "scope": scope,
        "nonce": nonce,
        "state": state,
        "redirect_uri": redirect_uri,
        "response_mode": response_mode,
        "response_type": response_type,
        "prompt": prompt,
        "requires_mfa": requires_mfa,
        "allows_kmsi": allows_kmsi,
        "code_challenge_method": code_challenge_method,
        "code_challenge": code_challenge,
        "requires_user_code": requires_user_code,
        "requires_pkce": requires_pkce,
        "submit_label": submit_label,
    }
    return response


def process_end_user_authentication(
    response_type: str,
    response_mode: str,
    client_id: str,
    client_secret: str,
    scope: str,
    redirect_uri: str,
    nonce: str,
    username: str,
    user_secret: str,
    **kwargs: Optional[Any],
) -> Dict[str, Any]:
    """Processes the information from a post submission to the authorize endpoint and returns
    the information as appropriate to the given authorisation flow.

    OpenidException is raised for validation and processing errors

    if a value for code_challenge_method is present, then it is assumed that this request
    is part of a device code authorisation flow where the end user is authenticated and has entered
    the user_code provided to them by the client application. redirect_uri is expected to be empty
    and if it is not, it is ignored.

    response_type generally governs whether authentication is an Implicit Flow or aHybrid Flow.
    Implicit allows for the client_id to specify either "id_token" or "id_token token", and Hybrid
    allows for the client_id to specify either "code id_token", "code token", or "code id_token token".
    Device Authentication Flow, is a Hybrid Flow.
    https://sazzer.github.io/blog/2016/09/03/OpenID-Connect-Response-Types/

    # TODO: Handling followup forms to capture post-credential-authentication requirements e.g. MFA code input

    Parameters
    ----------
    response_type:
        required str, Specifies the type of authorization flow
    response_mode:
        optional str, Specifies the type of token generated and method of response
    client_id:
        required, Credential to identify the client application
    client_secret:
        optional str, A client secret for additional client authentication
    scope:
        optional, If not input a default to "openid" is applied
    redirect_uri:
        optional str, Dependant on flow, a client provided uri to where the end user is directed to post authorization
    nonce:
        optional str, Highly recommended, a client provided code to verify the flow and mitigate against token replay
        attacks.
    username:
        required str, credentials to identify the end user
    user_secret:
        required str, authentication secret to aid in verifying the asserted user
    **kwargs:
        resource:
            optional str, permission resource identifier. when provided is added to the scope claims. This
            input provided as backwards compatibility and is superseded by the use of scope.
        state:
            optional str, client provided value included in the authentication request that must be returned
            with the token response.
        mfa:
            optional str, multi factor authentication code
        kmsi:
            optional bool, keep me signed in flag. # TODO: not currently implemented
        prompt:
            optional, Space separated string specifying user prompts for re-authentication and consent.
        user_code:
            optional, Where a user is required to enter a user code for device authorisation flow
        code_challenge_method:
            optional, "plain" (default) or "S256", the ype of code_challenge value provided
        code_challenge:
            optional, A high entropy random challenge generated by the client and provided to the end user,
            if sent, the code_verifier must be also sent this code on the token call. Required when client
            must do PKCE (RFC7636).
    """

    _ = client_secret, response_mode  # interface variables provided for future features

    if not validate_client_id(client_id):
        # This is a cursory validation at present and this condition will not fail unless
        # client_id is None or empty or client_secret is None.
        # Validation of client_id is always required, however client authentication is only
        # required in certain for certain actions and not at present required here.
        raise OpenidException(
            "client_auth_error", "Unable to validate the referring client application."
        )  # pragma: no cover

    response_type = validate_response_type(response_type)

    """ Currently only full credential (username + password) is supported, kmsi, mfa
        and other authentication mechanisms as not currently implemented. 
    """
    if username is None or username == "" or user_secret == "":
        raise OpenidException(
            "auth_processing_error", "A valid username and user_secret is required"
        )

    code_challenge_method: str = stringify(kwargs.get("code_challenge_method"))

    # For the device code flow, user_code and client_id are the critical inputs supported by
    # the end user credentials. Inputs like code_challenge_method can be retrieved by using the
    # client_id and user_code as a lookup against the original device code request.
    user_code: str = stringify(kwargs.get("user_code"))

    # required for PKCE, either a code_challenge or user_code is received
    code_challenge: str = stringify(kwargs.get("code_challenge"))

    # # TODO: Complete this validation
    # # Only perform these checks then code_challenge_method is empty and for this
    # # step in the end user device code flow
    # if code_challenge_method == "":
    #     if "code" in response_type and redirect_uri == "":
    #         raise OpenidException(
    #             "auth_processing_error", "A valid redirect_uri is required"
    #         )
    #     if nonce == "":
    #         raise OpenidException(
    #             "auth_processing_error", "A valid nonce value is required"
    #         )
    #     """

    scope = scope if scope else "openid"
    resource: str = stringify(kwargs.get("resource"))

    reply_parameters: Dict[str, Any]

    if code_challenge != "" and code_challenge_method != "":
        state: str = stringify(kwargs.get("state"))
        authorisation_code = ""  # TODO: do plain or s256 check
        return {
            "response_type": "code",
            "authorisation_code": authorisation_code,
            "redirect_uri": redirect_uri,
            "state": state,
        }

    if "code" in response_type:
        state: str = stringify(kwargs.get("state"))

        authorisation_code = openid_lib.authenticate_code(
            client_id=client_id,
            resource=resource,
            username=username,
            user_secret=user_secret,
            nonce=nonce,
            scope=scope,
            code_challenge_method=code_challenge_method,
            code_challenge=code_challenge,
            user_code=user_code,
        )
        return {
            "response_type": "code",
            "authorisation_code": authorisation_code,
            "redirect_uri": redirect_uri,
            "state": state,
        }

    else:  # if "token" in response_type:
        kmsi: str = stringify(kwargs.get("kmsi"))

        access_token = openid_lib.authenticate_token(
            client_id=client_id,
            resource=resource,
            username=username,
            user_secret=user_secret,
            nonce=nonce,
            scope=scope,
            kmsi=kmsi,
        )
        return {
            "response_type": "token",
            "access_token": access_token,
        }


def process_token_request(
    grant_type: str,
    client_id: str,
    client_secret: str,
    device_code: str,
    code: str,
    username: str,
    user_secret: str,
    nonce: str,
    scope: str,
    resource: str,
    redirect_uri: str,
    code_verifier: str,
) -> Dict[str, Any]:
    """Returns details of the requested token or other: pending | unsuccessful | error responses

    OpenidException is raised for validation and processing errors

    Issued token response:
        access_token: required
        refresh_token: optional
        expires_in: required
        scope: optional
        token_type: required, currently only Bearer supported

    Other responses:
        error: error_code
        error_description: human-readable error message

    Parameters
    ----------
    grant_type:
        required str, Must be authorization_code for the authorization code flow.
    client_id:
        required str, The Application (client) ID that the AD FS assigned to your app.
    client_secret:
        optional str, Required for web apps The application secret that you
        created during app registration in AD FS. You shouldn't use the
        application secret in a native app because client_secrets can't be
        reliably stored on devices. It's required for web apps and web
        APIs, which have the ability to store the client_secret securely on
        the server side. The client secret must be URL-encoded before being
        sent. These apps can also use a key based authentication by signing
        a JWT and adding that as client_assertion parameter.
    device_code:
        optional str, Required for "device_code" grant_type to identify token
    code:
        optional str, Required for "authorization_code" grant_type to identify token
    username:
        optional str, Required for "password" grant_type
    user_secret:
        optional str, Required for "password" grant_type
    nonce:
        optional str, Used with "password" grant_type
    scope:
       optional str, A space-separated list of scopes. if no value is provided, it is defaulted to openid
    resource:
        optional str, The url of your Web API.
        Note – If using MSAL client library, then resource parameter isn't sent. Instead, the resource url is sent
        as a part of the scope parameter: scope = [resource url]//[scope values e.g., openid]
        If resource isn't passed here or in scope, AD FS uses a default resource urn:microsoft:userinfo. userinfo
        resource policies such as MFA, Issuance or authorization policy, can't be customized.
    redirect_uri:
        required str, The same redirect_uri value that was used to acquire the authorization_code or device_code
    code_verifier:
        optional str, The same code_verifier that was used to obtain the authorization_code. Required if PKCE
        was used in the authorization code grant request. For more information, see the PKCE RFC. This option
        applies to AD FS 2019 and later.
    """

    _ = (
        client_secret,
        redirect_uri,
        code_verifier,
    )  # interface variables provided for future features

    grant_type = validate_grant_type(grant_type)

    response: Dict[str, Any] | None = None

    if grant_type == "device_code":
        response = openid_lib.get_access_token_from_authorisation_code(device_code)
        if response is None:
            user_code = openid_lib.device_user_codes.get(device_code)
            if user_code:
                # TODO: handle additional unsuccessful and error states, expired_token, authorization_declined etc.
                # TODO: openid_lib device_code cache cleanup
                device_request = openid_lib.device_code_requests.get(user_code)
                if device_request:
                    raise OpenidException(
                        "authorization_pending",
                        "End user authentication relating to the user_code provided has not been completed.",
                    )
                else:
                    # this condition has not been implemented as yet
                    raise OpenidException(
                        "authorization_declined",
                        "End user authentication relating to the user_code was not successful.",
                    )  # pragma: no cover
            else:
                # TODO: research standard error codes
                raise OpenidException(
                    "bad_verification_code", "device code is not recognised"
                )
        return response

    # TODO: handle grant_type for on-behalf-of flow
    # elif grant_type.endswith("jwt-bearer"):
    #     # For on-behalf-of flow
    #     client_id: str = request.form["client_id"]
    #     client_secret = request.form.get("client_secret", "")
    #
    #     # urn:ietf:params:oauth:client-assertion-type:jwt-bearer
    #     # client_secret is no required when client_assertion used
    #     client_assertion_type = request.form.get("client_assertion_type", "")
    #     client_assertion = request.form.get("client_assertion", "")
    #
    #     assertion = request.form["assertion"]
    #     requested_token_use = request.form["requested_token_use"]
    #     resource = request.form["resource"]  # second api resource uri
    #     scope = request.form["scope"]

    elif grant_type == "authorization_code":
        # check specifications for handling redirect_uri and compare with openid specs MS reference below:
        # https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/overview/ad-fs-openid-connect-oauth-flows-scenarios

        # TODO: check redirect_uri validation is required

        # TODO: check what todo with code_verifier:

        response = openid_lib.get_access_token_from_authorisation_code(code)

    elif grant_type == "password":
        _ = validate_client_id(client_id)

        response = openid_lib.authenticate_token(
            client_id=client_id,
            resource=resource,
            username=username,
            user_secret=user_secret,
            nonce=nonce,
            scope=scope,
        )

    if response is None:
        raise OpenidException(
            "bad_token_request", f"Unable to retrieve token for grant '{grant_type}'"
        )

    return response
