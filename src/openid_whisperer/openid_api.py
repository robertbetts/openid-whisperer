import logging
from typing import Dict, Any, List

from openid_whisperer import openid_lib

logger = logging.getLogger(__name__)

RESPONSE_TYPES_SUPPORTED: List[str] = [
    "code",
    "id_token",
    "code id_token",
    "id_token token",
    "code token",
    "code id_token token"
]

RESPONSE_MODES_SUPPORTED: List[str] = [
    "fragment", "query", "form_post"
]

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
    "device_code"
]


class OpenidException(Exception):
    def __init__(self, error_code: str, error_description: str):
        Exception.__init__(self, f"{error_code}: {error_description}")
        self.error_code: str = error_code
        self.error_description: str = error_description

    def to_dict(self) -> Dict[str, str]:
        return {
            "error": self.error_code,
            "error_code": self.error_code,
            "error_description": self.error_description
        }


def validate_client_id(client_id: str, client_secret: str) -> str:
    """ Returns client_id if successfully validating client_id and client_secret, else
        raises an OpenidException when unsuccessful
    """
    if isinstance(client_id, str) and isinstance(client_secret, str):
        return client_id
    else:
        raise OpenidException("client_auth_error", "Unable to validate the referring client application.")


def validate_response_type(response_type: str) -> str:
    """Returns response_type if response_type input is valid and is supported, else Raises an OpenidException

    Parameters
    ----------
    response_type:
        required, assumed to be a lowercase string
    """
    response_type_list = [item.strip() for item in response_type.split(" ") if item != ""]
    response_type_list.sort()
    response_type_check = " ".join(response_type_list)
    if response_type_check not in RESPONSE_TYPES_SUPPORTED:
        raise OpenidException(
            "auth_processing_error",
            f"Invalid response_type '{response_type}'. A call to /.well-known/openid-configuration will "
            "provide information on supported response types"
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
            error_message = f"Invalid response_mode of {response_mode} for request_type "\
                            f"{response_type}. response_mode 'query' expected."
    elif "token" in response_type and response_mode not in ("fragment", "form_post"):
        if response_mode == "":
            response_mode = "fragment"
        else:
            error_message = f"Invalid response_mode of {response_mode} for request_type "\
                            f"{response_type}. response_mode 'fragment' expected."
    # General response_mode validity check
    if response_mode not in RESPONSE_MODES_SUPPORTED:
        error_message = f"Unsupported response_mode of {response_mode}."

    if error_message:
        raise OpenidException("auth_processing_error", error_message)

    return response_mode


def validate_grant_type(grant_type: str) -> str:
    """ Returns a tuple of (adjusted_grant_type, error_message)
    Where the input grant_typ is in the forman of an urn e.g."urn:ietf:params:oauth:grant-type:jwt-bearer",
    grant type is updated to only the grant_type reference.

    OpenidException is raised for validation and processing errors

    Parameters
    ----------
    grant_type:
        required str
    """
    error_message: str | None = None
    if not isinstance(grant_type, str) or grant_type == "":
        error_message = "An empty input for grant_type is not supported"
    elif grant_type not in GRANT_TYPES_SUPPORTED:
        error_message = f"An grant_type of '{grant_type}' is not supported"
    elif grant_type.startswith("urn:ietf:params:oauth:grant-type:"):
        grant_type = grant_type.split(":")[-1].strip()

    if grant_type not in ("device_code", "authorization_code", "password"):
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
        code_challenge_method: str) -> Dict[str, Any]:
    """Returns a dictionary of values required to direct the end user through the required authentication flow

    OpenidException is raised for validation and processing errors

    # TODO: Using prompt to direct additional form based flow requirements
    # TODO: Functionality is not as yet provided to check for existing authenticated session's based on incoming
            device / browser hitting the authorize endpoint.
    # TODO: It is undecided whether browser / device challenge-response authorisation for token generation
            falls inside the scope of this project
    # TODO: It is the intention to support kerberos identity tokens

    POST only inputs:
    kmsi: optional
        Keep me signed in (yes/no)
    mfa: optional
        multi factor authentication code
    code_challenge: optional
        A high entropy random challenge. A challenge generated by the client,
        if sent, the code_verifier must be sent on the token call. *Required
        when client must do PKCE (RFC7636).
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
        “plain” (default) or “S256”. Can be used if code_challenge is
        sent. Defaults to “plain”. Needs to be sent if S256 is used as
        code_challenge method.
    """

    response_type = validate_response_type(response_type)
    response_mode = validate_response_mode(response_type, response_mode)
    if not isinstance(client_id, str) or client_id == "":
        raise OpenidException("auth_processing_error", "A valid client_id is required")

    if not isinstance(scope, str) or scope == "":
        raise OpenidException("auth_processing_error", "A valid scope is required")

    action: str = f"?scope={scope}&response_type={response_type}&response_mode={response_mode}&client_id={client_id}" \
                  f"&resource={resource}&redirect_uri={redirect_uri}&nonce={nonce}&state={state}&prompt={prompt}" \
                  f"&code_challenge_method={code_challenge_method}"

    response: dict[str, Any] = {
        "action": action,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_mode": response_mode,
        "response_type": response_type,
        "prompt": prompt,
        "code_challenge_method": code_challenge_method,
    }
    return response



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
        code_verifier: str) -> Dict[str, Any]:
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
    _ = validate_client_id(client_id, client_secret)

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
                        "End user authentication relating to the user_code provided has not been completed."
                    )
                else:
                    raise OpenidException(
                        "authorization_declined",
                        "End user authentication relating to the user_code was not successful."
                    )
            else:
                # TODO: research standard error codes
                raise OpenidException(
                    "bad_verification_code",
                    "device code is not recognised"
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

        # if not isinstance(redirect_uri, str) or redirect_uri == "":
        #     raise OpenidException("auth_processing_error", "A valid redirect_uri is required")

        # if not isinstance(code_verifier, str) or code_verifier == "":
        #     raise OpenidException("auth_processing_error", "A valid code_verifier is required")

        response = openid_lib.get_access_token_from_authorisation_code(code)

    elif grant_type == "password":

        response = openid_lib.authenticate_token(
            client_id=client_id,
            resource=resource,
            username=username,
            user_secret=user_secret,
            nonce=nonce,
            scope=scope
        )

    if response is None:
        raise OpenidException("bad_token_request", f"Unable to retrieve token for grant '{grant_type}'")

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
        **kwargs) -> Dict[str, Any]:
    """Returns a dictionary of values required for a flow's next step after performing the required
    authentication flow step processing.

    OpenidException is raised for validation and processing errors

    See initiate_end_user_authentication() for documentation on the required inputs

    Response_type governs whether authentication is Implicit Flow or Hybrid Flow. Implicit allows
    for the client_id to specify either "id_token" or "id_token token", and Hybrid allows for the
    client_id to specify either "code id_token", "code token", or "code id_token token".
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
            optional str, permissioned resource identifier. when provided is added to the scope claims. This
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
        code_challenge_method:
            optional, "plain" (default) or "S256", the ype of code_challenge value provided
        code_challenge:
            optional, A high entropy random challenge generated by the client and provided to the end user,
            if sent, the code_verifier must be also sent this code on the token call. Required when client
            must do PKCE (RFC7636).
    """
    if not validate_client_id(client_id, client_secret):
        raise OpenidException("client_auth_error", "Unable to validate the referring client application.")

    response_type = validate_response_type(response_type)
    response_mode = validate_response_mode(response_type, response_mode)

    if not isinstance(username, str) or username == "" or\
       not isinstance(user_secret, str) or user_secret == "":
        raise OpenidException("auth_processing_error", "A valid username and user_secret is required")

    if scope is None or scope == "":
        scope = "openid"

    resource: str | None = kwargs.get("resource")
    code_challenge: str | None = kwargs.get("code_challenge")
    # TODO: Review device flow and determine correct code challenge validation
    # if "code" in response_type and (not isinstance(code_challenge, str) or code_challenge == ""):
    #     raise AuthenticationProcessError("A valid code_challenge is required for the device code flow")
    if "code" in response_type and (not isinstance(redirect_uri, str) or redirect_uri == ""):
        raise OpenidException("auth_processing_error", "A valid redirect_uri is required")

    reply_parameters: Dict[str, Any]

    # Check for Hybrid Flow, raise an exception if the code_challenge has not been set
    if "code" in response_type:

        if not isinstance(nonce, str) or nonce == "":
            raise OpenidException("auth_processing_error", "A valid nonce value is required")

        state: str | None = kwargs.get("state")

        authorisation_code = openid_lib.authenticate_code(
            client_id=client_id,
            resource=resource,
            username=username,
            user_secret=user_secret,
            nonce=nonce,
            scope=scope,
            code_challenge=code_challenge,
        )
        reply_parameters = {
            "response_type": "code",
            "authorisation_code": authorisation_code,
            "redirect_uri": redirect_uri,
            "state": state,
        }

    else:  # then "token" is in response_type:

        kmsi: str | None = kwargs.get("kmsi")

        access_token = openid_lib.authenticate_token(
            client_id=client_id,
            resource=resource,
            username=username,
            user_secret=user_secret,
            nonce=nonce,
            scope=scope,
            kmsi=kmsi
        )
        reply_parameters = {
            "response_type": "token",
            "access_token": access_token,
        }

    return reply_parameters
