from typing import Dict, Any, List, Tuple

from openid_whisperer import openid_lib

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


class AuthenticationProcessError(Exception):
    ...


def valid_client_id(client_id: str, client_secret: str) -> bool:
    """ Returns True for a valid client_id and client_secret.
        True is currently always returned
    """
    if isinstance(client_id, str) and isinstance(client_secret, str):
        return True
    else:
        return False


def valid_response_type(response_type: str) -> bool:
    """Returns True if response_type input is valid and is supported, else False

    Parameters
    ----------
    response_type:
        required, assumed to be a lowercase string
    """
    response_type_list = [item.strip() for item in response_type.split(" ") if item != ""]
    response_type_list.sort()
    response_type_check = " ".join(response_type_list)
    if response_type_check in RESPONSE_TYPES_SUPPORTED:
        return True
    else:
        return False


def validate_response_mode(response_type: str, response_mode: str) -> Tuple[str, str | None]:
    """Returns returns a tuple of (adjusted_response_mode, error_message)
       where response_mode is an empty string, it is adjusted to the defaulted mode for the given response_type.
       error_message is None, for a valid response_mode, where there is an unsupported response_mode or
       invalid response_type/response_mode combination, detail of the error is returned.

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

    return response_mode, error_message


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
        code_challenge_method: str,
        code_challenge: str) -> Dict[str, Any]:
    """Returns a dictionary of values required to direct the end user through the required authentication flow

    Parameters
    ----------
    client_id: required
        The client identifier of an initiating application
    response_type: required
        Defines type of authorization flow. Must include "id_token" for end user sign-in.
        It may also include the response_type "token". Using token here allows your app
        to receive an access token immediately from the authorize endpoint without having
        to make a second request to the token endpoint.
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
    response_mode: optional
        Specifies the method that should be used to send the resulting token back
        to client_id. This value is defaulted to fragment.
        Possible values are query, fragment or form_post. The draft extension — JWT
        Secured Authorization Response Mode for OAuth 2.0 defines additional
        response modes, query.jwt, fragment.jwt, form_post.jwt or jwt.
    state: optional
        An optional value included in the authentication request that must be
        returned with the token response. It can be any string, usually a
        randomly generated unique value and is typically used for preventing
        cross-site request forgery attacks. The state is also used to encode
        information about the user's state in the client_id application before
        the authentication request occurred, such as the page or view they were on.
    rcode: optional
        The authorization_code that the client_id requested, it uses the
        authorization code to request an access token against the target
        resource. Authorization_codes are short-lived, typically expiring after
        about 10 minutes.
    state: optional
        If a state value is included in the request, the same value should appear
        in the response. The client_id should verify that the state values in the
        request and following response are identical.
    code_challenge_method: optional
        “plain” (default) or “S256”. Can be used if code_challenge is
        sent. Defaults to “plain”. Needs to be sent if S256 is used as
        code_challenge method.
    code_challenge: optional
        A high entropy random challenge. A challenge generated by the client,
        if sent, the code_verifier must be sent on the token call. *Required
        when client must do PKCE (RFC7636).
    """


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
    """Returns a dictionary of values requested as per the required authentication flow

    See initiate_end_user_authentication() for documentation on the required inputs

    Response_type governs whether authentication is Implicit Flow or Hybrid Flow. Implicit allows
    for the client_id to specify either "id_token" or "id_token token", and Hybrid allows for the
    client_id to specify either "code id_token", "code token", or "code id_token token".
    Device Authentication Flow, is a Hybrid Flow.
    https://sazzer.github.io/blog/2016/09/03/OpenID-Connect-Response-Types/

    Parameters
    ----------
    response_type:
    response_mode:
    client_id:
    client_secret:
    scope:
    redirect_uri:
    nonce:
    username:
    user_secret:
    **kwargs:
        resource:
        state:
        mfa:
        kmsi:
        prompt:
        code_challenge_method:
        code_challenge:
    """
    if not valid_client_id(client_id, client_secret):
        raise AuthenticationProcessError("Unable to validate the referring client application.")

    if not valid_response_type(response_type):
        raise AuthenticationProcessError(f"Invalid response_type '{response_type}'. A call to "
                                         "/.well-known/openid-configuration will "
                                         "provide information on supported response types")

    response_mode, error_message = validate_response_mode(response_type, response_mode)
    if error_message:
        raise AuthenticationProcessError(error_message)

    if not isinstance(username, str) or username == "" or\
       not isinstance(user_secret, str) or user_secret == "":
        raise AuthenticationProcessError("A valid username and user_secret is required")

    resource: str | None = kwargs.get("resource")
    code_challenge: str | None = kwargs.get("code_challenge")
    # TODO: Review device flow and determine correct code challenge validation
    # if "code" in response_type and (not isinstance(code_challenge, str) or code_challenge == ""):
    #     raise AuthenticationProcessError("A valid code_challenge is required for the device code flow")
    if "code" in response_type and (not isinstance(redirect_uri, str) or redirect_uri == ""):
        raise AuthenticationProcessError("A valid redirect_uri is required")

    reply_parameters: Dict[str, Any]

    # Check for Hybrid Flow, raise an exception if the code_challenge has not been set
    if "code" in response_type:

        if not isinstance(nonce, str) or nonce == "":
            raise AuthenticationProcessError("A valid nonce value is required")

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
