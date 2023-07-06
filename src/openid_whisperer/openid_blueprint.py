""" Flask Blueprint with OpenID compatible endpoints
"""
import logging
import json
from flask import (
    Blueprint,
    request,
    make_response,
    render_template,
    redirect,
    abort,
    jsonify,
)
from flask.typing import ResponseReturnValue

from openid_whisperer.config import get_cached_config
from openid_whisperer import openid_lib, openid_api
from openid_whisperer.openid_api import process_token_request, AuthTemplateInput
from openid_whisperer.openid_lib import OpenidException

config = get_cached_config()
logger = logging.getLogger(__name__)
openid_blueprint: Blueprint = Blueprint(
    "openid",
    __name__,
    url_prefix=config.id_service_prefix,
    template_folder="templates",
    static_folder="static",
)


@openid_blueprint.route("/oauth2/authorize", methods=["GET"])  # type: ignore[misc]
def authorize_get() -> ResponseReturnValue:
    """Handles get requests to the authorization endpoint, this would typically
    be to initiate human interaction required for a particular authorization
    flow.

    # TODO: Handle interactive flow, query example:
    GET /adfs/oauth2/authorize?
        client_id=PC-90274-SID-12655-DEV
        &response_type=code
        &redirect_uri=http://localhost:63385
        &scope=URI:API:RS-104134-21171-mock-api-PROD+offline_access+openid+profile
        &state=cezPxSQJLvjHrFob
        &code_challenge=b_tTwfMnShCYxxaZSuEE3CdO2uDHvHvdcvUC6wBj624
        &code_challenge_method=S256
        &nonce=9d431d44112f0cbca609f9b3bb5b7c0f9a8e241a91006c883a1af4abc4b19e36
        &client_info=1
        &login_hint=your_username@your_tenant.com
        &X-AnchorMailbox=UPN:your_username@your_tenant.com
    HTTP/1.1
    """

    # Mandatory query string arguments
    response_type: str = request.args.get("response_type", "")
    client_id: str = request.args.get("client_id", "")
    scope: str = request.args.get("scope", "")

    # Optional query string arguments
    response_mode: str = request.args.get("response_mode", "")
    resource: str = request.args.get("resource", "")
    redirect_uri: str = request.args.get("redirect_uri", "")
    nonce: str = request.args.get("nonce", "")
    state: str = request.args.get("state", "")
    prompt: str = request.args.get("prompt", "")

    # If a value for code_challenge_method is present, then assumed that this request
    # forms part of a device code authorisation flow.
    code_challenge_method: str = request.args.get("code_challenge_method", "")
    # ths a value for the code_challenge is present, this is a PKCE
    code_challenge: str = request.args.get("code_challenge", "")

    """
    # Query parameters supplied my MSAL for Azure interactive flow
    login_hint: str = request.args.get("prompt", "")
    client_info: str = request.args.get("client_info", "")
    code_challenge: str = request.args.get("code_challenge", "")
    """

    try:
        template_parameters: AuthTemplateInput = (
            openid_api.initiate_end_user_authentication(
                response_type=response_type,
                client_id=client_id,
                scope=scope,
                resource=resource,
                response_mode=response_mode,
                redirect_uri=redirect_uri,
                state=state,
                nonce=nonce,
                prompt=prompt,
                rcode=resource,
                code_challenge_method=code_challenge_method,
                code_challenge=code_challenge,
            )
        )
        authorize_get_resp = make_response(
            render_template("authenticate.html", **template_parameters)
        )
        return authorize_get_resp
    except OpenidException as e:
        abort(403, str(e))


@openid_blueprint.route("/oauth2/authorize", methods=["POST"])  # type: ignore[misc]
def authorize_post() -> ResponseReturnValue:
    """Handles an authorization POST request and returns an authorization response

    Where an error arises relating to the processing this request, error_code and error_description are
    appended to the response.
    """
    response_type: str = request.form.get("response_type", "")
    response_mode: str = request.form.get("response_mode", "")
    client_id: str = request.form.get("client_id")
    client_secret: str = request.form.get("client_secret", "")

    scope: str = request.form.get("scope")
    resource: str = request.form.get("resource")

    redirect_uri: str = request.form.get("redirect_uri", "")

    nonce: str = request.form.get("nonce", "")
    state: str = request.form.get("state", "")
    prompt: str = request.form.get("prompt", "")
    username = request.form.get("UserName")
    user_secret = request.form.get("Password")
    user_code = request.form.get("CodeChallenge")
    mfa = request.form.get("Mfa")
    kmsi = request.form.get("Kmsi")
    code_challenge_method: str = request.form.get("code_challenge_method", "")
    code_challenge: str = request.form.get("code_challenge", "")

    try:
        openid_response = openid_api.process_end_user_authentication(
            response_type=response_type,
            response_mode=response_mode,
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
            redirect_uri=redirect_uri,
            nonce=nonce,
            username=username,
            user_secret=user_secret,
            resource=resource,
            state=state,
            mfa=mfa,
            kmsi=kmsi,
            prompt=prompt,
            user_code=user_code,
            code_challenge_method=code_challenge_method,
            code_challenge=code_challenge,
        )
    except OpenidException as e:
        openid_response = e.to_dict()

    if code_challenge_method != "" and redirect_uri == "":
        if "error_code" in openid_response:
            termination_reply = openid_response["error_description"]
            status_code = 403
        else:
            termination_reply = (
                "Success, you have validated the user code provided to you."
            )
            status_code = 200

        template_parameters = {
            "termination_reply": termination_reply,
            "action": "",
            "client_id": "",
            "redirect_uri": "",
            "response_mode": "",
            "response_type": "",
            "prompt": "",
            "requires_mfa": "",
            "allows_kmsi": "",
            "code_challenge_method": "",
            "requires_user_code": "",
            "submit_label": "",
        }
        authorize_get_resp = make_response(
            render_template("authenticate.html", **template_parameters)
        )
        return authorize_get_resp, status_code

    if "code" in response_type:
        query_start = "&" if "?" in redirect_uri else "?"

        if "error_code" in openid_response:
            error_code = openid_response["error_code"]
            error_description = openid_response.get("error_description")
            redirect_uri = f"{redirect_uri}{query_start}error_code={error_code}&error_description={error_description}"
        else:
            authorisation_code = openid_response["authorisation_code"]
            redirect_uri = (
                f"{redirect_uri}{query_start}code={authorisation_code}&state={state}"
            )
            logging.debug("redirect_uri: %s", redirect_uri)

        # TODO: Research handling cases where redirect should be replaced by a form_post
        return redirect(redirect_uri, code=302)

    elif "token" in response_type:
        if "error_code" in openid_response:
            error_code = openid_response["error_code"]
            error_description = openid_response.get("error_description")
            response = {
                "error_code": error_code,
                "error_description": error_description,
            }
            status_code = 403
        else:
            response = openid_response["access_token"]
            status_code = 200
        return json.dumps(response), status_code

    elif "error_code" in openid_response:
        # TODO: see about when to abort or to rather redirect and include error details
        error_code = openid_response["error_code"]
        error_description = openid_response.get("error_description")
        abort(403, f"{error_code}: {error_description}")

    else:  # catch all line, because of response_type validation this line will never evaluate
        # TODO: see about when to abort or to rather redirect and include error details
        abort(
            403,
            f"InvalidResponseType: response_type value of '{response_type}' is not supported. "
            f"A call to /.well-known/openid-configuration will provide information on "
            f"supported response types",
        )  # pragma: no cover


@openid_blueprint.route("/oauth2/token", methods=["POST"])  # type: ignore[misc]
def token() -> ResponseReturnValue:
    """Returns:
    * (200) issued token json
    * (400) pending token json
    * (403) invalid token request json
    """
    grant_type: str = request.form.get("grant_type", "")
    device_code: str = request.form.get("device_code", "")
    client_id: str = request.form.get("client_id", "")
    client_secret: str = request.form.get("client_secret", "")

    # check specifications for handling redirect_uri and compare with openid specs MS reference below:
    # https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/overview/ad-fs-openid-connect-oauth-flows-scenarios
    redirect_uri: str = request.args.get("redirect_uri", "")

    code: str = request.form.get("code", "")
    code_verifier: str = request.form.get("code_verifier", "")

    username: str = request.form.get("username", "")
    user_secret: str = request.form.get("password", "")
    nonce: str = request.form.get("nonce", "")
    scope: str = request.form.get("scope", "")
    resource: str = request.form.get("resource", "")

    process_token_request_inputs = {
        "grant_type": grant_type,
        "client_id": client_id,
        "client_secret": client_secret,
        "device_code": device_code,
        "code": code,
        "username": username,
        "user_secret": user_secret,
        "nonce": nonce,
        "scope": scope,
        "resource": resource,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }

    try:
        response = process_token_request(**process_token_request_inputs)
        status_code = 200
    except OpenidException as e:
        response = e.to_dict()
        logging.debug(process_token_request_inputs)
        logging.debug(response)
        status_code = 403

    return jsonify(response), status_code


@openid_blueprint.route("/oauth2/userinfo", methods=["POST"])  # type: ignore[misc]
def userinfo() -> ResponseReturnValue:
    """Returns claims about the authenticated user"""
    return ""


@openid_blueprint.route("/oauth2/devicecode", methods=["POST"])  # type: ignore[misc]
def devicecode() -> ResponseReturnValue:
    """Returns a response including a device code, uri for end user verification and user code for
    the end user to enter.

     Device Code Flow:
     1. An end user visits the client app
     2. Client app makes a device code request to the identity provider
     3. The identity provider returns information for the app to pass on to the end user, to independently
        complete authentication and enter a user_code.
     4. The client app then polls the identity provider for notification as to the end users independent actions
     5. While the client is polling, the end user follows the verification_uri, goes through authentication
        and enters the user code supplied to them. The identity provider informs the end user if successful or not.
     6. Once the end user has followed the verification url or the time limited input period expired, the
        client application will receive a status updated from the identity provider and the act according its owb flow.

     this_response_example = {
         "device_code": device_code,
         "user_code": user_code,
         "verification_uri":  quote(auth_link),
         "expires_in": int(expires_in_seconds),
         "interval": 5,  # The polling interval the client should respect when waiting for user approval
         "message": f"Enter the following code: {user_code} at this link, {auth_link}"
     }
    """
    try:
        client_id = request.form["client_id"]
        """ this is a reminder
        client_secret = request.form.get("client_secret")
        """
        scope = request.form["scope"]
        resource = request.form.get("resource", "")
        # TODO: Check that the verification_uri returned in the response, is accessible to the the end user
        response = openid_lib.devicecode_request(
            config.id_provider_base_url_external,
            config.id_service_prefix,
            client_id,
            scope,
            resource,
        )
        status_code = 200
    except KeyError as e:
        response = {"error": "bad_devicecode_request", "error_description": str(e)}
        status_code = 403
    return jsonify(response), status_code


@openid_blueprint.route("/oauth2/v2.0/logout", methods=["GET", "POST"])  # type: ignore[misc]
@openid_blueprint.route("/oauth2/logout", methods=["GET", "POST"])  # type: ignore[misc]
def logout() -> ResponseReturnValue:
    """logs out the end user, the client is also responsible for clearing out
    any cached authenticated session info held. The end uer is then redirected to the
    given post_logout_redirect_uri
    """
    post_logout_redirect_uri = request.args["post_logout_redirect_uri"]
    return redirect(post_logout_redirect_uri, code=302)


@openid_blueprint.route("/discovery/keys", methods=["GET"])  # type: ignore[misc]
def keys() -> ResponseReturnValue:
    """Returns the public keys used to sign tokens"""
    return jsonify(openid_lib.get_keys()), 200


@openid_blueprint.route("/.well-known/openid-configuration", methods=["GET"])  # type: ignore[misc]
def openid_configuration() -> ResponseReturnValue:
    """returns OpenID Connect metadata"""
    # TODO: look at better way of determining this url, depending on the network location of
    #  the client_id and end user. i.e. if the endpoint is is accessible from different networks
    #  then there will have to be valid certificates in place for host ip of the listening
    #  endpoint and the url extracted from this send the usd user ot client app to the correct
    #  destination.
    id_provider_base_url = config.id_provider_base_url_external
    return (
        jsonify(
            openid_lib.get_openid_configuration(
                id_provider_base_url, config.id_service_prefix
            )
        ),
        200,
    )
