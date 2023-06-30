""" Flask Blueprint with OpenID compatible endpoints
"""
import logging
import json
from flask import Blueprint, request, make_response, render_template, redirect, abort, jsonify
from flask.typing import ResponseReturnValue

from openid_whisperer import openid_lib, openid_api
from openid_whisperer.config import IDP_BASE_URL
from openid_whisperer.openid_api import OpenidException, process_token_request

logger = logging.getLogger(__name__)
openid_prefix: str = "/adfs"
openid_blueprint: Blueprint = Blueprint('openid', __name__,
                                        url_prefix=openid_prefix,
                                        template_folder='templates',
                                        static_folder='static')


@openid_blueprint.route("/oauth2/authorize", methods=["GET"])  # type: ignore[misc]
def authorize_get() -> ResponseReturnValue:
    """ Handles get requests to the authorization endpoint, this would typically
        be to initiate human interaction required for a particular authorization
        flow.
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
    code_challenge_method: str = request.args.get("code_challenge_method", "")

    try:
        template_parameters = openid_api.initiate_end_user_authentication(
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
        )
        authorize_get_resp = make_response(render_template("login.html", **template_parameters))
        return authorize_get_resp
    except OpenidException as e:
        abort(403, str(e))


@openid_blueprint.route("/oauth2/authorize", methods=["POST"])  # type: ignore[misc]
def authorize_post() -> ResponseReturnValue:
    """ Handles an authorization POST request and returns an authorization response

        Where an error arises relating to the processing this request, error_code and error_description are
        appended to the response.
    """
    response_type: str = request.args.get("response_type", "")
    response_mode: str = request.args.get("response_mode", "")
    client_id: str = request.args.get("resource", "")
    client_secret: str = request.args.get("client_secret", "")
    scope: str = request.args.get("scope", "")

    resource: str = request.args.get("resource", "")
    redirect_uri: str = request.args.get("redirect_uri", "")
    nonce: str = request.args.get("nonce", "")
    state: str = request.args.get("state", "")
    prompt: str = request.args.get("prompt", "")

    grant_type: str = request.form.get("grant_type")  # password
    username = request.form.get("UserName")
    user_secret = request.form.get("Password")
    mfa = request.form.get("Mfa", "")
    kmsi = request.form.get("Kmsi", "")
    code_challenge_method: str = request.form.get("code_challenge_method", "")
    code_challenge: str = request.form.get("CodeChallenge", "")

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
            code_challenge_method=code_challenge_method,
            code_challenge=code_challenge
        )
    except OpenidException as e:
        openid_response = e.to_dict()

    if "code" in response_type:

        query_start = "&" if "?" in redirect_uri else "?"

        if "error_code" in openid_response:
            error_code = openid_response['error_code']
            error_description = openid_response.get('error_description')
            redirect_uri = f"{redirect_uri}{query_start}error_code={error_code}&error_description={error_description}"
        else:
            authorisation_code = openid_response["authorisation_code"]
            redirect_uri = f"{redirect_uri}{query_start}code={authorisation_code}&state={state}"

        # TODO: Research handling cases where redirect should be replaced by a form_post
        return redirect(redirect_uri, code=302)

    elif "token" in response_type:
        if "error_code" in openid_response:
            error_code = openid_response['error_code']
            error_description = openid_response.get('error_description')
            response = {
                "error_code": error_code,
                "error_description": error_description
            }
        else:
            response = openid_response["access_token"]
        return json.dumps(response)

    elif "error_code" in openid_response:
        # TODO: see about when to abort or to rather redirect and include error details
        error_code = openid_response['error_code']
        error_description = openid_response.get('error_description')
        abort(403, f"{error_code}: {error_description}")

    else:  # catch all line, because of response_type validation this line will never evaluate
        # TODO: see about when to abort or to rather redirect and include error details
        abort(403, f"InvalidResponseType: response_type value of '{response_type}' is not supported. "
                   f"A call to /.well-known/openid-configuration will provide information on "
                   f"supported response types")  # pragma: no cover


@openid_blueprint.route("/oauth2/token", methods=["POST"])  # type: ignore[misc]
def token() -> ResponseReturnValue:
    """ Returns:
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

    try:
        response = process_token_request(
            grant_type=grant_type,
            client_id=client_id,
            client_secret=client_secret,
            device_code=device_code,
            code=code,
            username=username,
            user_secret=user_secret,
            nonce=nonce,
            scope=scope,
            resource=resource,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier)
        status_code = 200
    except OpenidException as e:
        response = e.to_dict()
        status_code = 403
    # except Exception as e:
    #     logger.exception(e)
    #     response = {
    #         "error": "service_error",
    #         "error_status": "service_error",
    #         "error_description": str(e),
    #     }
    #     status_code = 500

    return jsonify(response), status_code


@openid_blueprint.route("/oauth2/userinfo", methods=["POST"])  # type: ignore[misc]
def userinfo() -> ResponseReturnValue:
    """ Returns claims about the authenticated user
    """
    return ""


@openid_blueprint.route("/oauth2/devicecode", methods=["POST"])  # type: ignore[misc]
def devicecode() -> ResponseReturnValue:
    """Returns a response including a device code, uri for end user verification and user code for
       the end user to enter.

        Device Code Flow:
        1. The user visits the URL
        2. The Token Service redirects to the Authentication Service for user authentication (SSO may occur)
        3. Once Authentication is done the Authentication Service redirects back to the Token Service
        4. The user is presented with a consent and once approved the user flow is complete. User can close browser.

        response = {
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
        client_secret = request.form.get("client_secret")
        scope = request.form["scope"]
        resource = request.form.get("resource", "")
        response = openid_lib.devicecode_request(IDP_BASE_URL, openid_prefix, client_id, scope, resource)
        status_code = 200
    except KeyError as e:
        response = {
            "error": "bad_devicecode_request",
            "error_description": str(e)
        }
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
    """ Returns the public keys used to sign tokens
    """
    return jsonify(openid_lib.get_keys()), 200


@openid_blueprint.route("/.well-known/openid-configuration", methods=["GET"])  # type: ignore[misc]
def openid_configuration() -> ResponseReturnValue:
    """ returns OpenID Connect metadata
    """
    return jsonify(openid_lib.get_openid_configuration(IDP_BASE_URL, openid_prefix)), 200
