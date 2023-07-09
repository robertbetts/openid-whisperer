""" Flask Blueprint with OpenID compatible endpoints
"""
import logging
import json
from typing import Dict, Any
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
from openid_whisperer import openid_lib
from openid_whisperer.openid_api import AuthTemplateInput
from openid_whisperer.openid_interface import (
    OpenidApiInterface,
    OpenidApiInterfaceException,
)
from openid_whisperer.openid_types import GeneralPackageExceptionTypes
from openid_whisperer.utils.credential_store_utils import UserCredentialStoreException
from openid_whisperer.utils.token_store_utils import TokenIssuerCertificateStoreException

config = get_cached_config()
logger = logging.getLogger(__name__)

openid_api_interface = OpenidApiInterface()

openid_blueprint: Blueprint = Blueprint(
    "openid",
    __name__,
    url_prefix=config.id_service_prefix,
    template_folder="templates",
    static_folder="static",
)


def return_redirect(redirect_uri: str, data: Dict[str, Any]) -> ResponseReturnValue:
    if len(data) > 0:
        query_start: str = "&" if "?" in redirect_uri else "?"
        for key, value in data.items():
            redirect_uri += f"{query_start}{key}={value}"
            query_start = "&"
    return redirect_uri


@openid_blueprint.route("/oauth2/authorize", methods=["GET"])  # type: ignore[misc]
def authorize_get() -> ResponseReturnValue:
    """Handles get requests to the authorization endpoint"""

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
    """
    status_code: int = 200
    try:
        template_parameters: AuthTemplateInput = openid_api_interface.get_authorize(
            tenant=openid_blueprint.url_prefix,
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
        authorize_get_resp = make_response(
            render_template("authenticate.html", **template_parameters)
        )
        return authorize_get_resp, status_code

    except (TokenIssuerCertificateStoreException, OpenidApiInterfaceException, UserCredentialStoreException) as e:
        abort(403, str(e))

    except Exception as e:
        logging.exception(e)
        error = f"server_error: Error {request.method} {request.url} {e}"
        abort(500, error)


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
    password = request.form.get("Password")
    user_code = request.form.get("CodeChallenge")
    mfa_code = request.form.get("Mfa")
    kmsi = request.form.get("Kmsi")
    code_challenge_method: str = request.form.get("code_challenge_method", "")
    code_challenge: str = request.form.get("code_challenge", "")

    if "code" not in response_type and "token" not in response_type:
        abort(
            403,
            f"InvalidResponseType: response_type value of '{response_type}' is not supported. "
            f"A call to /.well-known/openid-configuration will provide information on "
            f"supported response types",
        )

    status_code: int = 200
    try:
        openid_response = openid_api_interface.post_authorize(
            tenant=openid_blueprint.url_prefix,
            response_type=response_type,
            response_mode=response_mode,
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
            redirect_uri=redirect_uri,
            nonce=nonce,
            username=username,
            password=password,
            resource=resource,
            state=state,
            mfa_code=mfa_code,
            kmsi=kmsi,
            prompt=prompt,
            user_code=user_code,
            code_challenge_method=code_challenge_method,
            code_challenge=code_challenge,
        )
    except (TokenIssuerCertificateStoreException, OpenidApiInterfaceException, UserCredentialStoreException) as e:
        openid_response = e.to_dict()
        status_code = 403

    except Exception as e:
        logging.exception(e)
        openid_response = {
            "error_code": "server_error",
            "error_description": f"Error {request.method} {request.url} {e}"
        }
        status_code = 500

    if code_challenge_method != "" and redirect_uri == "":
        if "error_code" in openid_response:
            termination_reply = openid_response["error_description"]
        else:
            termination_reply = (
                "Success, you have validated the user code provided to you."
            )

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
        # TODO: Handling cases where redirect should be replaced by a form_post
        if "error_code" not in openid_response:
            code_response = {
                "code": openid_response["authorization_code"],
                "state": state,
            }
        else:
            code_response = openid_response
        redirect_uri = return_redirect(redirect_uri, code_response)
        return redirect(redirect_uri, code=302)

    elif "token" in response_type:
        if "error_code" in openid_response:
            response = openid_response
        else:
            response = openid_response["access_token"]
        return json.dumps(response), status_code

    else:  # "error_code" in openid_response:
        error_code = openid_response["error_code"]
        error_description = openid_response.get("error_description")
        abort(403, f"{error_code}: {error_description}")


@openid_blueprint.route("/oauth2/token", methods=["POST"])  # type: ignore[misc]
def token() -> ResponseReturnValue:
    """Returns:
    * (200) issued token json
    * (400) pending token json
    * (403) invalid token request json
    """
    grant_type: str = request.form.get("grant_type", "")
    device_code: str = request.form.get("device_code", "")
    access_token: str = request.form.get("access_token", "")
    refresh_token: str = request.form.get("refresh_token", "")
    token_type: str = request.form.get("token_type", "")
    expires_in: int | str = request.form.get("token_type", "")
    client_id: str = request.form.get("client_id", "")
    client_secret: str = request.form.get("client_secret", "")

    # check specifications for handling redirect_uri and compare with openid specs MS reference below:
    # https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/overview/ad-fs-openid-connect-oauth-flows-scenarios
    redirect_uri: str = request.args.get("redirect_uri", "")

    code: str = request.form.get("code", "")
    code_verifier: str = request.form.get("code_verifier", "")

    username: str = request.form.get("username", "")
    password: str = request.form.get("password", "")
    nonce: str = request.form.get("nonce", "")
    scope: str = request.form.get("scope", "")
    resource: str = request.form.get("resource", "")

    process_token_request_inputs = {
        "tenant": openid_blueprint.url_prefix,
        "grant_type": grant_type,
        "client_id": client_id,
        "refresh_token": refresh_token,
        "token_type": token_type,
        "expires_in": expires_in,
        "access_token": access_token,
        "client_secret": client_secret,
        "device_code": device_code,
        "code": code,
        "username": username,
        "password": password,
        "nonce": nonce,
        "scope": scope,
        "resource": resource,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }

    try:
        response = openid_api_interface.get_token(**process_token_request_inputs)
        status_code = 200
    except (TokenIssuerCertificateStoreException, OpenidApiInterfaceException, UserCredentialStoreException) as e:
        response = e.to_dict()
        status_code = 403
    except Exception as e:
        logging.exception(e)
        response = {
            "error_code": "server_error",
            "error_description": f"Error {request.method} {request.url} {e}"
        }
        status_code = 500

    return jsonify(response), status_code


@openid_blueprint.route("/oauth2/userinfo", methods=["POST"])  # type: ignore[misc]
def userinfo() -> ResponseReturnValue:
    """Returns claims about the authenticated user"""
    status_code = 200
    try:
        response = {}
    except (TokenIssuerCertificateStoreException, OpenidApiInterfaceException, UserCredentialStoreException) as e:
        response = e.to_dict()
        status_code = 403
    except Exception as e:
        logging.exception(e)
        response = {
            "error_code": "server_error",
            "error_description": f"Error {request.method} {request.url} {e}"
        }
        status_code = 500

    return jsonify(response), status_code


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
        tenant = "adfs"
        client_id = request.form.get("client_id", "")
        client_secret = request.form.get("client_secret", "")
        scope = request.form.get("scope", "")
        resource = request.form.get("resource", "")
        response = openid_api_interface.get_devicecode_request(
            tenant=tenant,
            base_url=config.id_provider_base_url_external,
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
            resource=resource,
        )
        status_code = 200

    except (TokenIssuerCertificateStoreException, OpenidApiInterfaceException, UserCredentialStoreException) as e:
        response = e.to_dict()
        status_code = 403

    except Exception as e:
        logging.exception(e)
        response = {
            "error_code": "server_error",
            "error_description": f"Error {request.method} {request.url} {e}"
        }
        status_code = 500

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
    status_code = 200
    try:
        response = openid_api_interface.token_store.get_keys()
    except (TokenIssuerCertificateStoreException, OpenidApiInterfaceException, UserCredentialStoreException) as e:
        response = e.to_dict()
        status_code = 403
    except Exception as e:
        logging.exception(e)
        response = {
            "error_code": "server_error",
            "error_description": f"Error {request.method} {request.url} {e}"
        }
        status_code = 500

    return jsonify(response), status_code


@openid_blueprint.route("/.well-known/openid-configuration", methods=["GET"])  # type: ignore[misc]
def openid_configuration() -> ResponseReturnValue:
    """returns OpenID Connect metadata"""
    # TODO: look at better way of determining this url, depending on the network location of
    #  the client_id and end user. i.e. if the endpoint is is accessible from different networks
    #  then there will have to be valid certificates in place for host ip of the listening
    #  endpoint and the url extracted from this send the usd user ot client app to the correct
    #  destination.
    try:
        id_provider_base_url = config.id_provider_base_url_external
        response = openid_lib.get_openid_configuration(
            tenant=config.id_service_prefix,
            base_url=id_provider_base_url,
        )
        status_code = 200
    except (TokenIssuerCertificateStoreException, OpenidApiInterfaceException, UserCredentialStoreException) as e:
        response = e.to_dict()
        status_code = 403
    except Exception as e:
        logging.exception(e)
        response = {
            "error_code": "server_error",
            "error_description": f"Error {request.method} {request.url} {e}"
        }
        status_code = 500

    return jsonify(response), status_code
