""" Flask Blueprint with OpenID compatible endpoints
"""
import logging
import json
from typing import List, Dict, Any
from urllib.parse import urljoin
from flask import Blueprint, request, make_response, render_template, redirect, abort
from werkzeug.exceptions import BadRequestKeyError
from flask.typing import ResponseReturnValue

from openid_whisperer import openid_lib
from openid_whisperer.config import IDP_BASE_URL

logger = logging.getLogger()
openid_prefix: str = "/adfs"
openid_blueprint: Blueprint = Blueprint('openid', __name__,
                                        url_prefix=openid_prefix,
                                        template_folder='templates',
                                        static_folder='static')


@openid_blueprint.route("/oauth2/authorize", methods=["GET", "POST"])
def authorize() -> ResponseReturnValue:
    """ returns an authorization code that can be used to obtain the 
        access token

        https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/overview/ad-fs-openid-connect-oauth-flows-scenarios

        https://adfs.contoso.com/adfs/oauth2/authorize?
        client_id=6731de76-14a6-49ae-97bc-6eba6914391e
        &response_type=id_token+token
        &redirect_uri=http%3A%2F%2Flocalhost%2Fmyapp%2F
        &scope=openid
        &response_mode=fragment
        &state=12345

        client_id	required	The Application (client) ID that the AD FS
            assigned to your app.
        response_type	required	Must include id_token for OpenID Connect
            sign-in. It may also include the response_type token. Using token
            here allows your app to receive an access token immediately from
            the authorize endpoint without having to make a second request to
            the token endpoint.
        redirect_uri	required	The redirect_uri of your app, where
            authentication responses can be sent and received by your app. It
            must exactly match one of the redirect_uris you configured in AD FS
        nonce	required	A value included in the request, generated by the
            app that is to be included in the resulting id_token as a claim.
            The app can then verify this value to mitigate token replay
            attacks. The value is typically a randomized, unique string that
            can be used to identify the origin of the request. Only required
            when an id_token is requested.
        
        scope	optional	A space-separated list of scopes. For OpenID 
            Connect, it must include the scope openid.
        resource	optional	The url of your Web API. Note: If using MSAL 
            client library, then resource parameter isn't sent. Instead, the
            resource url is sent as a part of the scope parameter:
                scope = [resource url]//[scope values e.g., openid]
                If resource isn't passed here or in scope, AD FS uses a default
                resource
                urn:microsoft:userinfo. userinfo resource policies such as MFA,
                Issuance or authorization policy, can't be customized.
        response_mode	optional	Specifies the method that should be used to
            send the resulting token back to your app. Defaults to fragment.
        state	optional	A value included in the request that must also be
            returned with the token response. It can be a string of any content
            that you wish. A randomly generated unique value is typically used
            for preventing cross-site request forgery attacks. The state is
            also used to encode information about the user's state in the app
            before the authentication request occurred, such as the page or
            view they were on.

        Response type: code
        rcode: The authorization_code that the app requested. The app can use 
            the authorization code to request an access token for the target 
            resource. Authorization_codes are short-lived, typically they
            expire after about 10 minutes.
        state: If a state parameter is included in the request, the same value 
            should appear in the response. The app should verify that the state
            values in the request and response are identical.                            

    """

    request_params: Dict[str, Any] = {}
    try:
        scope: str = request.args['scope'].split(" ")
        response_type: str = request.args['response_type']
        client_id: str = request.args['client_id']
        redirect_uri: str = request.args['redirect_uri']
        state: str = request.args.get('state', "")
        response_mode: str = request.args.get('response_mode', "")
        nonce: str = request.args.get('nonce', "")
        resource: str = request.args.get('resource', "")

    except BadRequestKeyError as e:
        error_message = f"Invalid input, missing query parameter {e.args[0]}. "\
                        "scope, response_type, client_id, redirect_url are required parameters"
        logger.debug(error_message)
        abort(403, error_message)

    if request.method == "GET":
        url_params = \
            "scope={}&response_type={}&client_id={}&resource={}&redirect_uri={}&nonce={}&state={}".format(
                scope, response_type, client_id, resource, redirect_uri, nonce, state
            )
        action = f"?{url_params}"
        resp = make_response(render_template('login.html',
                                             action=action,
                                             client_id=None,
                                             redirect_uri=None))
        return resp

    if request.method == "POST":
        if "code" in response_type:
            try:
                username = request.form["UserName"]
                user_secret = request.form["Password"]
            except BadRequestKeyError as e:
                error_message = f"Invalid input, missing form input {e.args[0]}. " \
                                "UserName, Password are required form parameters"
                logging.debug(error_message)
                abort(403, error_message)

            authorisation_code: str | None = openid_lib.authenticate_code(
                client_id=client_id,
                resource=resource,
                username=username,
                user_secret=user_secret,
                nonce=nonce,
                scope=scope
            )
            if authorisation_code is None:
                abort(401, "Unable to authenticate using the information provided")

            query_start = "&" if "?" in redirect_uri else "?"
            redirect_uri = f"{redirect_uri}{query_start}code={authorisation_code}"
            redirect_uri = f'{redirect_uri}&state={state}' if state else redirect_uri

            return redirect(redirect_uri, code=302)

        if "token" in response_type:
            try:
                username = request.form["UserName"]
                user_secret = request.form["Password"]
                kmsi = request.form.get("Kmsi", "")
            except BadRequestKeyError as e:
                error_message = f"Invalid input, missing form input {e.args[0]}. " \
                                "UserName, Password are required form parameters"
                abort(403, error_message)

            access_token_response = openid_lib.authenticate_token(
                client_id=client_id,
                resource=resource,
                username=username,
                user_secret=user_secret,
                nonce=nonce,
                scope=scope,
                kmsi=kmsi
            )
            if not access_token_response:
                abort(401, "Unable to authenticate using the information provided")
            return json.dumps(access_token_response)

        abort(500, f"Invalid value for query parameter response_type, {response_type}")

    # abort(500, f"Invalid request method {request.method}")


@openid_blueprint.route("/oauth2/token", methods=["POST"])
def token() -> ResponseReturnValue:
    """ returns an access token that can be used to access the resource 
        (Web API)

        // Line breaks for legibility only

        POST /adfs/oauth2/token HTTP/1.1
        Host: https://adfs.contoso.com/
        Content-Type: application/x-www-form-urlencoded

        client_id=6731de76-14a6-49ae-97bc-6eba6914391e
        &code=OAAABAAAAiL9Kn2Z27UubvWFPbm0gLWQJVzCTE9UkP3pSx1aXxUjq3n8b2JRLk...
        &redirect_uri=http%3A%2F%2Flocalhost%2Fmyapp%2F
        &grant_type=authorization_code
        &client_secret=JqQX2PNo9bpM0uEihUPzyrh    
        // NOTE: Only required for confidential clients (web apps)

        client_id	required	The Application (client) ID that the AD FS 
            assigned to your app.
        grant_type	required	Must be authorization_code for the 
            authorization code flow.
        code	required	The authorization_code that you acquired in the 
            first leg of the flow.
        redirect_uri	required	The same redirect_uri value that was used
            to acquire the authorization_code.
        client_secret	required for web apps The application secret that you
            created during app registration in AD FS. You shouldn't use the
            application secret in a native app because client_secrets can't be 
            reliably stored on devices. It's required for web apps and web 
            APIs, which have the ability to store the client_secret securely on
            the server side. The client secret must be URL-encoded before being
            sent. These apps can also use a key based authentication by signing
            a JWT and adding that as client_assertion parameter.
        resource optional   The url of your Web API.
            Note – If using MSAL client library, then resource parameter isn't sent. Instead, the resource url is sent
            as a part of the scope parameter: scope = [resource url]//[scope values e.g., openid]
            If resource isn't passed here or in scope, AD FS uses a default resource urn:microsoft:userinfo. userinfo
            resource policies such as MFA, Issuance or authorization policy, can't be customized.
        scope   optional    A space-separated list of scopes.
        code_verifier	optional	The same code_verifier that was used to
            obtain the authorization_code. Required if PKCE was used in the
            authorization code grant request. For more information, see the
            PKCE RFC. This option applies to AD FS 2019 and later
    """
    grant_type: str = request.form["grant_type"]
    if grant_type == "authorization_code":
        # TODO: look into specifications for handling redirect_uri and compare with openid specs MS reference below:
        # https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/overview/ad-fs-openid-connect-oauth-flows-scenarios

        # client_id: str | None = request.form["client_id"]
        code: str = request.form["code"] if request.form["code"] else ""
        # redirect_uri: str | None = request.form["redirect_uri"]
        # client_secret: str | None = request.form["client_secret"]
        # code_verifier: str | None = request.form["code_verifier"]
        response = openid_lib.get_access_token_from_authorisation_code(code)

    elif grant_type == "password":
        username = request.form["username"]
        user_secret = request.form["password"]
        nonce = request.form.get("nonce", "")
        scope = request.form.get("scope", "")
        access_token_response = openid_lib.authenticate_token(
            client_id=request.form["client_id"],
            resource=request.form["resource"],
            username=username,
            user_secret=user_secret,
            nonce=nonce,
            scope=scope
        )
        if access_token_response is None:
            response = {
                "error": "invalid_grant",
                "error_description": "MSIS9659: Invalid 'username' or 'password'."
            }
        else:
            response = access_token_response

    else:
        response = {
            "error": "invalid_grant",
            "error_description": f"unsupported grant_type: {grant_type}"
        }

    return json.dumps(response)


@openid_blueprint.route("/oauth2/userinfo", methods=["POST"])
def userinfo() -> ResponseReturnValue:
    """ returns claims about the authenticated user
    """
    return ""


@openid_blueprint.route("/oauth2/devicecode", methods=["POST"])
def devicecode() -> ResponseReturnValue:
    """ returns the device code and user code
    """
    return ""


@openid_blueprint.route("/oauth2/v2.0/logout", methods=["GET"])
@openid_blueprint.route("/oauth2/logout", methods=["POST"])
def logout() -> ResponseReturnValue:
    """ logs out the user
    """
    post_logout_redirect_uri = request.args["post_logout_redirect_uri"]
    return redirect(post_logout_redirect_uri, code=302)


@openid_blueprint.route("/discovery/keys", methods=["GET"])
def keys() -> ResponseReturnValue:
    """ public keys used to sign responses
    """
    return json.dumps(
        openid_lib.get_keys()
    )


@openid_blueprint.route("/.well-known/openid-configuration", methods=["GET"])
def openid_configuration() -> ResponseReturnValue:
    """ returns OAuth/OpenID Connect metadata
    """
    return json.dumps(openid_lib.get_openid_configuration(IDP_BASE_URL, openid_prefix))
