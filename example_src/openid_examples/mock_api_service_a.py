import logging
import os.path
import secrets
from typing import Dict, Any, AnyStr
from datetime import datetime
from functools import wraps
from urllib.parse import urljoin, urlparse, urlunsplit

from flask import (
    Flask,
    Blueprint,
    request,
    session,
    render_template,
    make_response,
    redirect,
    Response,
    jsonify,
    current_app
)
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_session import Session
import requests
import jwt
from json.decoder import JSONDecodeError

from openid_examples.mock_openid_client_lib import OpenIDClient
from openid_examples.mock_shared_config import config

config.initialize_logging()
logger = logging.getLogger(__name__)
template_folder = os.path.join(os.path.dirname(__file__), "templates")

mock_api_blueprint: Blueprint = Blueprint(
    "mock-api",
    __name__,
    template_folder="templates",
    static_folder="static",
    static_url_path="/mock-api/static"
)


def service_app(instance_id: str):
    app = Flask(
        "mock-api-service",
        template_folder=template_folder
    )
    app.secret_key = secrets.token_urlsafe(46)
    app.config.update(
        SESSION_KEY_PREFIX=instance_id,
        SESSION_COOKIE_NAME="mock-api-service",
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        # SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_PERMANENT=True,
        SESSION_TYPE="filesystem",
    )
    app.wsgi_app = ProxyFix(
        app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
    )
    Session(app)
    app.register_blueprint(mock_api_blueprint)
    return app


logger.info("Connecting to the identity provider: %s", config.identity_endpoint)
openid_client: OpenIDClient = OpenIDClient(
    provider_url=config.identity_endpoint,
    tenant=config.tenant,
    client_id=config.client_id,
    scope=config.scope,
    resource=config.resource_uri,
    verify_server=config.validate_certs,
)


def get_request_info():
    """ collate information relating to the request in order to process the response
    """
    proxy_scheme = "https" if request.headers.get("X-Force-Https", None) == "yes" else request.scheme
    return {
        "proxy_scheme": proxy_scheme,
    }


def retrieve_flask_session(sid):
    session_interface = current_app.session_interface
    data = current_app.session_interface.cache.get(session_interface.key_prefix + sid)
    if data is not None:
        user_session = session_interface.session_class(data, sid=sid)
    else:
        logging.debug(f"Flask session not found for sid {sid}")
        user_session = session_interface.session_class(sid=sid, permanent=session_interface.permanent)
    return user_session


def reflect_proxy_request(flask_request) -> AnyStr:
    """Returns a url where the network location, "{host}:{port}" respects that of the
    originating request. where there is a proxy, the X_FORWARDED values are used
    under the hood.

    This function is assumed to be used when Flask is handling a request.

    :param flask_request:
    """
    parts = urlparse(flask_request.url)
    request_netloc_parts = request.host.split(":")
    if len(request_netloc_parts) == 2:
        host, port = tuple(request_netloc_parts)
    else:
        host = request_netloc_parts[0]
        port = 80 if request.scheme == "http" else 443

    proxy_host = flask_request.headers.get("X-Forwarded-Host", host)
    proxy_port = flask_request.headers.get("X-Forwarded-Port", port)
    netloc = f"{proxy_host}:{proxy_port}"
    request_url = urlunsplit(
        (parts.scheme, netloc, parts.path, parts.query, parts.fragment)
    )
    return request_url


def start_provider_authentication_flow():
    logging.debug("Starting Identity Provider Authentication Flow")
    # Make an authentication and authorisation request
    response_type = "code"
    scope = openid_client.scope

    # nonce is used to validate the token generated for this authorisation request
    nonce = session["nonce"] = secrets.token_hex()
    # state is used to link this session to the redirect from the identity provider
    state = session.sid

    # Storing the url for this request in order to redirect back here after authorisation
    # if there is a proxy fronting the call, then this url represents X-FORWARDED-* values
    # Take note of the code `app.wsgi_app = ProxyFix(...)` above.
    incoming_request_url = reflect_proxy_request(request)
    logging.debug(f"Remembering incoming request for {incoming_request_url}")
    session["pre_auth_redirect_url"] = incoming_request_url
    session.modified = True

    redirect_url = urljoin(incoming_request_url, "/mock-api-private/handleAccessToken")
    logging.debug(f"url post authentication handling: {redirect_url}")

    response_mode = "query"

    auth_cb_url = openid_client.authorization_endpoint_url(use_gateway=False)
    auth_cb_url += (
        f"?scope={scope}&response_type={response_type}&response_mode={response_mode}"
        f"&client_id={config.client_id}&resource={config.resource_uri}"
        f"&nonce={nonce}&redirect_uri={redirect_url}&state={state}"
    )
    logger.debug("New User Session:\nstate:%s\nnonce:%s", state, nonce)
    logger.debug("Authorisation redirect: %s", auth_cb_url)

    return redirect(auth_cb_url, code=302)


def auth_token_required(f, allow_cookie: bool = True, allow_header: bool = True):
    """This decorator searches for a valid token in relation to the incoming request.
    Cookies: Authorization
    Headers: x-access-token, Authorization
    if a token in the request header is not present, then an existing authenticated
    session is referenced if present.
    For valid tokens, new claims are persisted in the session and the requested endpoint
    is called"""

    @wraps(f)
    def decorator(*args, **kwargs):
        response = None
        token = None
        token_claims = None
        """ token search order:
        1. Cookie: Authorization
        2. Header: Authorization
        3. Header: x-access-token
        4. Session
        """
        if allow_cookie:
            token = request.cookies.get("Authorization", "").split(" ")[-1].strip()
            if token:
                logger.debug("Found Authorisation cookie")
        if not token and allow_header:
            if 'Authorization' in request.headers:
                token = request.headers.get("Authorization", "").split(" ")[-1].strip()
                if token:
                    logger.debug("Found Authorization header")
            elif 'x-access-token' in request.headers:
                token = request.headers['x-access-token']
                if token:
                    logger.debug("Found x-access-token header")
        if not token:
            id_token = session.get("id_token")
            token = id_token if id_token else session.get("access_token")
            if token:
                token_claims = session.get("token_claims", {})
                logger.debug(f"existing user with claims: {token_claims}")

        if not token:  # throw error if no token provided
            if request.content_type == "application/json":
                response = make_response(jsonify({
                    "error": "missing_token",
                    "error_description": "Requests to this url, requires a valid jwt"
                }), 401)
            else:
                response = start_provider_authentication_flow()

        if token and token_claims is None:
            try:
                token_claims = openid_client.validate_access_token(
                    access_token=token,
                    audience=openid_client.audience,
                    verify_server=config.validate_certs,
                )
                session["access_token"] = token
                session["token_claims"] = token_claims
                session.modified = True
            except Exception as e:
                unverified_claims = jwt.decode(token, options={"verify_signature": False})
                logging.debug(f"unverified_claims: {unverified_claims}")
                logging.exception(e)
                error = jsonify({
                    "error": "Invalid token",
                    "error_description": "Requests to this url, require a valid jwt"
                })
                if request.content_type == "application/json":
                    response = make_response(error, 401)
                else:
                    response = start_provider_authentication_flow()
        if response:
            return response

        """When a valid token has been identified in relation to the incoming request, 
        new claims have been persist in the session and the requested endpoint will be called
        """
        return f(*args, **kwargs)
    return decorator


@mock_api_blueprint.route("/mock-api-private/handleAccessToken", methods=["GET", "POST"])
def handle_access_token() -> Response:
    """After human authentication was performed by the Identity Provider, and after successful authentication,
    a redirect (302) for a form_post is issued to this endpoint.

    If a valid access token (JWT) can not be retrieved from the Identity service on exchange of the code,
    then respond to the API service"s login page.

    With OpenID, this endpoint is always accessed from the end-user/device requiring authentication.

    The function IS ALWAYS called as a result from an Authentication flow initiated from this
    service and as such there will be a session previously setup with and session id, sid
    equal to the state parameter passed back by the Identity Provider.

    If a session can not be found, then it has timed out or the incoming request is invalid. We can't
    always rely on a session cookie depending on downstream proxies to to identify an existing user session.
    In addition, due to SameSite cookie security requirements, in certain configurations session cookies will
    be blocked. ***THIS IS CURRENTLY A CHALLENGE** to find a suitable solution for, and one that is independent of
    downstream infrastructure assembly and configuration.
    """
    state: str | None
    nonce: str | None
    code: str | None = None
    id_token: str | None = None
    tokens: Dict[str, Any] | None = None
    message: str | None = None

    if request.method == "GET":
        code = request.args.get("code")
        state = request.args.get("state")
        nonce = request.args.get("nonce")
    else:
        id_token = request.form.get("id_token")
        state = request.form.get("state")
        nonce = request.form.get("nonce")

    logger.debug((
        f"Incoming authorisation {request.method} response:\n"
        f"id_token: {id_token}\n"
        f"code: {code}\n"
        f"state: {state}\n"
        f"nonce: {nonce}\n"
        f"new_session: {session.new}\n"
    ))

    if state != session.sid:
        message = (
            "Unable to process authorization. Invalid response, request unverified."
        )
    elif session is None:
        message = (
            "Unable to process authorization. in"
        )
    elif request.method == "POST" and not id_token:
        message = (
            "Unable to process authorization. Invalid form_post, id_token not present."
        )

    elif not code and id_token:
        message = "Unable to process authorization. Invalid response, missing parameters."

    if message:
        logger.debug(message)
    elif id_token:
        tokens = {
            "id_token": id_token
        }
    elif code:
        # Using the code from the redirect (following Authentication), a follow-up call is required to
        # get the access_token from the Identity service in exchange for the code received here
        token_endpoint_url = openid_client.token_endpoint_url()
        header = {
            "content_type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        # redirect is the original redirect send by client_id to initiate the authentication flow
        redirect_url = urljoin(request.url, "/mock-api-private/handleAccessToken")
        payload = {
            "client_id": config.client_id,
            "code": code,
            "redirect_uri": redirect_url,
            "resource": config.resource_uri,
            "grant_type": "authorization_code",
        }

        r = requests.post(
            token_endpoint_url, payload, header, verify=config.validate_certs
        )
        if 200 <= r.status_code < 300:
            try:
                json_response = r.json()
                if "access_token" in json_response:
                    tokens = json_response
                elif "error" in json_response:
                    message = f"{json_response['error']}: {json_response['error_description']}"
                    logger.error(message)
                else:
                    logger.error(
                        "Unknown json response from Identity Provider:\n%s",
                        json_response,
                    )
                    message = "Unknown response from Identity Provider"
            except JSONDecodeError as e:
                logger.error(e)
                logger.debug(r.text)
                message = "Error requesting token from the Identity Provider error, bad JSON data"
            except Exception as e:
                logger.error(e)
                message = "Error requesting token from access_code"

    if tokens and message is None:
        try:
            access_token = tokens.get("access_token")
            token = id_token if id_token else access_token
            claims = openid_client.validate_access_token(
                access_token=token,
                audience=config.audience,
                verify_server=config.validate_certs,
            )
            if nonce and claims["nonce"] != nonce:
                message = "Unable to pair nonce from the token claims to the originating session"
            else:
                # Cache the access token in the session for future use
                session["id_token"] = id_token
                session["access_token"] = access_token
                session["user_claims"] = claims
                session["refresh_token"] = tokens.get("refresh_token")
                session.modified = True

                # Redirect to the pre-authorisation endpoint requested, i.e. the original end-user / device request.
                redirect_url = session.get("pre_auth_redirect_url")
                logger.debug(r"redirect url: {result_url}")
                resp = redirect(redirect_url, code=302)
                # current_app.session_interface.save_session(current_app, user_session, resp)
                return resp

        except jwt.ExpiredSignatureError as e:
            message = "Invalid token: %s" % e
            logger.error(message)
        except jwt.InvalidTokenError as e:
            message = "Invalid token: %s" % e
            logger.error(message)
        except Exception as e:
            message = "Error during token validation: %s" % e
            logger.exception(message)

    # If the code reaches this point then the authentication has been unsuccessful
    resp = make_response(
        render_template(
            "mock_api_logout.html", message=message
        ),
        401
    )
    return resp


@mock_api_blueprint.route("/")
def index():
    instance_id = current_app.config.get("SESSION_KEY_PREFIX")
    new_session = session.new
    session_id = session.sid
    access_token = session.get("access_token", "")
    id_token = session.get("id_token", "")
    refresh_token = session.get("refresh_token", "")
    user_claims = session.get("user_claims", "")
    template_input = {
        "instance_id": instance_id,
        "new_session": new_session,
        "session_id": session_id,
        "access_token": access_token,
        "id_token": id_token,
        "refresh_token": refresh_token,
        "user_claims": user_claims,
        "client_id": config.client_id,
        "provider_url": config.identity_endpoint
    }

    return render_template(
        "index.html",
        **template_input
    )


@mock_api_blueprint.route("/mock-api-public/api")
def api_public():
    return jsonify({"message": "This is a public endpoint, no access token is needed"})


@mock_api_blueprint.route("/mock-api-private", strict_slashes=False)
@auth_token_required
def index_authenticated():
    logger.debug("Authenticated access request")
    try:
        claims = session["user_claims"]
        exp_date = datetime.utcfromtimestamp(claims["exp"])
        return render_template(
            "authenticated_index.html",
            claims=claims,
            exp_date=exp_date,
            client_id=openid_client.client_id,
            openid_provider_url=openid_client.provider_url,
            token_issuer_uri=openid_client.identity_config["access_token_issuer"],
        )

    except Exception as e:
        message = f"Invalid session token: {e}"
        resp = make_response(
            render_template("mock_api_logout.html", message=message),
            500
        )
        return resp


@mock_api_blueprint.route("/mock-api-private/logout")
def logout():
    message = "You have successfully logged out"
    resp = make_response(render_template("mock_api_logout.html", message=message))
    session.clear()
    return resp


@mock_api_blueprint.route("/mock-api-private/api")
@auth_token_required
def api_private():
    result = {
        "message": "You have successfully authenticated for this private endpoint"
    }
    return jsonify(result)


@mock_api_blueprint.route("/mock-api-private/gettoken")
@auth_token_required
def gettoken():
    token = session.get("access_token", {})
    return jsonify(token)


def main() -> None:
    instance_id = "instance_a"
    app = service_app(instance_id)
    app.run(
        # ssl_context="adhoc",
        debug=config.flask_debug,
        host="0.0.0.0",
        port=config.api_port,
    )


if __name__ == "__main__":
    main()
