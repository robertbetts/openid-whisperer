import logging
import json
import secrets
from datetime import datetime
from uuid import uuid4

from flask import (
    Flask,
    request,
    session,
    render_template,
    make_response,
    redirect,
    Response,
)
import requests
import jwt
from json.decoder import JSONDecodeError

from openid_examples.mock_openid_client_lib import OpenIDClient
from openid_examples.mock_shared_config import config


app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(46)
logger = logging.getLogger(__name__)

logger.info("Connecting to the identity provider: %s", config.identity_endpoint_gw)
openid_client: OpenIDClient = OpenIDClient(
    provider_url=config.identity_endpoint,
    provider_url_gw=config.identity_endpoint_gw,
    tenant=config.tenant,
    client_id=config.client_id,
    scope=config.scope,
    resource=config.resource_uri,
    use_gateway=False,
    verify_server=config.validate_certs,
)


@app.route("/mock-api/handleAccessToken")
def handle_access_token() -> Response:
    """After human authentication was handled by the Identity service, and after successful authentication,
    a redirect (302) is issued to this endpoint.

    If a valid access token (JWT) can not be retrieved from the Identity service on exchange of the code,
    then respond to the API service's login page.
    """
    code: str | None = request.args.get("code")
    state: str | None = request.args.get("state")
    message: str | None = None
    access_token: str | None = None

    logger.debug("Incoming authorisation response:\ncode:%s\nstate:%s", code, state)

    if not code or not state or state != session.get("state"):
        message = "Validation failed for the access_token response"
        logger.debug(message)

    else:
        # Using the code from the redirect (following Authentication), a follow-up call is required to
        # get the access_token from the Identity service in exchange for the code received here
        token_endpoint_url = openid_client.token_endpoint_url(use_gateway=True)
        header = {
            "content_type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        payload = {
            "client_id": config.client_id,
            "code": code,
            "redirect_uri": config.redirect_url,
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
                    access_token = json_response["access_token"]
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

        # If message is set then there has been an error requesting the access_token
        if access_token is not None and message is None:
            try:
                claims = openid_client.validate_access_token(
                    access_token=access_token,
                    audience=config.audience,
                    verify_server=config.validate_certs,
                )
                if claims["nonce"] != session["nonce"]:
                    message = "Unable to pair nonce from the token request with the login redirect session"
                else:
                    # Cache the access token in the session for future use
                    session["access_token"] = access_token

                    # Redirect to the pre-authorisation endpoint requested
                    redirect_url = session.get("pre_auth_redirect_url")
                    redirect_url = redirect_url if redirect_url else "/"
                    resp = redirect(redirect_url, code=302)
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
    resp = make_response(render_template("mock_api_logout.html", message=message))
    session.clear()
    return resp, 401


@app.route("/")
@app.route("/mock-api")
def index():
    if session.new or "access_token" not in session:
        # Make an authentication and authorisation request
        response_type = "code"
        scope = openid_client.scope

        # nonce is used to validate the token generated for this authorisation request
        nonce = session["nonce"] = uuid4().hex
        # state is used to link this session to the redirect from the identity provider
        state = session["state"] = secrets.token_hex()

        # Storing the url for this request in order to redirect back here after authorisation
        session["pre_auth_redirect_url"] = request.url

        auth_url = openid_client.authorization_endpoint_url(use_gateway=True)
        auth_url += "?scope={}&response_type={}&client_id={}&resource={}&nonce={}&redirect_uri={}&state={}&nonce={}".format(
            scope,
            response_type,
            config.client_id,
            config.resource_uri,
            nonce,
            config.redirect_url,
            state,
            nonce,
        )
        logger.debug("New User Session:\nstate:%s\nnonce:%s", state, nonce)
        logger.debug("Authorisation redirect: %s", auth_url)
        return redirect(auth_url, code=302)

    else:
        access_token = session["access_token"]
        try:
            claims = openid_client.validate_access_token(
                access_token=access_token,
                audience=config.audience,
                verify_server=config.validate_certs,
            )
            exp_date = datetime.utcfromtimestamp(claims["exp"])
            return render_template(
                "mock_api_index.html",
                claims=claims,
                exp_date=exp_date,
                openid_provider_url=openid_client.provider_url,
                token_issuer_uri=openid_client.identity_config["access_token_issuer"],
            )

        except Exception as e:
            message = f"Invalid session token: {e}"
            resp = make_response(
                render_template("mock_api_logout.html", message=message)
            )
            session.clear()
            return resp


@app.route("/mock-api/api/public")
def api_public():
    return '{"message": "This is a public endpoint, no access token is needed"}'


@app.route("/mock-api/api/private")
def api_private():
    raw_token = request.headers.get("Authorization")
    if raw_token is None:
        result = {
            "error": "AccessDeniedError",
            "error_description": "This is a private endpoint, an access token is required",
        }
    else:
        try:
            token = raw_token[7:]
            openid_client.validate_access_token(
                access_token=token,
                audience=config.audience,
                verify_server=config.validate_certs,
            )
            result = {
                "message": "You have successfully authenticated for this private endpoint"
            }
        except Exception as e:
            logger.error(e)
            result = {
                "error": "AccessValidationError",
                "error_description": f"The access token provided is not valid - {e}",
            }
    return json.dumps(result)


@app.route("/mock-api/gettoken")
def gettoken():
    token = session.get("access_token", {})
    return json.dumps(token)


@app.route("/mock-api/logout")
def logout():
    message = "You have successfully logged out"
    resp = make_response(render_template("mock_api_logout.html", message=message))
    session.clear()
    return resp


def main() -> None:
    config.initialize_logging()
    app.run(
        ssl_context="adhoc",
        debug=config.flask_debug,
        host="0.0.0.0",
        port=config.api_port,
    )


if __name__ == "__main__":
    main()
