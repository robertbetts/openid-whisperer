import logging
import json
import secrets
from datetime import datetime
from uuid import uuid4
from typing import Dict

from flask import Flask, request, session, render_template, make_response, redirect, Response
import requests
import jwt
from json.decoder import JSONDecodeError

from mock_api_service.openid_client_lib import OpenIDClient
from mock_api_service.config import config


app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(46)

logging.info("Connecting to the identity provider: %s", config.identity_endpoint_gw)
openid_client: OpenIDClient = OpenIDClient(
    provider_url=config.identity_endpoint,
    provider_url_gw=config.identity_endpoint_gw,
    client_id=config.client_id,
    resource=config.resource_uri,
    verify_server=config.validate_certs,
    )


@app.route('/mock-api/handleAccessToken')
def handle_access_token() -> Response:
    """ After human authentication was handled by the Identity service, and after successful authentication,
        a redirect (302) is issued to this endpoint.

        If a valid access token (JWT) can not be retrieved from the Identity service on exchange of the code,
        then respond to the API service's login page.
    """
    code = request.args.get("code")
    state = request.args.get("state")

    message: str | None = None
    access_token: Dict[str, any] | None = None

    if state != session.get("state"):
        message = "Unable to pair state of access code response with the login redirect"
        logging.debug(message)

    else:
        # Using the code from the redirect (following Authentication), another call is required to IDA to
        # exchange the code for a JWT
        token_endpoint_url = openid_client.token_endpoint_url(gateway=True)
        header = {'content_type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'}
        payload = {'client_id': config.client_id, 'code': code, 'redirect_uri': config.redirect_url,
                   'resource': config.resource_uri, 'grant_type': 'authorization_code'}

        r = requests.post(token_endpoint_url, payload, header, verify=config.validate_certs)
        if 200 <= r.status_code < 300:
            try:
                json_response = r.json()
                if "access_token" in json_response:
                    access_token = json_response['access_token']
                elif "error" in json_response:
                    message = f"{json_response['error']}: {json_response['error_description']}"
                    logging.error(message)
                else:
                    logging.error("Unknown json response from Identity Provider:\n%s", json_response)
                    message = "Unknown response from Identity Provider"
            except JSONDecodeError as e:
                logging.error(e)
                logging.debug(request.text)
                message = "Error requesting token from the Identity Provider error, bad JSON data"
            except Exception as e:
                logging.error(e)
                message = "Error requesting token from access_code"

        # elif 400 <= r.status_code < 500:
        #     logging.error("Bad request submitted to the Identity Provider:\nresponse: %s", r.text)
        # elif 500 <= r.status_code:
        #     logging.error("Identity Provider server error:\nresponse: %s", r.text)
        # else:
        #     logging.error("Identity Provider server response: %s\nresponse: %s", r.status_code, r.text)

        # If message is set then there has been an error requesting the access_token
        if access_token is not None and message is None:
            try:
                claims = openid_client.validate_access_token(
                    access_token=access_token,
                    audience=config.audience,
                    verify_server=config.validate_certs)
                if claims["nonce"] != session["nonce"]:
                    message = "Unable to pair nonce from the token request with the login redirect session"
                else:
                    # Cache the access token in the session for future use
                    session['access_token'] = access_token
                    session['exp'] = exp_date = datetime.utcfromtimestamp(claims['exp'])
                    resp = make_response(render_template('mock_api_index.html', claims=claims, exp_date=exp_date))
                    return resp

            except jwt.ExpiredSignatureError as e:
                message = "Invalid token: %s" % e

            except jwt.InvalidTokenError as e:
                message = "Invalid token: %s" % e

            except Exception as e:
                logging.error(e)
                logging.exception(e)
                message = "Error during token validation: %s" % e

    # If the code reaches this point then assume there has been an error requesting an access token
    resp = make_response(render_template('mock_api_logout.html', message=message))
    session.clear()
    return resp


@app.route('/')
@app.route('/mock-api')
@app.route('/mock-api/')
def index():
    if 'access_token' in session:
        access_token = session['access_token']
        try:
            claims = openid_client.validate_access_token(
                access_token=access_token,
                audience=config.audience,
                verify_server=config.validate_certs,
            )
            exp_date = datetime.utcfromtimestamp(claims['exp'])
            return render_template('mock_api_index.html', claims=claims, exp_date=exp_date)

        except Exception as e:
            message = f"Invalid session token: {e}"
            resp = make_response(render_template('mock_api_logout.html', message=message))
            session.clear()
            return resp
    else:
        scope = "openid profile"
        nonce = session["nonce"] = uuid4().hex
        state = session["state"] = secrets.token_hex()
        auth_url = openid_client.authorization_endpoint_url(gateway=True)
        auth_url += \
            "?scope={}&response_type=code&client_id={}&resource={}&nonce={}&redirect_uri={}&state={}&nonce={}".format(
                scope, config.client_id, config.resource_uri, nonce, config.redirect_url, state, nonce
            )
        logging.debug("Auth redirect: %s", auth_url)
        return redirect(auth_url, code=302)


@app.route('/mock-api/api/public')
def api_public():
    return '{"message": "This is a public endpoint, no access token is needed"}'


@app.route('/mock-api/api/private')
def api_private():
    raw_token = request.headers.get('Authorization')
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
                verify_server=config.validate_certs)
            result = {
                "message": "You have successfully authenticated for this private endpoint"
            }
        except Exception as e:
            logging.error(e)
            result = {
                "error": "AccessValidationError",
                "error_description": f"The access token provided is not valid - {e}",
            }
    return json.dumps(result)
 
 
@app.route('/mock-api/gettoken')
def gettoken():
    token = session.get('access_token', {})
    return json.dumps(token)

 
@app.route('/mock-api/logout')
def logout():
    message = "You have successfully logged out"
    resp = make_response(render_template('mock_api_logout.html', message=message))
    session.clear()
    return resp


def main():
    config.initialize_logging()
    app.run(
        ssl_context='adhoc',
        debug=config.flask_debug,
        host='0.0.0.0',
        port=config.api_port)


if __name__ == "__main__":
    main()
