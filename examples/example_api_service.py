import logging
import json
import secrets
import os
from datetime import datetime
from uuid import uuid4

from flask import Flask, request, session, render_template, make_response, redirect, Response
import requests
import jwt

from openid_whisperer.openid_client_lib import OpenIDClient
from config import config


# API service parameters
#
API_GW_HOST: str = os.getenv("API_HOST", "localhost")
API_GW_PORT: int = int(os.getenv("API_PORT", "5006"))
API_HOST: str = os.getenv("API_HOST", "localhost")
API_PORT: int = int(os.getenv("API_PORT", "5006"))
FLASK_DEBUG: bool = os.getenv("FLASK_DEBUG", "True").lower() == "true"
VALIDATE_CERTS: bool = os.getenv("VALIDATE_CERTS", "False").lower() != "false"

# Identity Provider Parameters
#
identity_endpoint: str = "https://localhost:5005/adfs/"

# API service identity parameters
#
client_id: str = "PC-90274-SID-12655-DEV"
redirect_url: str = f"http://{API_GW_HOST}:{API_GW_PORT}/mock-api/handleAccessToken"
resource_uri: str = "URI:API:RS-104134-21171-mock-api-PROD"

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(46)

openid_client: OpenIDClient = OpenIDClient(
    provider_url=identity_endpoint,
    client_id=client_id,
    resource_uri=resource_uri,
    verify_server=VALIDATE_CERTS,
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

    message: str = ""
    if state != session["state"]:
        message = "Unable to pair state of access code response with the login redirect"

    else:
        # Using the code from the redirect (following Authentication), another call is required to IDA to
        # exchange the code for a JWT
        token_endpoint_url = openid_client.token_endpoint_url()
        header = {'content_type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'}
        payload = {'client_id': client_id, 'code': code, 'redirect_uri': redirect_url,
                   'resource': resource_uri, 'grant_type': 'authorization_code'}

        # TODO: Exception handling when exchanging the code for a JWT
        r = requests.post(token_endpoint_url, payload, header, verify=VALIDATE_CERTS)
        json_response = r.json()
        access_token = json_response['access_token']

        try:
            claims = openid_client.validate_access_token(access_token, verify_server=VALIDATE_CERTS)
            if claims["nonce"] != session["nonce"]:
                message = "Unable to pair nonce from the token request with the login redirect session"
            else:
                # Cache the access token in the session for future use
                session['access_token'] = access_token
                session['exp'] = exp_date = datetime.utcfromtimestamp(claims['exp'])
                resp = make_response(render_template('mock_api_index.html', claims=claims, exp_date=exp_date))
                return resp

        except jwt.ExpiredSignatureError as e:
            message = "Invalid JWT token: %s" % e

        except jwt.InvalidTokenError as e:
            message = "Invalid JWT token: %s" % e

        except Exception as e:
            message = "Error during JWT token validation: %s" % e

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
            claims = openid_client.validate_access_token(access_token)
            exp_date = datetime.utcfromtimestamp(claims['exp'])
            return render_template('mock_api_index.html', claims=claims, exp_date=exp_date)

        except Exception as e:
            message = "Session token has not - It may have expired: %s" % e
            resp = make_response(render_template('mock_api_logout.html', message=message))
            session.clear()
            return resp
    else:
        scope = "openid profile"
        nonce = session["nonce"] = uuid4().hex
        state = session["state"] = secrets.token_hex()
        auth_url = openid_client.authorization_endpoint_url()
        auth_url += \
            "?scope={}&response_type=code&client_id={}&resource={}&nonce={}&redirect_uri={}&state={}&nonce={}".format(
                scope, client_id, resource_uri, nonce, redirect_url, state, nonce
            )
        return redirect(auth_url, code=302)


@app.route('/mock-api/api/public')
def api_public():
    return '{"message": "This is a public endpoint, no access token is needed"}'


@app.route('/mock-api/api/private')
def api_private():
    token = request.headers.get('Authorization')
    if token is None:
        result = {"message": "Access Denied - This is a private endpoint, an access token is required"}
    else:
        try:
            openid_client.validate_access_token(token, verify_server=VALIDATE_CERTS)
            result = {"message": "You have successfully authenticated for this private endpoint"}
        except Exception as e:
            logging.exception(e)
            result = {"message": "Access Denied - The access token provided is not valid"}
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


if __name__ == "__main__":
    config.initialize_logging()
    app.run(debug=FLASK_DEBUG, host='0.0.0.0', port=API_PORT)
