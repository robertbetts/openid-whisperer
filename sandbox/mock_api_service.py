import logging
import json
import base64
import secrets
import os
from collections import UserDict
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime
from urllib.parse import urljoin, urlsplit, urlunsplit
from typing import Dict, Any

from flask import Flask, request, session, render_template, make_response, redirect, Response
import requests
import jwt

#
# API service parameters
#
API_GW_HOST: str = os.getenv("API_HOST", "192.168.56.102")
API_GW_PORT: int = int(os.getenv("API_PORT", "8000"))
API_HOST: str = os.getenv("API_HOST", "localhost")
API_PORT: int = int(os.getenv("API_PORT", "5001"))
FLASK_DEBUG: bool = os.getenv("FLASK_DEBUG", "True").lower() == "true"
VALIDATE_CERTS: bool = os.getenv("VALIDATE_CERTS", "False").lower() != "false"


def replace_base_netloc(url1: str, url2: str) -> str:
    """Combine the network location of url1 with scheme, path, query and fragment of url2"""
    parts1 = urlsplit(url1)
    parts2 = urlsplit(url2)
    return urlunsplit((parts2.scheme, parts1.netloc, parts2.path, parts2.query, parts2.fragment))


class IdentityConfig(UserDict):
    """ Dictionary like class for caching the Identity provider's configuration
    """
    def __init__(self, provider_url: str, verify_server: bool = True):
        self.provider_url: str = provider_url
        self.verify_server: str = verify_server
        super().__init__()
        self.refresh()

    def refresh(self):
        """ Update the dictionary's data with that from the identity provider
        """
        endpoint = urljoin(self.provider_url, ".well-known/openid-configuration")
        response = requests.get(url=endpoint, verify=self.verify_server)
        config_data: Dict[str, Any] = response.json()
        self.update(config_data)


#
# Identity Provider Parameters
#
identity_endpoint: str = "https://localhost:5000/adfs/"
identity_config: IdentityConfig = IdentityConfig(identity_endpoint, VALIDATE_CERTS)
identity_keys: Dict[str, Any] = {}
validated_claims: Dict[str, Any] = {}

#
# API service identity parameters
#
client_id: str = "PC-90274-SID-12655-DEV"
redirect_url: str = f"http://{API_GW_HOST}:{API_GW_PORT}/mock-api/handleAccessToken"
resource_uri: str = "URI:API:RS-104134-21171-mock-api-PROD"


app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(46)


def validate_access_token(access_token: str, verify_server: bool = True) -> Dict[str, Any]:
    """ Validate a JWT against the keys provided by the IDA service and return a valid claim payload.
        if the JWT, claim or IDA keys are invalid or the claim is empty the raise an exception.
    """
    global identity_keys, validated_claims
    at_list = access_token.split(".")
    header = json.loads(base64.b64decode(at_list[0]).decode("utf-8"))
    tok_x5t = header["x5t"]
    issuer: str = identity_config["access_token_issuer"]

    if not identity_keys:
        key_endpoint = replace_base_netloc(identity_endpoint, identity_config["jwks_uri"])
        header = {'content_type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'}
        response = requests.get(url=key_endpoint, headers=header, verify=verify_server)
        keys = json.loads(response.text)["keys"]

        # Loop through keys to create dictionary
        for key in keys:
            x5t = key["x5t"]  # Certificate id
            x5c = key["x5c"][0]  # base64 x509 certificate (DER, PKCS1)
            # extract signed public key to be used for access token validation
            public_key_spki_der = base64.b64decode(x5c.encode("ascii"))
            cert = x509.load_der_x509_certificate(public_key_spki_der, default_backend())
            public_key = cert.public_key()
            # cache the IDA public key
            identity_keys[x5t] = public_key

    key_errors = []
    token_errors = []
    # Loop through the available ida public keys to verify the JWT
    for key in identity_keys:
        try:
            claims = jwt.decode(access_token, identity_keys[tok_x5t],
                                audience=resource_uri, issuer=issuer, algorithms=["RS256"])
            if claims:
                validated_claims[access_token] = claims
                return claims
            else:
                raise Exception("Access token contains no valid claims")

        except jwt.ExpiredSignatureError as e:
            key_errors.append((key, e))

        except jwt.InvalidTokenError as e:
            token_errors.append((access_token, e))

    for error in token_errors:
        logging.error('Invalid JWT token: %s, %s', error[1], error[0])
        raise error[1]

    for error in key_errors:
        logging.error('IDA key signature error: %s - %s', error[0], error[1])
        raise error[1]


@app.route('/mock-api/handleAccessToken')
def handle_access_token() -> Response:
    """ After human authentication was handled by the Identity service, and after successful authentication,
        a redirect (302) is issued to this endpoint.

        If a valid access token (JWT) can not be retrieved from the Identity service on exchange of the code,
        then respond to the API service's login page.
    """
    code = request.args.get('code')
 
    # Using the code from the redirect (following Authentication), another call is required to IDA to
    # exchange the code for a JWT
    token_url = replace_base_netloc(identity_endpoint, identity_config["token_endpoint"])
    header = {'content_type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'}
    payload = {'client_id': client_id, 'code': code, 'redirect_uri': redirect_url,
               'resource': resource_uri, 'grant_type': 'authorization_code'}

    # TODO: Exception handling when exchanging the code for a JWT
    r = requests.post(token_url, payload, header, verify=VALIDATE_CERTS)
    json_response = r.json()
    access_token = json_response['access_token']

    try:
        claims = validate_access_token(access_token, verify_server=VALIDATE_CERTS)
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
            claims = validate_access_token(access_token)
            exp_date = datetime.utcfromtimestamp(claims['exp'])
            return render_template('mock_api_index.html', claims=claims, exp_date=exp_date)

        except Exception as e:
            message = "Session token has not - It may have expired: %s" % e
            resp = make_response(render_template('mock_api_logout.html', message=message))
            session.clear()
            return resp
    else:
        nonce = "1234"
        url = "/adfs/oauth2/authorize?response_type=code&client_id={}&resource={}&nonce={}&redirect_uri={}".format(
            client_id, resource_uri, nonce, redirect_url
        )
        auth_url = urljoin(identity_endpoint, url)
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
            validate_access_token(token, verify_server=VALIDATE_CERTS)
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
    app.run(debug=FLASK_DEBUG, host='0.0.0.0', port=API_PORT)
