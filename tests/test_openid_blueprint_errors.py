import json
from uuid import uuid4
import secrets


def test_get_authorize_error(client):
    """ Test missing query parameter client_id
    """
    scope = "openid profile"
    response_type = "code"
    # client_id = "ID_12345"
    resource_uri = "TEST:URI:RS-104134-21171-test-api"
    redirect_url = "http://test/api/handleAccessToken"
    nonce = uuid4().hex
    state = secrets.token_hex()
    auth_url = "/adfs/oauth2/authorize?"
    auth_url += "scope={}&response_type={}&resource={}&redirect_uri={}&state={}&nonce={}".format(
        scope, response_type, resource_uri, redirect_url, state, nonce
    )
    response = client.get(auth_url)
    assert response.status_code == 403
    assert "A valid client_id is required" in response.text


def test_post_authorize_code_error(client):
    """ 1) Test missing form parameter UserName
        2) Test invalid credentials
    """
    scope = "openid profile"
    response_type = "code"
    client_id = "ID_12345"
    resource_uri = "TEST:URI:RS-104134-21171-test-api"
    redirect_url = "http://test/api/handleAccessToken"
    nonce = uuid4().hex
    state = secrets.token_hex()
    auth_url = "/adfs/oauth2/authorize?"
    auth_url += "scope={}&response_type={}&client_id={}&resource={}&redirect_uri={}&nonce={}&state={}".format(
        scope, response_type, client_id, resource_uri, redirect_url, nonce, state
    )
    secret = "very long dev reminder"
    data = {
        "grant_type": "password",
        "client_id": client_id,
        "resource": resource_uri,
        "Password": secret,
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'}
    response = client.post(auth_url, data=data, headers=headers)
    assert response.status_code == 302
    assert "error_code" in response.location

    data["UserName"] = ""
    response = client.post(auth_url, data=data, headers=headers)
    assert response.status_code == 302
    assert "error_code" in response.location


def test_post_authorize_token_error(client):
    """ 1) Test missing form parameter UserName
        2) Test invalid credentials
        3) Test invalid response_type input
        4) Test invalid request method
    """
    scope = "openid profile"
    response_type = "token id_token"
    client_id = "ID_12345"
    resource_uri = "TEST:URI:RS-104134-21171-test-api"
    redirect_url = "http://test/api/handleAccessToken"
    nonce = uuid4().hex
    state = secrets.token_hex()
    auth_url = "/adfs/oauth2/authorize?"
    auth_url += "scope={}&response_type={}&client_id={}&resource={}&redirect_uri={}&nonce={}&state={}".format(
        scope, response_type, client_id, resource_uri, redirect_url, nonce, state
    )
    domain = "my-domain"
    username = "my-name"
    domain_username = f"{username}@{domain}"
    secret = "very long dev reminder"
    data = {
        "grant_type": "password",
        "client_id": client_id,
        "resource": resource_uri,
        # "UserName": domain_username,
        "Password": secret,
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'}
    response = client.post(auth_url, data=data, headers=headers)
    assert response.status_code == 200
    result = json.loads(response.text)
    assert "error_code" in result
    assert "A valid username and user_secret is required" in result["error_description"]

    data["UserName"] = ""

    response = client.post(auth_url, data=data, headers=headers)
    assert response.status_code == 200
    result = json.loads(response.text)
    assert "error_code" in result
    assert "A valid username and user_secret is required" in result["error_description"]

    response_type = "BadValue"
    auth_url = "/adfs/oauth2/authorize?"
    auth_url += "scope={}&response_type={}&client_id={}&resource={}&redirect_uri={}&nonce={}&state={}".format(
        scope, response_type, client_id, resource_uri, redirect_url, nonce, state
    )
    data["UserName"] = domain_username
    response = client.post(auth_url, data=data, headers=headers)
    assert response.status_code == 403
    assert "Invalid response_type" in response.text
    # assert "A valid username and user_secret is required" in result["error_description"]
    # assert f"Invalid value for query parameter response_type, {response_type}" in response.text

    response_type = "token"
    auth_url += "scope={}&response_type={}&client_id={}&resource={}&redirect_uri={}&nonce={}&state={}".format(
        scope, response_type, client_id, resource_uri, redirect_url, nonce, state
    )
    data["UserName"] = domain_username
    response = client.patch(auth_url, data=data, headers=headers)
    assert response.status_code == 405


def test_post_get_token_error(client):
    """ 1) Test invalid grant_type
        2) when grant_type is password with invalid credentials
    """
    token_url = "/adfs/oauth2/token"
    data = {
        "grant_type": "invalid",
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'}
    response = client.post(token_url, data=data, headers=headers)
    assert response.status_code == 403
    result = json.loads(response.text)
    assert result["error"] == "auth_processing_error"
    assert result["error_description"] == f"The grant_type of '{data['grant_type']}' not as yet implemented"

    scope = "openid profile"
    client_id = "ID_12345"
    resource_uri = "TEST:URI:RS-104134-21171-test-api"
    domain_username = ""
    nonce = uuid4().hex
    token_url = "/adfs/oauth2/token"
    secret = "very long dev reminder"
    data = {
        "grant_type": "password",
        "username": domain_username,
        "password": secret,
        "nonce": nonce,
        "scope": scope,
        "client_id": client_id,
        "resource": resource_uri,
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'}
    response = client.post(token_url, data=data, headers=headers)
    assert response.status_code == 403
    result = json.loads(response.text)
    assert result["error"] == "bad_token_request"
    assert result["error_description"] == "Unable to retrieve token for grant 'password'"
