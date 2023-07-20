import json
from uuid import uuid4
import secrets


def test_get_authorize_403_error(client, scenario_api_a):
    """Test missing query parameter client_id"""
    scope = scenario_api_a["scope"]
    response_type = "code"
    resource = scenario_api_a["resource"]
    redirect_uri = scenario_api_a["redirect_uri"]
    nonce = scenario_api_a["nonce"]
    state = secrets.token_hex()
    auth_url = "/adfs/oauth2/authorize?"
    auth_url += "scope={}&response_type={}&resource={}&redirect_uri={}&state={}&nonce={}".format(
        scope, response_type, resource, redirect_uri, state, nonce
    )
    response = client.get(auth_url)
    assert response.status_code == 403
    assert "A valid client_id is required" in response.text


def test_post_authorize_code_error(client, scenario_api_a):
    # 1) Test missing / empty UserName
    client_id = scenario_api_a["client_id"]
    scope = scenario_api_a["scope"]
    response_type = "code"
    resource = scenario_api_a["resource"]
    redirect_uri = scenario_api_a["redirect_uri"]
    nonce = scenario_api_a["nonce"]
    state = secrets.token_hex()
    auth_url = "/adfs/oauth2/authorize?"
    auth_url += "scope={}&response_type={}&client_id={}&resource={}&redirect_uri={}&nonce={}&state={}".format(
        scope, response_type, client_id, resource, redirect_uri, nonce, state
    )
    password = scenario_api_a["password"]
    data = {
        "response_type": response_type,
        "grant_type": "password",
        "client_id": client_id,
        "resource": resource,
        "Password": password,
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    response = client.post(auth_url, data=data, headers=headers)
    assert response.status_code == 302
    assert "error" in response.location


def test_post_authorize_token_error(client):
    """1) Test missing form parameter UserName
    2) Test invalid credentials
    3) Test invalid response_type input
    4) Test invalid request method
    """
    scope = "openid profile"
    response_type = "token id_token"
    client_id = "ID_12345"
    client_secret = uuid4().hex
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
        "response_type": response_type,
        "grant_type": "password",
        "client_id": client_id,
        "client_secret": client_secret,
        "resource": resource_uri,
        # "UserName": domain_username,
        "Password": secret,
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    response = client.post(auth_url, data=data, headers=headers)
    result = json.loads(response.text)
    assert "error" in result
    assert "Valid credentials are required" in result["error_description"]
    assert response.status_code == 403

    data["UserName"] = ""
    response = client.post(auth_url, data=data, headers=headers)
    assert response.status_code == 403
    result = json.loads(response.text)
    assert "error" in result
    assert "Valid credentials are required" in result["error_description"]

    response_type = "BadValue"
    auth_url = "/adfs/oauth2/authorize?"
    auth_url += "scope={}&response_type={}&client_id={}&resource={}&redirect_uri={}&nonce={}&state={}".format(
        scope, response_type, client_id, resource_uri, redirect_url, nonce, state
    )
    data["response_type"] = response_type
    data["UserName"] = domain_username
    response = client.post(auth_url, data=data, headers=headers)
    assert response.status_code == 403
    result = json.loads(response.text)
    assert "api_validation_error" in result["error"]

    response_type = "token"
    auth_url += "scope={}&response_type={}&client_id={}&resource={}&redirect_uri={}&nonce={}&state={}".format(
        scope, response_type, client_id, resource_uri, redirect_url, nonce, state
    )
    data["response_type"] = response_type
    data["UserName"] = domain_username
    response = client.patch(auth_url, data=data, headers=headers)
    assert response.status_code == 405


def test_post_get_token_error(client, scenario_api_a):
    """1) Test invalid grant_type
    2) when grant_type is password with invalid credentials
    """
    token_url = "/adfs/oauth2/token"
    data = {
        "client_id": scenario_api_a["client_id"],
        "client_secret": scenario_api_a["client_secret"],
        "grant_type": "invalid",
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    response = client.post(token_url, data=data, headers=headers)
    assert response.status_code == 403
    result = json.loads(response.text)
    assert "api_validation_error" in result["error"]
    assert (
        result["error_description"]
        == f"The grant_type of '{data['grant_type']}' is not supported"
    )

    token_url = "/adfs/oauth2/token"
    data = {
        "grant_type": "password",
        "username": scenario_api_a["username"],
        "password": scenario_api_a["password"],
        "nonce": scenario_api_a["nonce"],
        "scope": scenario_api_a["scope"],
        "client_id": scenario_api_a["client_id"],
        "client_secret": scenario_api_a["client_secret"],
        "resource": scenario_api_a["resource"],
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    response = client.post(token_url, data=data, headers=headers)
    result = json.loads(response.text)
    assert "access_token" in result
    assert response.status_code == 200


def test_logout_call(client):
    response = client.get(
        "/adfs/oauth2/logout?post_logout_redirect_uri=http://test/api/logout"
    )
    assert response.status_code == 403

    response = client.post(
        "/adfs/oauth2/logout?post_logout_redirect_uri=http://test/api/logout"
    )
    assert response.status_code == 403


def test_post_userinfo_403_error(client, scenario_api_a, openid_api):
    """Use broken openid_interface to force unhandled runtime exception"""

    api_url = "/adfs/oauth2/userinfo"
    data = {
        "" "client_id": "",
        "client_secret": "",
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    response = client.post(api_url, data=data, headers=headers)
    result = response.json
    assert "auth_processing_error" in result["error"]
    assert response.status_code == 403
