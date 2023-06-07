import json
from uuid import uuid4
import secrets
from urllib.parse import urlparse
from typing import List
from openid_whisperer.main import app

import pytest

def test_userinfo():
    test_client = app().test_client()
    response = test_client.post("/adfs/oauth2/userinfo")
    # if response.status_code != 200:
    #     logging.info(response.text)
    assert response.status_code == 200


def test_devicecode():
    test_client = app().test_client()
    response = test_client.post("/adfs/oauth2/devicecode")
    # if response.status_code != 200:
    #     logging.info(response.text)
    assert response.status_code == 200


def test_logout():
    test_client = app().test_client()
    response = test_client.post("/adfs/oauth2/logout?post_logout_redirect_uri=http://test/api/logout")
    # if response.status_code != 302:
    #     logging.info(response.text)
    assert response.status_code == 302

    test_client = app().test_client()
    response = test_client.get("/adfs/oauth2/v2.0/logout?post_logout_redirect_uri=http://test/api/logout")
    # if response.status_code != 302:
    #     logging.info(response.text)
    assert response.status_code == 302


def test_discover_keys():
    test_client = app().test_client()
    response = test_client.get("/adfs/discovery/keys")
    assert response.status_code == 200


def test_openid_configuration():
    test_client = app().test_client()
    response = test_client.get("/adfs/.well-known/openid-configuration")
    # if response.status_code != 200:
    #     logging.info(response.text)
    assert response.status_code == 200


def test_get_authorize():
    scope = "openid profile"
    response_type = "code"
    client_id = "ID_12345"
    resource_uri = "TEST:URI:RS-104134-21171-test-api"
    redirect_url = "http://test/api/handleAccessToken"
    nonce = uuid4().hex
    state = secrets.token_hex()
    auth_url = "/adfs/oauth2/authorize?"
    auth_url += "scope={}&response_type={}&client_id={}&resource={}&redirect_uri={}&state={}&nonce={}".format(
        scope, response_type, client_id, resource_uri, redirect_url, state, nonce
    )
    test_client = app().test_client()
    response = test_client.get(auth_url)
    assert response.status_code == 200





def test_authorize_code_and_fetch_token(client):
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
    domain = "my-domain"
    username = "my-name"
    domain_username = f"{username}@{domain}"
    secret = "very long dev reminder"
    data = {
        "grant_type": "password",
        "client_id": client_id,
        "resource": resource_uri,
        "UserName": domain_username,
        "Password": secret,
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'}
    response = client.post(auth_url, data=data, headers=headers)
    # if response.status_code != 302:
    #     logging.info(response.text)
    assert response.status_code == 302

    query = urlparse(response.location).query
    query_items: List[tuple[str, str]] = \
        [(item.split("=", 1)[0], item.split("=", 1)[1]) for item in [part for part in query.split("&")]]
    query_params = dict(query_items)

    token_url = "/adfs/oauth2/token"
    data = {
        "grant_type": "authorization_code",
        "code": query_params["code"],
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'}
    response = client.post(token_url, data=data, headers=headers)
    # if response.status_code != 200:
    #     logging.info(response.text)
    assert response.status_code == 200


def test_post_authorize_token(client):
    scope = "openid profile"
    response_type = "token"
    client_id = "ID_12345"
    resource_uri = "TEST:URI:RS-104134-21171-test-api"
    redirect_url = "http://test/api/handleAccessToken"
    auth_url = "/adfs/oauth2/authorize?"
    auth_url += "scope={}&response_type={}&client_id={}&resource={}&redirect_uri={}".format(
        scope, response_type, client_id, resource_uri, redirect_url
    )
    domain = "my-domain"
    username = "my-name"
    domain_username = f"{username}@{domain}"
    secret = "very long dev reminder"
    kmsi = ""

    data = {
        "grant_type": "password",
        "client_id": client_id,
        "resource": resource_uri,
        "UserName": domain_username,
        "Password": secret,
        "Kmsi": kmsi,
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'}
    response = client.post(auth_url, data=data, headers=headers)
    assert response.status_code == 200


def test_post_get_token_with_password(client):
    scope = "openid profile"
    client_id = "ID_12345"
    resource_uri = "TEST:URI:RS-104134-21171-test-api"
    response_type = "token"
    redirect_url = "http://test/api/handleAccessToken"
    auth_url = "/adfs/oauth2/authorize?"
    auth_url += "scope={}&response_type={}&client_id={}&resource={}&redirect_uri={}".format(
        scope, response_type, client_id, resource_uri, redirect_url
    )
    domain = "my-domain"
    username = "my-name"
    domain_username = f"{username}@{domain}"
    secret = "very long dev reminder"
    kmsi = ""

    data = {
        "grant_type": "password",
        "client_id": client_id,
        "resource": resource_uri,
        "UserName": domain_username,
        "Password": secret,
        "Kmsi": kmsi,
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'}
    response = client.post(auth_url, data=data, headers=headers)
    assert response.status_code == 200

    nonce = uuid4().hex
    token_url = "/adfs/oauth2/token"
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
    assert response.status_code == 200


def run_authorize_code_offline_access(client, user_code):
    response_type = "code"
    client_id = "ID_12345"

    # testing passing in resource in scope for openapi / azure compatibility
    resource_uri = "TEST:URI:RS-104134-21171-test-api"
    scope = f"openid profile offline_access {resource_uri}"

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
        "UserName": domain_username,
        "Password": secret,
        "CodeChallenge": user_code
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'}
    response = client.post(auth_url, data=data, headers=headers)
    return response


def test_device_code_flow(client):

    scope = "openid profile"
    client_id = "ID_12345"
    resource_uri = "TEST:URI:RS-104134-21171-test-api"
    data = {
        "client_id": client_id,
        "scope": scope,
        "resource": resource_uri,
    }
    devicecode_url = "/adfs/oauth2/devicecode"
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'}
    response = client.post(devicecode_url, data=data, headers=headers)
    assert response.status_code == 200
    devicecode_response = json.loads(response.text)

    # Test invalid token
    token_url = "/adfs/oauth2/token"
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": client_id,
        "device_code": "BadCode",
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'}
    response = client.post(token_url, data=data, headers=headers)
    assert response.status_code == 200
    token_response = json.loads(response.text)
    assert token_response["error"] == "bad_verification_code"

    # Test pending token
    token_url = "/adfs/oauth2/token"
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": client_id,
        "device_code": devicecode_response["device_code"],
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'}
    response = client.post(token_url, data=data, headers=headers)
    assert response.status_code == 200
    token_response = json.loads(response.text)
    assert token_response["error"] == "authorization_pending"

    # Authenticate with user_code
    response = run_authorize_code_offline_access(client, devicecode_response["user_code"])
    assert response.status_code == 200
    assert "User successfully authenticated" in response.text


# Test valid token
    token_url = "/adfs/oauth2/token"
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": client_id,
        "device_code": devicecode_response["device_code"],
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'}
    response = client.post(token_url, data=data, headers=headers)
    assert response.status_code == 200
    token_response = json.loads(response.text)
    assert "access_token" in token_response

    # second authorise try must fail
    response = run_authorize_code_offline_access(client, devicecode_response["user_code"])
    assert response.status_code == 500

