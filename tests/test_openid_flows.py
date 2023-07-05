import json
from uuid import uuid4
import secrets
from urllib.parse import urlparse
from typing import List
from openid_whisperer.main import app


def test_userinfo_call():
    test_client = app().test_client()
    response = test_client.post("/adfs/oauth2/userinfo")
    assert response.status_code == 200


def test_devicecode_call():
    test_client = app().test_client()
    response = test_client.post("/adfs/oauth2/devicecode")
    assert response.status_code == 403
    assert response.json["error"] == "bad_devicecode_request"


def test_logout_call():
    test_client = app().test_client()
    response = test_client.get(
        "/adfs/oauth2/logout?post_logout_redirect_uri=http://test/api/logout"
    )
    assert response.status_code == 302
    response = test_client.post(
        "/adfs/oauth2/logout?post_logout_redirect_uri=http://test/api/logout"
    )
    assert response.status_code == 302

    test_client = app().test_client()
    response = test_client.get(
        "/adfs/oauth2/v2.0/logout?post_logout_redirect_uri=http://test/api/logout"
    )
    assert response.status_code == 302
    response = test_client.post(
        "/adfs/oauth2/v2.0/logout?post_logout_redirect_uri=http://test/api/logout"
    )
    assert response.status_code == 302


def test_discover_keys_call():
    test_client = app().test_client()
    response = test_client.get("/adfs/discovery/keys")
    assert response.status_code == 200


def test_openid_configuration_call():
    test_client = app().test_client()
    response = test_client.get("/adfs/.well-known/openid-configuration")
    assert response.status_code == 200


def test_authorize_get_call():
    scope = "openid profile"
    response_type = "code"
    client_id = "ID_12345"
    resource_uri = "TEST:URI:RS-104134-21171-test-api"
    redirect_uri = "http://test/api/handleAccessToken"
    nonce = uuid4().hex
    state = secrets.token_hex()
    auth_url = (
        f"/adfs/oauth2/authorize?scope={scope}&response_type={response_type}&client_id={client_id}"
        f"&resource={resource_uri}&redirect_uri={redirect_uri}&state={state}&nonce={nonce}"
    )
    test_client = app().test_client()
    response = test_client.get(auth_url)
    assert response.status_code == 200


def test_authorize_code_and_fetch_token_flow(client):
    scope = "openid profile"
    response_type = "code"
    client_id = "ID_12345"
    resource_uri = "TEST:URI:RS-104134-21171-test-api"
    redirect_uri = "http://test/api/handleAccessToken"
    nonce = uuid4().hex
    state = secrets.token_hex()
    auth_url = f"/adfs/oauth2/authorize"
    domain = "my-domain"
    username = "my-name"
    domain_username = f"{username}@{domain}"
    secret = "very long dev reminder"
    data = {
        "response_type": response_type,
        "grant_type": "password",
        "client_id": client_id,
        "scope": scope,
        "resource": resource_uri,
        "UserName": domain_username,
        "Password": secret,
        "nonce": nonce,
        "state": state,
        "redirect_uri": redirect_uri,
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    response = client.post(auth_url, data=data, headers=headers)
    if response.status_code != 302:
        print(response.text)
    assert response.status_code == 302
    assert "code" in response.location
    print(response.location)
    query = urlparse(response.location).query
    query_items: List[tuple[str, str]] = [
        (item.split("=", 1)[0], item.split("=", 1)[1])
        for item in [part for part in query.split("&")]
    ]
    query_params = dict(query_items)

    token_url = "/adfs/oauth2/token"
    data = {
        "grant_type": "authorization_code",
        "code": query_params["code"],
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    response = client.post(token_url, data=data, headers=headers)
    print(response.text)
    assert response.status_code == 200


def test_authorize_token_flow(client):
    response_type = "token id_token"
    client_id = "ID_12345"
    scope = "openid profile"
    resource = "TEST:URI:RS-104134-21171-test-api"
    auth_url = "/adfs/oauth2/authorize"
    domain = "my-domain"
    username = "my-name"
    domain_username = f"{username}@{domain}"
    secret = "very long dev reminder"
    kmsi = ""
    nonce = uuid4().hex

    data = {
        "response_type": response_type,
        "grant_type": "password",
        "client_id": client_id,
        "scope": scope,
        "resource": resource,
        "UserName": domain_username,
        "Password": secret,
        "Kmsi": kmsi,
        "nonce": nonce,
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    response = client.post(auth_url, data=data, headers=headers)
    if response.status_code != 200:
        print(response.text)
    assert response.status_code == 200


def test_fetch_token_with_password_flow(client):
    response_type = "token id_token"
    client_id = "ID_12345"
    scope = "openid profile"
    resource = "TEST:URI:RS-104134-21171-test-api"
    auth_url = "/adfs/oauth2/authorize"
    domain = "my-domain"
    username = "my-name"
    domain_username = f"{username}@{domain}"
    secret = "very long dev reminder"
    kmsi = ""
    nonce = uuid4().hex

    data = {
        "response_type": response_type,
        "grant_type": "password",
        "client_id": client_id,
        "resource": resource,
        "UserName": domain_username,
        "Password": secret,
        "nonce": nonce,
        "Kmsi": kmsi,
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    response = client.post(auth_url, data=data, headers=headers)
    if response.status_code != 200:
        print(response.text)
    assert response.status_code == 200

    token_url = "/adfs/oauth2/token"
    data = {
        "grant_type": "password",
        "username": domain_username,
        "password": secret,
        "nonce": nonce,
        "scope": scope,
        "client_id": client_id,
        "resource": resource,
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    response = client.post(token_url, data=data, headers=headers)
    assert response.status_code == 200


