from uuid import uuid4
import secrets
from urllib.parse import urlparse
from typing import List
from openid_whisperer.main import app


def test_userinfo_call(client, input_scenario_one):
    response = client.post("/adfs/oauth2/userinfo")
    assert response.status_code == 403

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    data = {
        "client_id": input_scenario_one["client_id"],
        "username": input_scenario_one["username"],
    }
    response = client.post(
        "/adfs/oauth2/userinfo",
        data=data,
        headers=headers,
    )
    assert isinstance(response.json, dict)
    assert response.status_code == 200


def test_devicecode_call(client):
    response = client.post("/adfs/oauth2/devicecode")
    print(response.text)
    assert response.json["error_code"] == "auth_processing_error"
    assert response.status_code == 403


def test_logout_call(client, input_scenario_one):
    client_id = input_scenario_one["client_id"]
    username = input_scenario_one["username"]

    response = client.get(
        f"/adfs/oauth2/logout?client_id={client_id}&username={username}&post_logout_redirect_uri=http://test/api/logout"
    )
    assert response.status_code == 302

    response = client.get(
        f"/adfs/oauth2/v2.0/logout?client_id={client_id}&username={username}&post_logout_redirect_uri=http://test/api/logout"
    )
    assert response.status_code == 302

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    data = {
        "client_id": client_id,
        "username": username,
    }
    response = client.post(
        "/adfs/oauth2/logout",
        data=data,
        headers=headers,
    )
    result = response.json
    assert result == {}
    assert response.status_code == 200

    response = client.post(
        "/adfs/oauth2/v2.0/logout",
        data=data,
        headers=headers,
    )
    result = response.json
    assert result == {}
    assert response.status_code == 200


def test_discover_keys_call():
    test_client = app().test_client()
    response = test_client.get("/adfs/discovery/keys")
    assert response.status_code == 200


def test_openid_configuration_call():
    test_client = app().test_client()
    response = test_client.get("/adfs/.well-known/openid-configuration")
    assert response.status_code == 200


def test_post_authorize_kmsi_with_code(client, input_scenario_one):
    response_type = "code"
    redirect_uri = "http://test/api/handleAccessToken"
    state = secrets.token_hex()
    auth_url = f"/adfs/oauth2/authorize"
    data = {
        "response_type": response_type,
        "grant_type": "password",
        "client_id": input_scenario_one["client_id"],
        "scope": input_scenario_one["scope"],
        "resource": input_scenario_one["resource"],
        "UserName": input_scenario_one["username"],
        "Password": input_scenario_one["password"],
        "Kmsi": "1",
        "nonce": input_scenario_one["nonce"],
        "state": state,
        "redirect_uri": redirect_uri,
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    response = client.post(auth_url, data=data, headers=headers)
    assert response.status_code == 302

    # cookie_header = response.headers['Set-Cookie']
    assert (
        f"openid-whisperer-token-{input_scenario_one['client_id']}"
        in response.headers.get("Set-Cookie")
    )


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


def test_authorize_code_and_fetch_token_flow(client, input_scenario_one):
    response_type = "code"
    redirect_uri = "http://test/api/handleAccessToken"
    state = secrets.token_hex()
    auth_url = f"/adfs/oauth2/authorize"
    data = {
        "response_type": response_type,
        "grant_type": "password",
        "client_id": input_scenario_one["client_id"],
        "scope": input_scenario_one["scope"],
        "resource": input_scenario_one["resource"],
        "UserName": input_scenario_one["username"],
        "Password": input_scenario_one["password"],
        "nonce": input_scenario_one["nonce"],
        "state": state,
        "redirect_uri": redirect_uri,
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    response = client.post(auth_url, data=data, headers=headers)
    if response.status_code != 302:
        print(response.text)  # pragma: no cover
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
        "client_id": input_scenario_one["client_id"],
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
        print(response.text)  # pragma: no cover
    assert response.status_code == 200


def test_fetch_token_with_password_flow(client, input_scenario_one):
    response_type = "token id_token"
    auth_url = "/adfs/oauth2/authorize"

    data = {
        "response_type": response_type,
        "grant_type": "password",
        "client_id": input_scenario_one["client_id"],
        "scope": input_scenario_one["scope"],
        "resource": input_scenario_one["resource"],
        "UserName": input_scenario_one["username"],
        "Password": input_scenario_one["password"],
        "nonce": input_scenario_one["nonce"],
        "Kmsi": input_scenario_one["kmsi"],
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    response = client.post(auth_url, data=data, headers=headers)
    if response.status_code != 200:
        print(response.text)  # pragma: no cover
    assert response.status_code == 200

    token_url = "/adfs/oauth2/token"
    data = {
        "grant_type": "password",
        "username": input_scenario_one["username"],
        "password": input_scenario_one["password"],
        "nonce": input_scenario_one["nonce"],
        "scope": input_scenario_one["scope"],
        "client_id": input_scenario_one["client_id"],
        "resource": input_scenario_one["resource"],
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    response = client.post(token_url, data=data, headers=headers)
    assert response.status_code == 200
