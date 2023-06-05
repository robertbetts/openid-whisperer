from uuid import uuid4
import secrets
import json

from openid_whisperer.main import app


def test_userinfo():
    test_client = app().test_client()
    response = test_client.post("/adfs/oauth2/userinfo")
    assert response.status_code == 200


def test_devicecode():
    test_client = app().test_client()
    response = test_client.post("/adfs/oauth2/devicecode")
    assert response.status_code == 200


def test_logout():
    test_client = app().test_client()
    response = test_client.post("/adfs/oauth2/logout?post_logout_redirect_uri=http://test/api/logout")
    assert response.status_code == 302

    test_client = app().test_client()
    response = test_client.get("/adfs/oauth2/v2.0/logout?post_logout_redirect_uri=http://test/api/logout")
    assert response.status_code == 302


def test_openid_configuration():
    test_client = app().test_client()
    response = test_client.get("/adfs/.well-known/openid-configuration")
    assert response.status_code == 200


def test_get_authorize():
    client_id = "ID_12345"
    resource_uri = "TEST:URI:RS-104134-21171-testapi"
    resource_uri = ""
    redirect_url = "http://test/api/handleAccessToken"
    nonce = uuid4().hex
    state = secrets.token_hex()
    auth_url = "/adfs/oauth2/authorize"
    auth_url += "?response_type=code&client_id={}&resource={}&nonce={}&redirect_uri={}&state={}&nonce={}".format(
        client_id, resource_uri, nonce, redirect_url, state, nonce
    )

    test_client = app().test_client()
    response = test_client.get(auth_url)
    assert response.status_code == 200


def test_post_authorize():
    client_id = "ID_12345"
    resource_uri = "TEST:URI:RS-104134-21171-testapi"
    # redirect_url = "http://test/api/handleAccessToken"
    # nonce = uuid4().hex
    # state = secrets.token_hex()
    auth_url = "/adfs/oauth2/authorize"
    # auth_url += "?response_type=code&client_id={}&resource={}&nonce={}&redirect_uri={}&state={}&nonce={}".format(
    #     client_id, resource_uri, nonce, redirect_url, state, nonce
    # )
    username = "username@domain"
    secret = "very long dev reminder"

    data = {
        "grant_type": "password",
        "client_id": client_id,
        "resource": resource_uri,
        "username": username,
        "password": secret,
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'}

    test_client = app().test_client()
    response = test_client.post(auth_url, data=data, headers=headers)
    assert response.status_code == 302

