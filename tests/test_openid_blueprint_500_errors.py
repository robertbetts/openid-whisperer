import secrets
import pytest


def test_get_authorize_500_error(client, scenario_api_a, broken_openid_api):
    """Use broken openid_interface to force unhandled runtime exception"""
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
    assert "Internal Server Error" in response.text
    assert response.status_code == 500


def test_post_authorize_500_error(client, scenario_api_a, broken_openid_api):
    """Use broken openid_interface to force unhandled runtime exception"""

    auth_url = "/adfs/oauth2/authorize"
    data = {
        "response_type": "code",
        "response_mode": "query",
        "client_id": scenario_api_a["client_id"],
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    response = client.post(auth_url, data=data, headers=headers)
    assert "broken_validate_client" in response.location
    assert response.status_code == 302


def test_post_token_500_error(client, scenario_api_a, broken_openid_api):
    """Use broken openid_interface to force unhandled runtime exception"""

    api_url = "/adfs/oauth2/token"
    data = {
        "grant_type": "password",
        "client_id": scenario_api_a["client_id"],
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    response = client.post(api_url, data=data, headers=headers)
    result = response.json
    assert "server_error" in result["error"]
    assert response.status_code == 500


def test_post_userinfo_500_error(client, scenario_api_a, broken_openid_api):
    """Use broken openid_interface to force unhandled runtime exception"""

    api_url = "/adfs/oauth2/userinfo"
    data = {
        "client_id": scenario_api_a["client_id"],
        "client_secret": scenario_api_a["client_secret"],
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    response = client.post(api_url, data=data, headers=headers)
    result = response.json
    assert "server_error" in result["error"]
    assert response.status_code == 500


def test_post_devicecode_500_error(client, scenario_api_a, broken_openid_api):
    """Use broken openid_interface to force unhandled runtime exception"""

    api_url = "/adfs/oauth2/devicecode"
    data = {
        "client_id": scenario_api_a["client_id"],
        "client_secret": scenario_api_a["client_secret"],
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    response = client.post(api_url, data=data, headers=headers)
    result = response.json
    assert "server_error" in result["error"]
    assert response.status_code == 500


def test_post_logout_500_error(client, scenario_api_a, broken_openid_api):
    """Use broken openid_interface to force unhandled runtime exception"""

    api_url = "/adfs/oauth2/logout"
    data = {
        "client_id": scenario_api_a["client_id"],
        "client_secret": scenario_api_a["client_secret"],
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    response = client.post(api_url, data=data, headers=headers)
    result = response.json
    assert "server_error" in result["error"]
    assert response.status_code == 500


def test_get_logout_500_error(client, scenario_api_a, broken_openid_api):
    client_id = scenario_api_a["client_id"]
    response = client.get(
        f"/adfs/oauth2/logout?client_id={client_id}post_logout_redirect_uri=http://test/api/logout"
    )
    assert response.status_code == 500


def test_get_keys_500_error(client, scenario_api_a, broken_openid_api):
    response = client.get("/adfs/discovery/keys")

    assert response.status_code == 500
