import json


def end_user_authorise_post(client, user_code, response_type, client_id, scope, resource, username, password):
    data = {
        "response_type": response_type,
        "client_id": client_id,
        "scope": scope,
        "resource": resource,
        "UserName": username,
        "Password": password,
        "code_challenge_method": "plan",
        "CodeChallenge": user_code,
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    response = client.post("/adfs/oauth2/authorize", data=data, headers=headers)
    return response


def test_device_code_flow(app):

    client = app.test_client()

    client_id = "ID_12345"
    scope = f"openid profile offline_access"
    resource = "TEST:URI:RS-104134-21171-test-api"
    data = {
        "client_id": client_id,
        "scope": scope,
        "resource": resource,
    }
    devicecode_url = "/adfs/oauth2/devicecode"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
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
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    response = client.post(token_url, data=data, headers=headers)
    assert response.status_code == 403
    token_response = json.loads(response.text)
    assert token_response["error"] == "bad_verification_code"

    # Test pending token
    response_type = "code"
    domain = "my-domain"
    user = "my-name"
    username = f"{user}@{domain}"
    password = "very long dev reminder"
    auth_end_point = "/adfs/oauth2/token"
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": client_id,
        "device_code": devicecode_response["device_code"],
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    response = client.post(token_url, data=data, headers=headers)
    assert response.status_code == 403
    token_response = json.loads(response.text)
    assert token_response["error"] == "authorization_pending"

    # Authenticate with user_code
    response = end_user_authorise_post(
        client,
        user_code=devicecode_response["user_code"],
        response_type=response_type,
        client_id=client_id,
        username=username,
        password=password,
        resource=resource,
        scope=scope,
    )
    assert "Success, you have validated the user code provided to you." in response.text
    assert "text/html" in response.content_type
    assert response.status_code == 200

    # Now inspect the contents of the authlib_cache to validate backend token state
    from openid_whisperer import openid_lib
    print("wait here")


    # Test valid token
    token_url = "/adfs/oauth2/token"
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": client_id,
        "device_code": devicecode_response["device_code"],
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    response = client.post(token_url, data=data, headers=headers)
    token_response = json.loads(response.text)
    assert "access_token" in token_response
    assert "application/json" in response.content_type
    assert response.status_code == 200

    # second authorise try must fail
    response_type = "code"
    domain = "my-domain"
    user = "my-name"
    username = f"{user}@{domain}"
    password = "very long dev reminder"
    auth_end_point = "adfs/oauth2/authorize"
    response = end_user_authorise_post(
        client=client,
        user_code=devicecode_response["user_code"],
        response_type=response_type,
        client_id=client_id,
        username=username,
        password=password,
        resource=resource,
        scope=scope,
        auth_end_point=auth_end_point,
    )
    assert response.status_code == 403
