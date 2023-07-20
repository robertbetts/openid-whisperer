import json


def end_user_authorise_post(
    client, user_code, response_type, client_id, scope, resource, username, password
):
    data = {
        "response_type": response_type,
        "client_id": client_id,
        "scope": scope,
        "resource": resource,
        "UserName": username,
        "Password": password,
        "CodeChallenge": user_code,
        "code_challenge_method": "plain",
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    response = client.post("/adfs/oauth2/authorize", data=data, headers=headers)
    return response


def test_device_code_flow(app, scenario_api_a):
    client = app.test_client()

    data = {
        "client_id": scenario_api_a["client_id"],
        "scope": scenario_api_a["scope"],
        "resource": scenario_api_a["resource"],
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
        "client_id": scenario_api_a["client_id"],
        "device_code": "BadCode",
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    response = client.post(token_url, data=data, headers=headers)
    assert response.status_code == 403
    token_response = json.loads(response.text)
    # TODO: double check the error below
    assert token_response["error"] == "devicecode_authorization_pending"

    # Test pending token
    response_type = "code"
    auth_end_point = "/adfs/oauth2/token"
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": scenario_api_a["client_id"],
        "device_code": devicecode_response["device_code"],
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    response = client.post(token_url, data=data, headers=headers)
    assert response.status_code == 403
    token_response = json.loads(response.text)
    assert token_response["error"] == "devicecode_authorization_pending"

    # Authenticate with user_code
    response = end_user_authorise_post(
        client,
        user_code=devicecode_response["user_code"],
        response_type=response_type,
        client_id=scenario_api_a["client_id"],
        username=scenario_api_a["username"],
        password=scenario_api_a["password"],
        resource=scenario_api_a["resource"],
        scope=scenario_api_a["scope"],
    )
    assert "Success, you have validated the user code provided to you." in response.text
    assert "text/html" in response.content_type
    assert response.status_code == 200

    print(devicecode_response)
    # Test valid token
    token_url = "/adfs/oauth2/token"
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": scenario_api_a["client_id"],
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
    auth_end_point = "adfs/oauth2/authorize"
    response = end_user_authorise_post(
        client=client,
        user_code=devicecode_response["user_code"],
        response_type=response_type,
        client_id=scenario_api_a["client_id"],
        username=scenario_api_a["username"],
        password=scenario_api_a["password"],
        resource=scenario_api_a["resource"],
        scope=scenario_api_a["scope"],
    )
    assert response.status_code == 403
