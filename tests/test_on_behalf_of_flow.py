

def test_on_behalf_request(client, openid_api, input_scenario_one):

    end_user_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUz...."
    token_url = "/adfs/oauth2/token"
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "client_id": input_scenario_one["client_id"],
        "client_secret": "sampleCredentials",
        "assertion": end_user_token,
        "requested_token_use": "on_behalf_of",
        "scope": input_scenario_one["scope"],
        "resource": input_scenario_one["resource"],
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    response = client.post(token_url, data=data, headers=headers)
    print(response.text)
    assert response.status_code == 403

