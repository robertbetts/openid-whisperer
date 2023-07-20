import jwt
import pytest


def create_client_secret(
        openid_api,
        client_id,
        resource,
        client_algorithm,
        token_key_id,
):
    audience = [client_id, resource]
    token_response = openid_api.token_store.create_client_secret_token(
        client_id=client_id,
        client_secret=openid_api.token_store.token_issuer_private_key,
        token_endpoint_url=audience,
        token_key_id=token_key_id,
        token_expiry=60,
        token_algorithm=client_algorithm,
        token_id=token_key_id,
    )
    return token_response["token"]


# @pytest.mark.skip
def test_on_behalf_request(client, openid_api, scenario_api_a):
    """
    # 1. end-user requests token IP to access API-A

    # 2. API-A validates end-user token and requests an on-behalf token from IP to access API-B

    # 3. API-A uses new token to access API-B

    # 4. Test to see if API-B can determine that the token is an on-behalf token?

    """
    form_post_headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }

    # 1. end-user requests token IP to access API-A
    # 1.a leaving this here as need to check the response of a single token string???
    auth_url = "/adfs/oauth2/authorize"
    data = {
        "response_type": "token id_token",
        "grant_type": "password",
        "client_id": scenario_api_a["client_id"],
        "scope": scenario_api_a["scope"],
        "resource": scenario_api_a["resource"],
        "UserName": scenario_api_a["username"],
        "Password": scenario_api_a["password"],
        "nonce": scenario_api_a["nonce"],
    }
    response = client.post(auth_url, data=data, headers=form_post_headers)
    print(response.text)
    assert response.status_code == 200

    # 1.b use token password grant to fetch end user token for API-A
    token_url = "/adfs/oauth2/token"
    data = {
        "grant_type": "password",
        "username": scenario_api_a["username"],
        "password": scenario_api_a["password"],
        "nonce": scenario_api_a["nonce"],
        "scope": scenario_api_a["scope"],
        "client_id": scenario_api_a["client_id"],
        "resource": scenario_api_a["resource"],
    }
    response = client.post(token_url, data=data, headers=form_post_headers)
    data = response.json
    print(data)
    assert response.status_code == 200

    end_user_token_api_a = data["access_token"]

    # 2. API-A validates end-user token, API-A request is own token and then requests an on-behalf token from IP to access API-B
    # 2.a API-A will need to generate a secret to request it own access token

    client_assertion = scenario_api_a["client_assertion"]
    client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

    token_url = "/adfs/oauth2/token"
    data = {
        "client_id": scenario_api_a["client_id"],
        "grant_type": "client_credentials",
        "client_assertion": client_assertion,
        "client_assertion_type": client_assertion_type,
        "scope": scenario_api_a["scope"],
        "resource": scenario_api_a["resource"],
    }
    unverified_headers = jwt.get_unverified_header(client_assertion)
    unverified_claims = jwt.decode(client_assertion, options={"verify_signature": False})
    response = client.post(token_url, data=data, headers=form_post_headers)
    print(response.text)
    assert response.status_code == 200
    client_token = response.json["access_token"]
    check_claims = jwt.decode(client_token, options={"verify_signature": False})
    print(client_token)
    print(check_claims)

    # 2.b API-A will use this client_token to request an on-behalf-of token from the IP

    token_url = "/adfs/oauth2/token"
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "client_assertion": client_token,
        "client_assertion_type": "",
        "client_id": scenario_api_a["client_id"],
        "assertion": end_user_token_api_a,
        "requested_token_use": "on_behalf_of",
        "scope": scenario_api_a["scope"],
        "resource": scenario_api_a["resource"],
    }
    response = client.post(token_url, data=data, headers=form_post_headers)
    print(response.text)
    assert response.status_code == 200

    # 3. API-A uses new token to access API-B
    # 4. Test to see if API-B can determine that the token is an on-behalf token?

