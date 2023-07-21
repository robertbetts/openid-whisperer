"""
Upon successful validation of the Refresh Token, the response body is the Token Response of Section 3.1.3.3 except that it might not contain an id_token.

If an ID Token is returned as a result of a token refresh request, the following requirements apply:

its iss Claim Value MUST be the same as in the ID Token issued when the original authentication occurred,
its sub Claim Value MUST be the same as in the ID Token issued when the original authentication occurred,
its iat Claim MUST represent the time that the new ID Token is issued,
its aud Claim Value MUST be the same as in the ID Token issued when the original authentication occurred,
if the ID Token contains an auth_time Claim, its value MUST represent the time of the original authentication - not the time that the new ID token is issued,
its azp Claim Value MUST be the same as in the ID Token issued when the original authentication occurred; if no azp Claim was present in the original ID Token, one MUST NOT be present in the new ID Token, and
otherwise, the same rules apply as apply when issuing an ID Token at the time of the original authentication.


POST /token HTTP/1.1
  Host: server.example.com
  Content-Type: application/x-www-form-urlencoded

  client_id=s6BhdRkqt3
    &client_secret=some_secret12345
    &grant_type=refresh_token
    &refresh_token=8xLOxBtZp8
    &scope=openid%20profile


  HTTP/1.1 200 OK
  Content-Type: application/json
  Cache-Control: no-store
  Pragma: no-cache

  {
   "access_token": "TlBN45jURg",
   "token_type": "Bearer",
   "refresh_token": "9yNOxJtZa5",
   "expires_in": 3600
  }
"""

post_headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "application/json",
}
import jwt


def test_blueprint_token_refresh(openid_api, client, scenario_api_a):
    """Happy path for testing token refresh.

    Fetch an initial token and then use that to request a refresh
    """
    data = {
        "grant_type": "password",
        "client_id": scenario_api_a["client_id"],
        "client_secret": scenario_api_a["client_secret"],
        "scope": scenario_api_a["scope"],
        "resource": scenario_api_a["resource"],
        "username": scenario_api_a["username"],
        "password": scenario_api_a["password"],
        "nonce": scenario_api_a["nonce"],
    }
    auth_url = "/adfs/oauth2/token"
    response = client.post(auth_url, data=data, headers=post_headers)
    assert response.status_code == 200
    print(response.text)
    access_token = response.json["access_token"]
    refresh_token = response.json["refresh_token"]
    claims = jwt.decode(access_token, options={"verify_signature": False})

    # Request refresh token
    data = {
        "client_id": scenario_api_a["client_id"],
        "client_secret": scenario_api_a["client_secret"],
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }
    token_url = "/adfs/oauth2/token"
    response = client.post(token_url, data=data, headers=post_headers)
    print(response.text)
    assert response.status_code == 200
    access_token = response.json["access_token"]
    refresh_claims = jwt.decode(access_token, options={"verify_signature": False})
    print(refresh_claims)
    assert refresh_claims["sub"] == claims["sub"]
    assert refresh_claims["iss"] == claims["iss"]
    assert refresh_claims["aud"] == claims["aud"]
    assert refresh_claims["auth_time"] == claims["auth_time"]
    assert refresh_claims["exp"] >= claims["exp"]
    assert refresh_claims["iat"] >= claims["iat"]

