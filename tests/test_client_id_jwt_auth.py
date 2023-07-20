import json
from uuid import uuid4
import base64

import pytest

from openid_whisperer.utils.common import generate_s256_hash


def test_create_client_secret_token(openid_api):
    """Happy path test the TokenIssuerCertificateStore features for creating and validating client secret JWTs

    Creating a client secret JWT is used for upstream identity providers and decoding client secret JWT's
    for validating incoming client requests.
    """

    identity_provider_id = "ip_name"
    id_client_id = "client_id"
    token_expiry = 600  # 10 minutes
    token_endpoint_url = "https://idp/oauth/token"
    token_id = uuid4().hex
    token_algorithm = "HS256"

    token_key_id = uuid4().hex
    client_key_info = {
        "key_id": token_key_id,
        "key_issuer": id_client_id,
        "algorithm": token_algorithm,
    }
    client_key_info["public_key"] = generate_s256_hash(json.dumps(client_key_info))

    openid_api.token_store.add_client_secret(client_id=id_client_id, **client_key_info)
    with pytest.raises(KeyError) as e:
        openid_api.token_store.add_client_secret(client_id=id_client_id, **client_key_info)
    print(e)

    with pytest.raises(KeyError) as e:
        client_key_info2 = client_key_info.copy()
        client_key_info2["key_id"] = "12345"
        openid_api.token_store.add_client_secret(client_id=id_client_id, **client_key_info2)
    print(e)

    assert_claims = {
        "jti": token_id,
        "sub": id_client_id,
        "iss": id_client_id,
        "aud": token_endpoint_url,
    }

    token_response = openid_api.token_store.create_client_secret_token(
        client_id=id_client_id,
        client_secret=client_key_info["public_key"],
        token_endpoint_url=token_endpoint_url,
        token_key_id=token_key_id,
        token_expiry=token_expiry,
        token_algorithm=token_algorithm,
        token_id=token_id,
    )
    print(token_response["token"])

    validated_claims = openid_api.token_store.decode_client_secret_token(
        token=token_response["token"],
    )
    print(validated_claims)

    assert isinstance(validated_claims, dict) and len(validated_claims) > 6
    for key, value in assert_claims.items():
        assert validated_claims[key] == value


def test_grant_type_of_client_credentials(openid_api, client, scenario_api_a):

    client_id = "CLIENT-90274-DEV"
    client_algorithm = "RS256"
    resource = scenario_api_a["resource"]
    audience = [client_id, resource]
    token_key_id = "dGh1bWJwcmludF92YWx1ZQ=="

    token_response = openid_api.token_store.create_client_secret_token(
        client_id=client_id,
        client_secret=openid_api.token_store.token_issuer_private_key,
        token_endpoint_url=audience,
        token_key_id=token_key_id,
        token_expiry=60,
        token_algorithm=client_algorithm,
        token_id=token_key_id,
    )
    print(token_response["token"])

    client_assertion = token_response["token"]
    client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

    try:
        client_key_info = {
            "key_id": token_key_id,
            "key_issuer": client_id,
            "algorithm": client_algorithm,
            "public_key": openid_api.token_store.token_issuer_private_key.public_key()
        }
        openid_api.token_store.add_client_secret(client_id=client_id, **client_key_info)
    except KeyError:  # pragma: no cover
        pass

    result = openid_api.validate_client(
        client_id=client_id,
        client_secret=None,
        client_assertion=client_assertion,
        client_assertion_type=client_assertion_type,
    )

    print(result)

    token_url = "/adfs/oauth2/token"
    data = {
        "client_id": scenario_api_a["client_id"],
        "grant_type": "client_credentials",
        "client_assertion": client_assertion,
        "client_assertion_type": client_assertion_type,
        "scope": scenario_api_a["scope"],
        "resource": scenario_api_a["resource"],
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    response = client.post(token_url, data=data, headers=headers)
    print(response.text)
    assert response.status_code == 200
