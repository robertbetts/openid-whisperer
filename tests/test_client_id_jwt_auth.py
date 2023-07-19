import json
from uuid import uuid4

from openid_whisperer.utils.common import generate_s256_hash


def test_create_client_secret_token(openid_api):
    """ Happy path test the TokenIssuerCertificateStore features for creating and validating client secret JWTs

    Creating a client secret JWT is used for upstream identity providers and decoding client secret JWT's
    for validating incoming client requests.
    """

    identity_provider_id = "ip_name"
    id_client_id = "client_id"
    token_expiry = 600  # 10 minutes
    token_endpoint_url = "https://idp/oauth/token"
    token_id = uuid4().hex
    token_algorithm = "HS256"

    client_key_info = {
        "key_id": uuid4().hex,
        "key_issuer": id_client_id,
        "algorithm": token_algorithm
    }
    client_key_info["public_key"] = generate_s256_hash(json.dumps(client_key_info))

    openid_api.token_store.add_client_secret(client_id=id_client_id, **client_key_info)

    assert_claims = {
        "jti": token_id,
        "sub": id_client_id,
        "iss": id_client_id,
        "aud": token_endpoint_url,
    }

    token_response = openid_api.token_store.create_client_secret_token(
        identity_provider_id=identity_provider_id,
        ip_client_id=id_client_id,
        client_secret=client_key_info["public_key"],
        token_endpoint_url=token_endpoint_url,
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

