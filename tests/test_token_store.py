from openid_whisperer.utils.token_store import TokenIssuerCertificateStore


def test_token_store_config(config):
    config_settings = {
        "token_expiry_seconds": 605,
        "refresh_token_expiry_seconds": 3605,
        "ca_cert_filename": config.ca_cert_filename,
        "org_key_filename": config.org_key_filename,
        "org_key_password": config.org_key_password,
        "org_cert_filename": config.org_cert_filename,
    }

    token_store = TokenIssuerCertificateStore(**config_settings)
    for key, value in config_settings.items():
        assert getattr(token_store, key) == value

    config_settings = {
        "token_expiry_seconds": None,
        "refresh_token_expiry_seconds": 0,
        "ca_cert_filename": config.ca_cert_filename,
        "org_key_filename": config.org_key_filename,
        "org_key_password": config.org_key_password,
        "org_cert_filename": config.org_cert_filename,
    }
    token_store = TokenIssuerCertificateStore(**config_settings)
    assert token_store.token_expiry_seconds == 600
    assert token_store.refresh_token_expiry_seconds == 3600

    issuer_certificate = token_store.token_issuer_certificate
    issuer_pair = token_store.token_certificates[token_store.token_issuer_key_id]
    assert issuer_certificate == issuer_pair["certificate"]

    # Test ca_cert_filename=None code path
    config_settings = {
        "ca_cert_filename": None,
        "ca_cert_filename": config.ca_cert_filename,
        "org_key_filename": config.org_key_filename,
        "org_key_password": config.org_key_password,
        "org_cert_filename": config.org_cert_filename,
    }
    token_store = TokenIssuerCertificateStore(**config_settings)


def test_token_issue_and_decode(openid_api, input_scenario_one):
    user_claims = openid_api.credential_store.get_user_scope_claims(
        username=input_scenario_one["username"],
        scope=input_scenario_one["scope"],
    )
    audience = [input_scenario_one["client_id"]]
    _, token_response = openid_api.token_store.create_new_token(
        client_id=input_scenario_one["client_id"],
        issuer=openid_api.issuer_reference,
        sub=input_scenario_one["username"],
        user_claims=user_claims,
        audience=audience,
        nonce=input_scenario_one["nonce"],
    )
    decoded_claims = openid_api.token_store.decode_token(
        token=token_response["access_token"],
        issuer=openid_api.issuer_reference,
        audience=audience,
    )
    assert isinstance(decoded_claims, dict) and len(decoded_claims) > 5
    assert decoded_claims["nonce"] == input_scenario_one["nonce"]

    assert (
        openid_api.token_store.validate_jwt_token(
            token_response["access_token"],
            token_type="token",
            issuer=openid_api.issuer_reference,
            audience=audience,
        )
        is True
    )

    assert (
        openid_api.token_store.validate_jwt_token(
            token_response["access_token"],
            token_type="token",
            issuer=openid_api.issuer_reference,
            audience=[],
        )
        is False
    )

    assert (
        openid_api.token_store.validate_jwt_token(
            token_response["access_token"],
            token_type="refresh_token",
            issuer=openid_api.issuer_reference,
            audience=audience,
        )
        is False
    )
