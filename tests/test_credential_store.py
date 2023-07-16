import pytest

from openid_whisperer.utils.credential_store import UserCredentialStore
from openid_whisperer.utils.user_info_ext import UserInfoFakerExtension


@pytest.fixture
def credential_store():
    store = UserCredentialStore()
    yield store


def test_authorisation_code(input_scenario_one, credential_store):
    assert credential_store.authenticate(
        input_scenario_one["tenant"],
        input_scenario_one["username"],
        input_scenario_one["password"],
    )


def test_login_attempts(input_scenario_one):
    validate_users = False
    json_users = None
    session_expiry_seconds = 0
    maximum_login_attempts = 0
    credential_store = UserCredentialStore(
        validate_users=validate_users,
        json_users=json_users,
        session_expiry_seconds=session_expiry_seconds,
        maximum_login_attempts=maximum_login_attempts
    )

    username = "bbb"
    all_scope = "profile address phone email"
    user_info_claims = credential_store.get_user_scope_claims(username=username, scope=all_scope)
    auth_result = credential_store.authenticate(
        tenant=input_scenario_one["tenant"],
        username=username,
        password=None,
    )
    assert auth_result is False
    auth_result = credential_store.authenticate(
        tenant=input_scenario_one["tenant"],
        username=username,
        password=input_scenario_one["password"],
    )
    assert auth_result


def test_validating_login_attempts(input_scenario_one):

    session_expiry_seconds = 0
    maximum_login_attempts = 0
    validate_users = True

    credential_store = UserCredentialStore(
        validate_users=validate_users,
        session_expiry_seconds=session_expiry_seconds,
        maximum_login_attempts=maximum_login_attempts
    )
    username = "bbb"
    all_scope = "profile address phone email"

    auth_result = credential_store.authenticate(
        tenant=input_scenario_one["tenant"],
        username=username,
        password=input_scenario_one["password"],
    )
    assert auth_result is False

    faker_extension = UserInfoFakerExtension()
    fake_info = faker_extension.get_user_claims(username=username, scope=all_scope)

    result = credential_store.update_user_scope_claims(username=username, user_claims=fake_info)
    assert result is False

    result = credential_store.add_user_scope_claims(username=username, user_claims=fake_info)
    assert result is True

    result = credential_store.update_user_scope_claims(username=username, user_claims=fake_info)
    assert result is True

    result = credential_store.add_user_scope_claims(username=username, user_claims=fake_info)
    assert result is False

    auth_result = credential_store.authenticate(
        tenant=input_scenario_one["tenant"],
        username=username,
        password=input_scenario_one["password"],
    )
    assert auth_result is True


def test_authentication_failures(input_scenario_one):

    maximum_login_attempts = 3
    validate_users = True

    credential_store = UserCredentialStore(
        validate_users=validate_users,
        maximum_login_attempts=maximum_login_attempts
    )
    username = "bbb"
    all_scope = "profile address phone email"

    faker_extension = UserInfoFakerExtension()
    fake_info = faker_extension.get_user_claims(username=username, scope=all_scope)

    result = credential_store.add_user_scope_claims(username=username, user_claims=fake_info)
    assert result is True

    # User no exists and should be able to authenticate when providing a set of valid credentials
    auth_result = credential_store.authenticate(
        tenant=input_scenario_one["tenant"],
        username=username,
        password=input_scenario_one["password"],
    )
    assert auth_result is True

    for _ in range(maximum_login_attempts):
        auth_result = credential_store.authenticate(
            tenant=input_scenario_one["tenant"],
            username=username,
            password="",
        )
        assert auth_result is False

    # After 3 failed login attempts the user should be allowed not further attempts even with valid credentials
    auth_result = credential_store.authenticate(
        tenant=input_scenario_one["tenant"],
        username=username,
        password=input_scenario_one["password"],
    )
    assert auth_result is False


