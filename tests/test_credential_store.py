import pytest

from openid_whisperer.utils.credential_store import UserCredentialStore


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
