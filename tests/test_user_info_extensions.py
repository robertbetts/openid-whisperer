from unittest import TestCase
from openid_whisperer.openid_blueprint import register_user_info_extension
from openid_whisperer import openid_blueprint
from openid_whisperer.utils.user_info_ext import (
    UserInfoExtension,
    ALL_TOKEN_CLAIMS,
    UserInfoFakerExtension,
)


def test_extension_registrations():
    register_user_info_extension(openid_blueprint.openid_api_interface, "Faker")
    register_user_info_extension(openid_blueprint.openid_api_interface, "InvalidName")

    class CustomExtension(UserInfoExtension):
        ...

    custom_extension = CustomExtension()
    register_user_info_extension(
        openid_blueprint.openid_api_interface, custom_extension
    )


def test_scope_type_claims():
    user_info_extension = UserInfoExtension()
    scope_keys = user_info_extension.scope_claims(scope="profile address phone email")
    assert scope_keys == set(ALL_TOKEN_CLAIMS)


def test_extension_faker_user_info_requests(openid_api, scenario_api_a):
    register_user_info_extension(openid_api, "Faker")
    for _ in range(1000):
        user_info = openid_api.post_userinfo(
            tenant=scenario_api_a["tenant"],
            client_id=scenario_api_a["client_id"],
            client_secret=scenario_api_a["client_secret"],
            username=scenario_api_a["username"],
        )


def test_update_user_info_claim_date():
    username = "bbb"
    all_scope = "profile address phone email"

    user_info_extension = UserInfoExtension()
    scope_keys = user_info_extension.scope_claims(scope=all_scope)

    faker_extension = UserInfoFakerExtension()
    fake_info = faker_extension.get_user_claims(username=username, scope=all_scope)
    user_info_extension.update_user_claims(username=username, user_claims=fake_info)
    check_user_info = user_info_extension.get_user_claims(
        username=username, scope=all_scope
    )

    TestCase().assertDictEqual(check_user_info, fake_info)


def test_missing_faker_import():
    from openid_whisperer.utils import user_info_ext

    faker = user_info_ext.faker
    user_info_ext.faker = None
    faker_extension = UserInfoFakerExtension()
    try:
        assert isinstance(faker_extension, UserInfoExtension)
    finally:
        user_info_ext.faker = faker
