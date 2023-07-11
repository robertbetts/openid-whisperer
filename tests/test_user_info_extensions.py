from openid_whisperer.openid_blueprint import register_user_info_extension
from openid_whisperer import openid_blueprint
from openid_whisperer.utils.user_info_ext import UserInfoExtension


def test_extension_registrations():
    register_user_info_extension(openid_blueprint.openid_api_interface, "Faker")
    register_user_info_extension(openid_blueprint.openid_api_interface, "InvalidName")

    class CustomExtension(UserInfoExtension):
        ...

    custom_extension = CustomExtension()
    register_user_info_extension(
        openid_blueprint.openid_api_interface, custom_extension
    )


def test_extension_faker_user_info_requests(openid_api, input_scenario_one):
    register_user_info_extension(openid_api, "Faker")
    for _ in range(1000):
        user_info = openid_api.post_userinfo(
            tenant=input_scenario_one["tenant"],
            client_id=input_scenario_one["client_id"],
            client_secret=input_scenario_one["client_secret"],
            username=input_scenario_one["username"]
        )

