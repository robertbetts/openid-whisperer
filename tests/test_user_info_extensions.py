from openid_whisperer.openid_blueprint import register_user_info_extension
from openid_whisperer import openid_blueprint
from openid_whisperer.utils.user_info_ext import UserInfoExtension


def test_extension_registrations():
    register_user_info_extension(openid_blueprint.openid_api_interface, "Faker")
    register_user_info_extension(openid_blueprint.openid_api_interface, "InvalidName")

    class CustomExtension(UserInfoExtension):
        ...

    custom_extension = CustomExtension()
    register_user_info_extension(openid_blueprint.openid_api_interface, custom_extension)


