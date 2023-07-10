from typing import Dict, Any, List
import random

import faker

from openid_whisperer.utils.common import get_now_seconds_epoch

USER_INFO_CLAIMS: List[str] = [
    "name",
    "family_name",
    "given_name",
    "middle_name",
    "nickname",
    "preferred_username",
    "profile",
    "picture",
    "website",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "updated_at",
    "email",
    "email_verified",
    "address",
    "phone_number",
    "phone_number_verified",
]

GENDER = ["female", "male", "non-binary"]
GENDER_WEIGHTS = [46, 44, 10]


class UserInfoExtension:
    def __init__(self):
        self._user_info: Dict[str, Any] = {}
        self.faker = faker.Faker()

    def user_info(self, username: str, scope: str):
        if username in self._user_info:
            user_data = self._user_info[username]
        else:
            gender = random.choices(population=GENDER, weights=GENDER_WEIGHTS, k=1)[0]
            match gender:
                case "female":
                    name = self.faker.name_female()
                case "mail":
                    name = self.faker.name_male()
                case _:
                    name = self.faker.name_nonbinary()
            given_name, family_name = name.split(" ")
            middle_name = random.choice([self.faker.first_name(), self.faker.last_name()])
            domain_name = self.faker.domain_name()
            user_data = {
                "name": name,
                "family_name": family_name,
                "given_name": given_name,
                "middle_name": middle_name,
                "nickname": given_name,
                "preferred_username": f"{family_name}, {given_name} {middle_name[0]}",
                "profile": "",
                "picture": "",
                "website": "",
                "gender": gender,
                "birthdate": self.faker.date_of_birth(minimum_age=16),
                "zoneinfo": "",
                "locale": "",
                "updated_at": get_now_seconds_epoch(),
                "email": f"{given_name}.{middle_name[0]}.{family_name}@{domain_name}",
                "email_verified": True,
                "address": "",
                "phone_number": self.faker.phone_number(),
                "phone_number_verified": True,
            }
            self._user_info[username] = user_data
            return user_data


if __name__ == "__main__":
    userdb = UserInfoExtension()
    user_info = userdb.user_info("o123456", "openid profile")
    from pprint import pformat
    print(pformat(user_info))
