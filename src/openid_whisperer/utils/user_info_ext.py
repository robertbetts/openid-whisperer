import logging
from typing import Dict, Any, List
from abc import ABCMeta, abstractmethod
import random

try:
    import faker
except ModuleNotFoundError:
    faker = None

from openid_whisperer.utils.common import get_now_seconds_epoch

logger = logging.getLogger(__name__)


class UserInfoExtensionTemplate(metaclass=ABCMeta):
    @abstractmethod
    def scope_claims(self, scope: str | None = None) -> List[str]:
        ...

    @abstractmethod
    def update_user_claims(self, username: str, user_claims: Dict[str, Any]) -> None:
        ...

    @abstractmethod
    def get_user_claims(
        self, username: str, scope: str, including_empty: bool = False
    ) -> dict[str, Any]:
        ...


OPENID_CLAIMS: List[str] = [
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


class UserInfoExtension(UserInfoExtensionTemplate):
    def __init__(self) -> None:
        self._user_info: Dict[str, Any] = {}

    def scope_claims(self, scope: str | None = None) -> List[str]:
        _ = scope
        return OPENID_CLAIMS

    def update_user_claims(self, username: str, user_claims: Dict[str, Any]) -> None:
        """Update existing user claim information. begin with existing info and only update those claims
        provided in user_claims where the claim is present in OPENID_CLAIMS

        :param username:
        :param user_claims:
        :return: None
        """
        updated_claims = self._user_info.get(username, {})
        updated_claims.update(
            dict(
                [
                    (key, value)
                    for key, value in user_claims.items()
                    if key in OPENID_CLAIMS
                ]
            )
        )
        updated_claims["updated_at"] = get_now_seconds_epoch()
        self._user_info[username] = updated_claims

    def get_user_claims(
        self, username: str, scope: str, including_empty: bool = False
    ) -> Dict[str, Dict[str, Any]]:
        """Searches the input username and returns a set of compliant ida claims

        :param username:  username in format SID or SID@DOMAIN (0728000@EMEA)
        :param scope: Indicates set of claims returned in addition to the audience attached to a token request
        :param including_empty: when True include empty claim values
        :return: dictionary of claims
        """
        username_parts = username.split("@")
        if len(username_parts) == 1:
            uid = username
            domain = ""
        else:
            uid = username_parts[0]
            domain = username_parts[1]

        if username in self._user_info:
            user_data = self._user_info[username]
        else:
            user_data = {
                "name": uid,
                "family_name": "",
                "given_name": "",
                "middle_name": "",
                "nickname": uid,
                "preferred_username": uid,
                "profile": "",
                "picture": "",
                "website": "",
                "gender": "",
                "birthdate": "",
                "zoneinfo": "",
                "locale": "",
                "updated_at": get_now_seconds_epoch(),
                "email": f"{uid}@mock-company.com",
                "email_verified": False,
                "address": domain,
                "phone_number": "",
                "phone_number_verified": False,
            }
            self._user_info[username] = dict(
                [
                    (key, value)
                    for key, value in user_data.items()
                    if (including_empty is True) or (value != "")
                ]
            )
        return user_data


class UserInfoFakerExtension(UserInfoExtension):
    def __new__(cls, *args: List[Any], **kwargs: dict[str, Any]) -> Any:
        if faker is None:
            logger.warning(
                "Faker package not available, defaulting the extension to the default, UserInfoExtension."
            )
            return UserInfoExtension()
        else:
            return super().__new__(cls)

    def __init__(self) -> None:
        self._user_info: Dict[str, Any] = {}
        self.faker = faker.Faker()

    def get_user_claims(
        self, username: str, scope: str, including_empty: bool = False
    ) -> Dict[str, Dict[str, Any]]:
        """Searches the input username and returns a set of compliant ida claims

        :param username:  username in format SID or SID@DOMAIN (0728000@EMEA)
        :param scope: Indicates set of claims returned in addition to the audience attached to a token request
        :param including_empty: when True include empty claim values
        :return: dictionary of claims
        """
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
            names = name.split(" ")
            given_name = names[0]
            family_name = names[-1]
            if len(names) >= 3:
                middle_name = names[1]
            else:
                middle_name = random.choice(
                    [self.faker.first_name(), self.faker.last_name()]
                )
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
                "birthdate": self.faker.date_of_birth(minimum_age=16).isoformat(),
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


if __name__ == "__main__":  # pragma: no cover
    userdb = UserInfoFakerExtension()
    user_info = userdb.get_user_claims("o123456", "openid profile")
    from pprint import pformat

    print(pformat(user_info))
