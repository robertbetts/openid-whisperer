from typing import Dict, Any, List, Set
from abc import ABCMeta, abstractmethod
import random

try:
    import faker
except ModuleNotFoundError:  # pragma: no cover
    faker = None

from openid_whisperer.utils.common import get_now_seconds_epoch
from openid_whisperer.utils.common import package_get_logger

logger = package_get_logger(__name__)

SCOPE_PROFILE_CLAIMS = [
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
]
SCOPE_EMAIL_CLAIMS = ["email", "email_verified"]
SCOPE_ADDRESS_CLAIMS = ["address"]
SCOPE_PHONE_CLAIMS = ["phone_number", "phone_number_verified"]
ALL_TOKEN_CLAIMS = (
    SCOPE_PROFILE_CLAIMS
    + SCOPE_EMAIL_CLAIMS
    + SCOPE_ADDRESS_CLAIMS
    + SCOPE_PHONE_CLAIMS
)


class UserInfoExtensionTemplate(metaclass=ABCMeta):
    _user_scope_claims: List[str]

    @abstractmethod
    def scope_claims(self, scope: str | None = None) -> Set[str]:
        """Returns a list of claims keys supported for the input scope.
        :param scope: a string containing a space separated scopes.
        """

    @abstractmethod
    def update_user_claims(self, username: str, user_claims: Dict[str, Any]) -> None:
        """Returns None, the internally cached claim information for the input username is
         updated with the input user_claims. Only the supported claims fields should be allowed.
        :param username:
        :param user_claims:
        """

    def has_user_claims(self, username: str) -> bool:
        """Returns True if the username has cached user claims, else False
        :param username:
        """

    @abstractmethod
    def get_user_claims(
        self, username: str, scope: str, include_empty: bool = False
    ) -> Dict[str, Any]:
        """Returns a dictionary of user claim information for the input username. if there is
        no information for the input user, then return an empty dictionary. This method is
        requested in the CredentialStore when user_validation is enabled to test for the
        existence of an end user.

        :param username:
        :param scope: a string containing a space separated scopes.
        :param include_empty: default is False, where only non-empty claim fields are returned.
        :return:
        """


class UserInfoExtension(UserInfoExtensionTemplate):
    def __init__(self) -> None:
        self._user_scope_claims: List[str] = ALL_TOKEN_CLAIMS
        self._user_info: Dict[str, Any] = {}

    def scope_claims(self, scope: str | None = None) -> Set[str]:
        """returns a set of claim keys which is a union of all
            the keys related to all included claim scope.

        :param scope: String of space separated claim scopes
        """
        claim_keys: Set[str] = set()
        scope = scope if scope else "openid"
        for scope_item in scope.split(" "):
            scope_item = scope_item.strip()
            match scope_item:
                case "profile":
                    claim_keys.update(SCOPE_PROFILE_CLAIMS)
                case "email":
                    claim_keys.update(SCOPE_EMAIL_CLAIMS)
                case "address":
                    claim_keys.update(SCOPE_ADDRESS_CLAIMS)
                case "phone":
                    claim_keys.update(SCOPE_PHONE_CLAIMS)

        return claim_keys

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
                    if key in self._user_scope_claims
                ]
            )
        )
        updated_claims["updated_at"] = get_now_seconds_epoch()
        self._user_info[username] = updated_claims

    def filter_empty_claims(
        self,
        user_claims: Dict[str, Dict[str, Any]],
        scope: str,
        include_empty: bool = True,
    ) -> Dict[str, Dict[str, Any]]:
        """Common code the filter empty values from claims returned. empty is true then Python
        evaluates the value of user_claims[key] as False.
        *NOTE*: the default of include empty is True, in get_user_claims, the most common call of this function,
        it is False.

        :param user_claims:
        :param scope:
        :param include_empty:
        """
        scope_claim_keys = self.scope_claims(scope)
        return dict(
            [
                (key, value)
                for key, value in user_claims.items()
                if ((include_empty is True) or (value != ""))
                and key in scope_claim_keys
            ]
        )

    def has_user_claims(self, username: str) -> bool:
        """Returns True if the username has cached user claims, else False
        :param username:
        """
        return username in self._user_info

    def get_user_claims(
        self, username: str, scope: str, include_empty: bool = False
    ) -> Dict[str, Dict[str, Any]]:
        """Returns a set of compliant ida claims for the input username, if there are no claims for the
        input username, then a set is created, cached and returned.

        :param username:  username in format SID or SID@DOMAIN (0728000@EMEA)
        :param scope: Indicates set of claims returned in addition to the audience attached to a token request
        :param include_empty: when True include empty claim values
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
            user_claim_data = self._user_info[username]
        else:
            user_claim_data = {
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

        self._user_info[username] = user_claim_data
        # Filter out empty claims is so required.
        return self.filter_empty_claims(user_claim_data, scope, include_empty)


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
        self._faker = faker.Faker()
        self._gender_list = ["female", "male", "non-binary"]
        self._gender_list_weighting = [46, 44, 10]
        super().__init__()

    def get_user_claims(
        self, username: str, scope: str, include_empty: bool = False
    ) -> Dict[str, Dict[str, Any]]:
        """Returns a set of compliant ida claims for the input username, if there are no claims for the
        input username, then a set is created, cached and returned.

        :param username:  username in format SID or SID@DOMAIN (0728000@EMEA)
        :param scope: Indicates set of claims returned in addition to the audience attached to a token request
        :param include_empty: when True include empty claim values
        :return: dictionary of claims
        """
        if username in self._user_info:
            user_claim_data = self._user_info[username]
        else:
            gender = random.choices(
                population=self._gender_list, weights=self._gender_list_weighting, k=1
            )[0]
            match gender:  # pragma: no cover
                case "female":
                    name = self._faker.name_female()
                case "male":
                    name = self._faker.name_male()
                case _:
                    name = self._faker.name_nonbinary()
            names = name.split(" ")
            given_name = names[0]
            family_name = names[-1]
            if len(names) >= 3:
                middle_name = names[1]  # pragma: no cover
            else:
                middle_name = random.choice(
                    [self._faker.first_name(), self._faker.last_name()]
                )
            domain_name = self._faker.domain_name()
            user_claim_data = {
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
                "birthdate": self._faker.date_of_birth(minimum_age=16).isoformat(),
                "zoneinfo": "",
                "locale": "",
                "updated_at": get_now_seconds_epoch(),
                "email": f"{given_name}.{middle_name[0]}.{family_name}@{domain_name}",
                "email_verified": True,
                "address": "",
                "phone_number": self._faker.phone_number(),
                "phone_number_verified": True,
            }
            self._user_info[username] = user_claim_data
        return self.filter_empty_claims(user_claim_data, scope, include_empty)


if __name__ == "__main__":  # pragma: no cover
    userdb = UserInfoFakerExtension()
    user_info = userdb.get_user_claims("o123456", "openid profile")
    from pprint import pformat

    print(pformat(user_info))
