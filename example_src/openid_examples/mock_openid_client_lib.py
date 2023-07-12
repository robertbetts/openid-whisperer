""" Module with OpenID client functionality. Used for unit testing and example code
"""
import logging
import json
import base64
from collections import UserDict
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from urllib.parse import urljoin, urlsplit, urlunsplit
from typing import Dict, Any, Optional, List, Type
import math

import requests
import jwt

logger = logging.getLogger(__name__)


class OpenidClientException(Exception):
    ...


def replace_base_netloc(url1: str, url2: str) -> str:
    """Combine the network location of url1 with scheme, path, query and fragment of url2"""
    parts1 = urlsplit(url1)
    parts2 = urlsplit(url2)
    return urlunsplit(
        (parts2.scheme, parts1.netloc, parts2.path, parts2.query, parts2.fragment)
    )


class IdentityConfig(UserDict):
    """Dictionary like class that contains and caches an identity service's published services and settings. This
    is accessed via a call to http://identity_service_address/{tenant}/.well-known/openid-configuration.

    The initial call to the identity service is made when the first configuration element is requested.
    """

    def __init__(
        self,
        provider_url: str,
        tenant: Optional[str] = None,
        verify_server: bool = True,
    ):
        self.tenant = tenant if tenant else ""
        self._provider_url: str = urljoin(provider_url, tenant)
        self.verify_server: bool = verify_server
        self.initialised: bool = False
        super().__init__()

    @property
    def provider_url(self) -> str:
        return urljoin(self._provider_url, self.tenant)

    def refresh(self):
        """Update the dictionary's data with that from the identity provider. This class is first refreshed when the
        configuration element is accessed.
        """
        endpoint = urljoin(self.provider_url, ".well-known/openid-configuration")
        response = requests.get(url=endpoint, verify=self.verify_server)
        if response.status_code == 200:
            config_data: Dict[str, Any] = response.json()
            self.update(config_data)
        else:
            logging.error(
                "Failed to access identity provider openid-configuration endpoint"
            )
            raise OpenidClientException(
                f"Error accessing the identity provider service\n{response.text}"
            )

    def __getitem__(self, item):
        """checking if this is the first get operation to trigger a refresh"""
        if self.initialised is False:
            self.refresh()
            self.initialised = True
        return UserDict.__getitem__(self, item)


class OpenIDClient:
    """OpenID 1.0 example compatible client library"""

    def __init__(
        self,
        provider_url: str,
        provider_url_gw: str,
        tenant: str,
        client_id: str,
        scope: str,
        resource: Optional[str] = None,
        use_gateway: bool = False,
        verify_server: bool = True,
    ):
        self.provider_url: str = provider_url
        self.provider_url_gw: str = provider_url_gw
        self.tenant: str = tenant
        self.client_id: str = client_id
        self.scope: str = scope if scope else "openid"
        self.resource: str = resource if resource else ""
        self.use_gateway: bool = use_gateway
        self.verify_server = verify_server

        self.identity_keys: Dict[str, Any] = {}
        self.validated_claims: Dict[str, Any] = {}

        provider_url = self.provider_url_gw if use_gateway else self.provider_url
        self.identity_config: Type[IdentityConfig] = IdentityConfig(
            provider_url=provider_url,
            tenant=self.tenant,
            verify_server=self.verify_server,
        )

    def validate_access_token(
        self,
        access_token: str,
        audience: Optional[str | List],
        verify_server: bool = True,
        use_gateway: bool = False,
    ) -> Dict[str, Any]:
        """Validate a JWT (Bearer token) against the keys provided by the IDA service and return the validated token
         claim payload. If the JWT, claim or IDA keys are invalid or the claim is empty, then raise an exception.

        If a colon is found in the first 10 characters of the input access_token, the only accepted
        "type indicator".lower() is "bearer"

        audience is a mandatory token check, as a minimum the aud claim should always contain the OpenID client_id,
        as well as being the value of the "appid" claim.

        The issuer reference embedded in the token is compared to "access_token_issuer" value received from a
        call to http://identity_service/{tenant}/.well-known/openid-configuration.

        FYI: resource: For those migrating from MS ADFS or earlier version of Azure, there is a move away from
        specifying the resource permissions using the resource (resource_uri) parameter in the various authentication
        flows. The preference is defined authorisation requirements withing the scope parameter.

        Parameters:
            access_token: can be in the form of "Bearer: LKJLJHKVG345VJGGG...." or only the token value e.g "LKJLJHKVG345VJGGG...."
            audience: parameter should as a minimum contain [client_id, resource] as a list of strings or a single space separated string.
            verify_server: Whether to validate the SSL credentials of the identity service
            use_gateway: access internal or external address of the identity service
        """
        access_token = access_token.strip()

        if ":" in access_token[:10]:
            token_type, token = (item.strip() for item in access_token.split(":", 1))
            if token_type.lower() != "bearer":
                logger.warning(
                    "Only Bearer tokens have been tested, result for {} is undefined"
                )
            access_token = token

        token_parts = access_token.split(".")
        # Adjust the left padding to avoid the base64 padding error
        token_header = token_parts[0].ljust(
            int(math.ceil(len(token_parts[0]) / 4)) * 4, "="
        )
        header = json.loads(base64.b64decode(token_header).decode("utf-8"))
        tok_x5t = header["x5t"]

        issuer: str = self.identity_config["access_token_issuer"]

        claims: Dict[str, Any] = {}
        provider_url: str = (
            self.provider_url_gw if self.use_gateway else self.provider_url
        )
        if use_gateway:
            provider_url = self.provider_url_gw

        if not self.identity_keys:
            key_endpoint = replace_base_netloc(
                provider_url, self.identity_config["jwks_uri"]
            )
            header = {
                "content_type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            }
            response = requests.get(
                url=key_endpoint, headers=header, verify=verify_server
            )
            keys = json.loads(response.text)["keys"]

            # Loop through keys to create dictionary
            for key in keys:
                x5t = key["x5t"]  # Certificate id
                x5c = key["x5c"][0]  # base64 x509 certificate (DER, PKCS1)
                # extract signed public key to be used for access token validation
                public_key_spki_der = base64.b64decode(x5c.encode("ascii"))
                cert = x509.load_der_x509_certificate(
                    public_key_spki_der, default_backend()
                )
                public_key = cert.public_key()
                # cache the IDA public key
                self.identity_keys[x5t] = public_key

        key_errors = []
        token_errors = []
        # Loop through the available ida public keys to verify the JWT
        for key in self.identity_keys:
            try:
                claims = jwt.decode(
                    access_token,
                    self.identity_keys[tok_x5t],
                    audience=audience,
                    issuer=issuer,
                    algorithms=["RS256"],
                )
                if claims:
                    self.validated_claims[access_token] = claims
                    # Token and claims are good, ignore possible failed validations against invalid keys
                    key_errors = []
                    token_errors = []
                    break
                else:
                    token_errors.append(
                        (access_token, Exception("Token contains no validated claims"))
                    )

            except jwt.ExpiredSignatureError as e:
                key_errors.append((key, e))

            except jwt.InvalidAudienceError as e:
                # logging.exception("Unable to validate audience claim for %s, %s", audience, e)
                token_errors.append((access_token, e))

            except jwt.InvalidTokenError as e:
                # logging.exception(e)
                token_errors.append((access_token, e))

        err = None

        for error in token_errors:
            err = error[1] if err is None else err
            logging.error("%s", error[1])

        for error in key_errors:
            err = error[1] if err is None else err
            logging.error("keyError: %s", error[1])

        if err:
            raise err

        return claims

    def token_endpoint_url(self, use_gateway: bool = False) -> str:
        provider_url: str = (
            self.provider_url_gw if self.use_gateway else self.provider_url
        )
        if use_gateway:
            provider_url = self.provider_url_gw
        return replace_base_netloc(provider_url, self.identity_config["token_endpoint"])

    def authorization_endpoint_url(self, use_gateway: bool = False) -> str:
        provider_url: str = (
            self.provider_url_gw if self.use_gateway else self.provider_url
        )
        if use_gateway:
            provider_url = self.provider_url_gw
        return replace_base_netloc(
            provider_url, self.identity_config["authorization_endpoint"]
        )

    def request_token_password_grant(
        self,
        username: str,
        secret: str,
        mfa: Optional[str] = "",
        headers: Dict[str, Any] | None = None,
        use_gateway: bool = False,
    ) -> Dict[str, Any]:
        """make a rest call to an identity service for the issuance of a valid jwt"""
        _ = mfa  # providing interface support for the function in advance of the feature
        request_data = {
            "grant_type": "password",
            "client_id": self.client_id,
            "resource": self.resource,
            "username": username,
            "password": secret,
        }

        token_endpoint_url = self.token_endpoint_url(use_gateway=use_gateway)
        headers = {} if headers is None else headers
        headers.update(
            {
                "content_type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            }
        )
        try:
            request_session = requests.session()
            request_session.verify = self.verify_server
            logging.info(request_data)
            response = request_session.post(
                token_endpoint_url,
                data=request_data,
                headers=headers,
                verify=self.verify_server,
            )
            access_token = json.loads(response.text)
            return access_token
        except Exception as e:
            logging.exception(e)
            return {"error": str(e)}
