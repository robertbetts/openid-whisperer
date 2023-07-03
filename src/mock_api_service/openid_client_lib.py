""" Module with OpenID client functionality. Used for unit testing and example code
"""
import logging
import json
import base64
from collections import UserDict
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from urllib.parse import urljoin, urlsplit, urlunsplit
from typing import Dict, Any, Optional, List
import math

import requests
import jwt


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
    """Dictionary like class for accessing and caching an OpenID Identity provider's configuration"""

    def __init__(self, provider_url: str, verify_server: bool = True):
        self.provider_url: str = provider_url
        self.verify_server: bool = verify_server
        self.initialised: bool = False
        super().__init__()

    def refresh(self):
        """Update the dictionary's data with that from the identity provider.
        this class is refreshed with the identity provider the first an
        element is retrieved.
        """
        endpoint = urljoin(self.provider_url, ".well-known/openid-configuration")
        response = requests.get(url=endpoint, verify=self.verify_server)
        if response.status_code == 200:
            config_data: Dict[str, Any] = response.json()
            self.update(config_data)
        else:
            logging.error("Failed identity provider endpoint {}".format(endpoint))
            raise OpenidClientException(
                "Unable to connect to the identity provider\n{}".format(response.text)
            )

    def __getitem__(self, item):
        """checking if this is the first get operation to trigger a refresh"""
        if self.initialised is False:
            self.refresh()
            self.initialised = True
        return UserDict.__getitem__(self, item)


class OpenIDClient:
    """OpenID 1.0 Compatible Client Library"""

    def __init__(
        self,
        provider_url: str,
        provider_url_gw: str,
        client_id: str,
        resource: Optional[str] = None,
        use_gateway: bool = False,
        verify_server: bool = True,
    ):
        self.provider_url: str = provider_url
        self.provider_url_gw: str = provider_url_gw
        self.client_id: str = client_id
        self.resource: str = resource if resource else ""
        self.use_gateway: bool = use_gateway
        self.verify_server = verify_server

        self.identity_keys: Dict[str, Any] = {}
        self.validated_claims: Dict[str, Any] = {}

        provider_url = self.provider_url_gw if use_gateway else self.provider_url
        self.identity_config: IdentityConfig = IdentityConfig(
            provider_url, verify_server
        )

    def validate_access_token(
        self,
        access_token: str,
        audience: Optional[str | List] = None,
        verify_server: bool = True,
        use_gateway: bool = False,
    ) -> Dict[str, Any]:
        """Validate a JWT against the keys provided by the IDA service and return the valid claim payload.
        if the JWT, claim or IDA keys are invalid or the claim is empty the raise an exception.

        audience is mandatory token check, as a minimum the aud claim will always contain the OpenID client_id. Where
        resource has been specified, this will be included in the aud claim.
        Where the audience parameter is None, the audience is assigned [self.client_id, self.resource]
        """
        at_list = access_token.split(".")
        # Adjust the left padding to avoid the base64 padding error
        token_header = at_list[0].ljust(int(math.ceil(len(at_list[0]) / 4)) * 4, "=")
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
