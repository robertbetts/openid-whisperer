import logging
from urllib.parse import urljoin
from typing import Dict, Any
import json
import requests

from mocking_examples.openid_client_lib import OpenIDClient
from mocking_examples.config import config


def call_api_private_endpoint(access_token, use_gateway: bool = False):
    api_endpoint: str = config.api_endpoint_gw if use_gateway else config.api_endpoint
    api_endpoint = urljoin(api_endpoint, "/mock-api/api/private")
    headers = {"Authorization": f"Bearer {access_token['access_token']}"}
    proxies: Dict[str, Any] = {"http": None, "https": None}
    try:
        response = requests.get(
            api_endpoint, headers=headers, proxies=proxies, verify=config.validate_certs
        )
        logging.info(response.status_code)
        if response.status_code != 200:
            logging.info("Unexpected response: \n%s", response.text)
        else:
            result = json.loads(response.text)
            logging.info(result)
    except Exception as e:
        logging.exception(e)
        return {"error": str(e)}


def main():
    config.initialize_logging()
    openid_client: OpenIDClient = OpenIDClient(
        provider_url=config.identity_endpoint,
        provider_url_gw=config.identity_endpoint_gw,
        client_id=config.client_id,
        resource=config.resource_uri,
        verify_server=config.validate_certs,
        use_gateway=False,
    )
    access_token = openid_client.request_token_password_grant(
        username="username@domain",
        secret="very long dev reminder",
    )
    if not access_token:
        logging.error(
            "Unable to validate credentials against the openid provider at %s",
            config.identity_endpoint,
        )
    else:
        logging.info(f"Access Token: {access_token}")
        call_api_private_endpoint(access_token)


if __name__ == "__main__":
    main()
