import logging
from urllib.parse import urljoin
from typing import Dict, Any
import requests

from openid_examples.mock_shared_config import config
from openid_examples.mock_openid_client_lib import OpenIDClient

logger = logging.getLogger(__name__)


def call_private_endpoint(api_endpoint: str, access_token: str):
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}"
    }
    proxies: Dict[str, Any] = {"http": None, "https": None}
    try:
        response = requests.get(
            api_endpoint, headers=headers, proxies=proxies, verify=config.validate_certs
        )
        logging.info(response.status_code)
        if response.status_code != 200:
            logger.info(f"Unexpected response:\n{response.text}")
        elif response == 302:
            logging.info("redirect received")
        if response.headers["Content-Type"] == "application/json":
            result = response.json()
        else:
            result = response.text
        logger.info(result)
    except Exception as e:
        logger.exception(e)
        return {"error": str(e)}


def main():
    config.initialize_logging()
    openid_client: OpenIDClient = OpenIDClient(
        provider_url=config.identity_endpoint,
        tenant=config.tenant,
        client_id=config.client_id,
        scope=config.scope,
        resource=config.resource_uri,
        verify_server=config.validate_certs,
    )
    token_response = openid_client.request_token_password_grant(
        username="username@domain",
        secret="username authentication secret",
    )
    if not token_response:
        logger.error((
            f"Unable to validate credentials against the openid provider, "
            f"{config.identity_endpoint}"
        ))
    else:
        logger.info(f"Access Token: {token_response}")
        endpoint_url = urljoin(config.api_endpoint, "mock-api-private/api")
        call_private_endpoint(endpoint_url, token_response["access_token"])


if __name__ == "__main__":
    main()
