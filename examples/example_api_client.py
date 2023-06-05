import logging
import os
from urllib.parse import urljoin
from typing import Dict, Any
import json
import requests

from openid_whisperer.openid_client_lib import OpenIDClient

VALIDATE_CERTS: bool = os.getenv("VALIDATE_CERTS", "False").lower() != "false"

client_id: str = "PC-90274-SID-12655-DEV"
resource_uri: str = "URI:API:RS-104134-21171-mock-api-PROD"
openid_base_url: str = "https://localhost:5005/adfs/"

api_base_url_direct: str = "http://localhost:5006"
api_base_url_gw: str = "http://localhost:5006"


def call_api_private_endpoint(access_token):
    api_endpoint = urljoin(api_base_url_gw, "/mock-api/api/private")
    headers = {
        "Authorization": access_token["access_token"]
    }
    proxies: Dict[str, Any] = {'http': None, 'https': None}
    try:
        response = requests.get(api_endpoint, headers=headers, proxies=proxies)
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
    openid_client: OpenIDClient = OpenIDClient(
        provider_url=openid_base_url,
        client_id=client_id,
        resource_uri=resource_uri,
        verify_server=VALIDATE_CERTS,
        )
    access_token = openid_client.request_token_password_grant(
        username="username@domain",
        secret="very long dev reminder",
        )
    logging.info(access_token)
    call_api_private_endpoint(access_token)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    main()
