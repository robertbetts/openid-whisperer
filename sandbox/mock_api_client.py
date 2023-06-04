import logging
from urllib.parse import urljoin
from typing import Dict, Any
import json
import requests

client_id: str = "PC-90274-SID-12655-DEV"
resource_uri: str = "URI:API:RS-104134-21171-mock-api-PROD"
openid_base_url: str = "https://localhost:5005"

api_base_url_direct: str = "http://localhost:5006"
api_base_url_gw: str = "http://localhost:5006"


def get_token_grant(
        sid: str,
        domain: str,
        secret: str,
        headers: Dict[str, Any] | None = None,
        verify_server: bool = True,
        ) -> Dict[str, Any]:
    """ make a rest call to the IDA service for the issuance of a valid jwt
    """

    username = f"{domain}\\{sid}"
    request_data = {
        "grant_type": "password",
        "client_id": client_id,
        "resource": resource_uri,
        "username": username,
        "password": secret,
    }
    token_endpoint = urljoin(openid_base_url, "adfs/oauth2/token")
    headers = {} if headers is None else headers
    headers.update({'content_type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'})
    try:
        request_session = requests.session()
        request_session.verify = verify_server
        logging.info(request_data)
        response = request_session.post(token_endpoint, data=request_data, headers=headers, verify=verify_server)
        access_token = json.loads(response.text)
        return access_token
    except Exception as e:
        logging.exception(e)
        return {"error": str(e)}


def call_mock_api_direct(access_token: Dict[str, Any], verify_server: bool = True):
    api_endpoint = urljoin(api_base_url_direct, "/api/private")
    headers = {
        "Authorization": access_token["access_token"]
    }
    try:
        request_session = requests.session()
        request_session.verify = verify_server
        response = request_session.get(api_endpoint, headers=headers, verify=verify_server)
        result = json.loads(response.text)
        logging.info(response.status_code)
        logging.info(result)
    except Exception as e:
        logging.exception(e)
        return {"error": str(e)}


def call_mock_api_gw(access_token):
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
    access_token = get_token_grant("o728000", "EMEA", "very long dev reminder", verify_server=False)
    logging.info(access_token)
    call_mock_api_gw(access_token)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    main()
