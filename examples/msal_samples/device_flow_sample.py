"""
The configuration file would look like this:

{
    "authority": "https://login.microsoftonline.com/common",
    "client_id": "your_client_id",
    "scope": ["User.ReadBasic.All"],
        // You can find the other permission names from this document
        // https://docs.microsoft.com/en-us/graph/permissions-reference
    "endpoint": "https://graph.microsoft.com/v1.0/users"
        // You can find more Microsoft Graph API endpoints from Graph Explorer
        // https://developer.microsoft.com/en-us/graph/graph-explorer
}

You can then run this sample with a JSON configuration file:

    python sample.py parameters.json
"""

import sys
import json
import logging
from typing import List
from urllib.parse import urlparse
from pprint import pformat

import requests
import msal


def submit_credentials_with_challenge_code(config, challenge_info):
    """ Mock the end user authenticating and submitting the user code provided to them.
    """
    url_parts = urlparse(challenge_info["verification_uri"])
    query = url_parts.query
    query_items: List[tuple[str, str]] = [
        (item.split("=", 1)[0], item.split("=", 1)[1])
        for item in [part for part in query.split("&")]
    ]
    query_params = dict(query_items)
    logging.info(pformat(query_params))

    auth_url = f"{url_parts.scheme}://{url_parts.netloc}{url_parts.path}"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    data = {
        "response_type": query_params["response_type"],
        "client_id": query_params["client_id"],
        "prompt": query_params["prompt"],
        "scope": query_params["scope"],
        "resource": query_params["resource"],
        "UserName": config["username"],
        "Password": config["password"],
        "CodeChallenge": challenge_info["user_code"],
        "code_challenge_method": query_params["code_challenge_method"],
        "code_challenge": challenge_info.get("code_challenge", ""),
    }
    response = requests.post(auth_url, data=data, headers=headers, verify=False)
    logging.info(response.status_code)
    if response.status_code != 200:
        logging.info("Error processing end user verification of the user code")
        sys.exit()
    else:
        logging.info("End User code_challenge submitted")
        assert "Success, you have validated the user code provided to you." in response.text


# Optional logging
logging.basicConfig(level=logging.DEBUG)  # Enable DEBUG log for entire script
logging.getLogger("msal").setLevel(logging.INFO)  # Optionally disable MSAL DEBUG logs

# config = json.load(open(sys.argv[1]))
config = {
    "authority": "https://localhost:5005/adfs",
    "client_id": "PC-90274-SID-12655-DEV",
    "client_secret": "your_client_secret",
    "username": "your_username@your_tenant.com",
    "password": "This is a sample only. You better NOT persist your password.",
    "scope": ["URI:API:RS-104134-21171-mock-api-PROD"],
    "endpoint": "https://localhost:5700/mock-api/api/private",
}

# Create a preferably long-lived app instance which maintains a token cache.
app = msal.PublicClientApplication(
    config["client_id"],
    authority=config["authority"],
    validate_authority=False,
    verify=False,
    # token_cache=...  # Default cache is in memory only.
    # You can learn how to use SerializableTokenCache from
    # https://msal-python.readthedocs.io/en/latest/#msal.SerializableTokenCache
)

# The pattern to acquire a token looks like this.
result = None

# Note: If your device-flow app does not have any interactive ability, you can
#   completely skip the following cache part. But here we demonstrate it anyway.
# We now check the cache to see if we have some end users signed in before.
accounts = app.get_accounts()
if accounts:
    logging.info("Account(s) exists in cache, probably with token too. Let's try.")
    print("Pick the account you want to use to proceed:")
    for a in accounts:
        print(a["username"])
    # Assuming the end user chose this one
    chosen = accounts[0]
    # Now let's try to find a token in cache for this account
    result = app.acquire_token_silent(config["scope"], account=chosen)

if not result:
    logging.info("No suitable token exists in cache. Let's get a new one from AAD.")

    flow = app.initiate_device_flow(scopes=config["scope"])
    if "user_code" not in flow:
        raise ValueError(
            "Fail to create device flow. Err: %s" % json.dumps(flow, indent=4)
        )

    print(flow["message"])
    sys.stdout.flush()  # Some terminal needs this to ensure the message is shown

    # Short cust to emulate what the user would do
    submit_credentials_with_challenge_code(config, flow)

    # Ideally you should wait here, in order to save some unnecessary polling
    # input("Press Enter after signing in from another device to proceed, CTRL+C to abort.")

    result = app.acquire_token_by_device_flow(flow)  # By default it will block
    # You can follow this instruction to shorten the block time
    #    https://msal-python.readthedocs.io/en/latest/#msal.PublicClientApplication.acquire_token_by_device_flow
    # or you may even turn off the blocking behavior,
    # and then keep calling acquire_token_by_device_flow(flow) in your own customized loop.

if "access_token" in result:
    # Calling graph using the access token
    graph_data = requests.get(  # Use token to call downstream service
        config["endpoint"],
        headers={"Authorization": "Bearer " + result["access_token"]},
        verify=False,
    ).json()
    print("API call result: %s" % json.dumps(graph_data, indent=2))
else:
    print(result.get("error"))
    print(result.get("error_description"))
    print(result.get("correlation_id"))  # You may need this when reporting a bug
