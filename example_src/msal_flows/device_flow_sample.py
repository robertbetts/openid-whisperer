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
import os
import json
import logging
from typing import List
from urllib.parse import urlparse
from pprint import pformat

import requests
import msal


def submit_credentials_with_challenge_code(config, challenge_info):
    """Mock the end user authenticating and submitting the user code provided to them."""
    try:
        url_parts = urlparse(challenge_info["verification_uri"])
        query = url_parts.query
        query_items: List[tuple[str, str]] = [
            (item.split("=", 1)[0], item.split("=", 1)[1])
            for item in [part for part in query.split("&")]
        ]
        query_params = dict(query_items)
        print(
            "Responding to the following authentication request:\n{pformat(query_params)}\n"
        )

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
        device_response = requests.post(
            auth_url, data=data, headers=headers, verify=False
        )
        print(
            f"\nEnd User code_challenge submission response: {device_response.status_code}"
        )

        if device_response.status_code != 200:
            print("\nError processing end user verification of the user code")
            sys.exit()
        else:
            assert (
                "Success, you have validated the user code provided to you."
                in device_response.text
            )
            print("\nSuccessful verification of the user code")
    except Exception as e:
        print("\nError during verification of the user code")
        logging.exception(e)


# Optional logging
logging.basicConfig(level=logging.DEBUG)  # Enable DEBUG log for entire script
logging.getLogger("msal").setLevel(logging.INFO)  # Optionally disable MSAL DEBUG logs

json_config_file = os.path.join(os.path.dirname(__file__), "common_config_https.json")
if len(sys.argv) == 2 and sys.argv[1]:
    json_config_file = sys.argv[1]
config = json.load(open(json_config_file, "rb"))
config.update({
})


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

    print(f'\nDevice Prompt:\n{flow["message"]}\n\n')
    sys.stdout.flush()  # Some terminal needs this to ensure the message is shown

    # Ideally you should wait here, in order to save some unnecessary polling
    # input("Press Enter after signing in from another device to proceed, CTRL+C to abort.")

    # Short cust to emulate what the user would do
    submit_credentials_with_challenge_code(config, flow)

    result = app.acquire_token_by_device_flow(flow)  # By default it will block
    # You can follow this instruction to shorten the block time
    #    https://msal-python.readthedocs.io/en/latest/#msal.PublicClientApplication.acquire_token_by_device_flow
    # or you may even turn off the blocking behavior,
    # and then keep calling acquire_token_by_device_flow(flow) in your own customized loop.

if "access_token" in result:
    print(f"\nDevice code process successful.")
    print(f'Obtained Bearer token: {result["access_token"]}')
    print(f'Usering token to access {config["endpoint"]}')
    # Calling graph using the access token
    response = requests.get(  # Use token to call downstream service
        config["endpoint"],
        headers={"Authorization": "Bearer " + result["access_token"]},
        verify=False,
    )
    try:
        graph_data = response.json()
        print("API call result: %s" % json.dumps(graph_data, indent=2))
    except Exception as e:
        print(e)
        print(
            f"Expected JSON response from endpoint:\nstatus_code:{response.status_code}\nurl:{response.url}"
        )

else:
    print(result.get("error"))
    print(result.get("error_description"))
    print(result.get("correlation_id"))  # You may need this when reporting a bug
