"""
Example created By Robert Betts copying code layout from confidential_client_certificate_example.py
and username_password_example.py


The configuration file would look like this:

{
    "authority": "https://login.microsoftonline.com/organizations",
    "client_id": "your_client_id",
    "username": "your_username@your_tenant.com",
    "password": "This is a sample only. You better NOT persist your password.",
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

import sys  # For simplicity, we'll read config file from 1st CLI param sys.argv[1]
import json
import logging

import requests
import msal


# Optional logging
logging.basicConfig(level=logging.DEBUG)  # Enable DEBUG log for entire script
logging.getLogger("msal").setLevel(logging.INFO)  # Optionally disable MSAL DEBUG logs


config = {
    "authority": "https://localhost:5005/adfs",
    "client_id": "CLIENT-5700-DEV",
    "client_secret": "your_client_secret",
    "username": "your_username@your_tenant.com",
    "password": "This is a sample only. You better NOT persist your password.",
    "scope": ["URI:API:CLIENT-5700-API"],
    "endpoint": "http://localhost:5700/mock-api/api/private",
    "scope2": ["URI:API:CLIENT-5800-API"],
    "endpoint2": "http://localhost:5800/mock-api/api/private",
    "thumbprint": "thumbprint_value",
    "private_key_file": "src/openid_whisperer/demo_certs/key.pem",
}


# Create a preferably long-lived app instance which maintains a token cache.
http_client = requests.session()
http_client.verify = False
app = msal.ConfidentialClientApplication(
    config["client_id"],
    authority=config["authority"],
    client_credential={
        # "thumbprint": config["thumbprint"],
        "private_key": open(config['private_key_file']).read(),
        "thumbprint": "thumbprint_value".encode("utf-8").hex(),
    },
    validate_authority=False,
    verify=False,
    http_client=http_client,
    # token_cache=...  # Default cache is in memory only.
    # You can learn how to use SerializableTokenCache from
    # https://msal-python.readthedocs.io/en/latest/#msal.SerializableTokenCache
)


# The pattern to acquire a token looks like this.
result = None

# Firstly, check the cache to see if this end user has signed in before
accounts = app.get_accounts(username=config["username"])
if accounts:
    logging.info("Account(s) exists in cache, probably with token too. Let's try.")
    result = app.acquire_token_silent(config["scope"], account=accounts[0])

if not result:
    logging.info("No suitable token exists in cache. Let's get a new one from AAD.")
    # See this page for constraints of Username Password Flow.
    # https://github.com/AzureAD/microsoft-authentication-library-for-python/wiki/Username-Password-Authentication
    result = app.acquire_token_by_username_password(
        config["username"], config["password"], scopes=config["scope"]
    )

if "error" in result:
    print(result.get("error"))
    print(result.get("error_description"))
    print(result.get("correlation_id"))  # You may need this when reporting a bug
    sys.exit()

print(result)
user_assertion = result["access_token"]
logging.info("Now acquire an OBO token from AAD.")
obo_result = app.acquire_token_on_behalf_of(
    user_assertion=result["access_token"], scopes=config["scope2"], claims_challenge=None
)

if "access_token" in obo_result:

    logging.info("Using OBO token to mke a request to API 2")
    graph_data = requests.get(  # Use token to call downstream service
        config["endpoint2"],
        headers={"Authorization": "Bearer " + obo_result["access_token"]},
        verify=False,
    ).json()
    print("API call result: %s" % json.dumps(graph_data, indent=2))
else:
    print(obo_result.get("error"))
    print(obo_result.get("error_description"))
    print(obo_result.get("correlation_id"))  # You may need this when reporting a bug
    if 65001 in obo_result.get(
        "error_codes", []
    ):  # Not mean to be coded programatically, but...
        # AAD requires user consent for U/P flow
        print(
            "Visit this to consent:", app.get_authorization_request_url(config["scope2"])
        )
