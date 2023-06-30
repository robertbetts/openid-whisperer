# OpenID Whisperer - Identity Service
OpenID Compliant Identity Service

This project started life as a mock Microsoft ADFS service, it has since evolved into a compliant
OpenID version 1 service. It covers most of the authentication flows required by applications with
an OpenID / Oauth dependency. Recently the [MSAL](https://pypi.org/project/msal/) library was successfully
test against OPenID Whisperer.

* UserName@domain / Password credentials are not checked and assumed to be correct.
* client_id, resource and scope profiles/permissions are echoed back as part of the aud claim. 

## Environment Setup
1. Install Python, this project is developed with CPython ^3.11
2. Upgrade pip 

```commandline
install python -m pip --upgrade pip
```
3. Install Poetry, this is the package manager for this project
4. Clone the Repository

```commandline
git clone https://github.com/robertbetts/openid-whisperer.git
```
5. Setup project

```commandline
cd openid-whisperer
poetry install
poetry update
```
6. Setup environment variables, default `.env` and `.env_${ENVIRONMENT:-TEST}`

```
INTERNAL_HOST=localhost
GATEWAY_HOST=localhost
API_HOST=localhost
API_PORT=5700
API_HOST_GW=localhost
API_PORT_GW=5700
ID_SERVICE_HOST=localhost
ID_SERVICE_PORT=5000
ID_SERVICE_HOST_GW=localhost
ID_SERVICE_PORT_GW=5000
CA_KEY_FILENAME=certs/ca_key.pem
CA_CERT_FILENAME=certs/ca_cert.pem
ORG_KEY_FILENAME=certs/key.pem
ORG_CERT_FILENAME=certs/cert.pem
NO_PROXY=localhost,127.0.0.1
VALIDATE_CERTS=false
FLASK_DEBUG=false
ENVIRONMENT=TEST
```

## Running Code
### Running unit tests
Code test coverage objective is 100%. there are currently no unit tests for the module mock_api_service
```
poetry run coverage run -m pytest && poetry run coverage report -m
```

Run OpenID Whisperer (from project root)
```
poetry run python -m openid_whisperer.main 
```

Run Mock API Service (from project root)
```
poetry run python -m mock_api_service
```

Run Mock API Service Client (from project root)
```
poetry run python -m mock_api_service.mock_api_client 
```
