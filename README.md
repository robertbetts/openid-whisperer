# OpenID Whisperer - Identity Service
OpenID Compliant Identity Service

[![codecov](https://codecov.io/gh/robertbetts/openid-whisperer/branch/main/graph/badge.svg?token=DVSBZY794D)](https://codecov.io/gh/robertbetts/openid-whisperer)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This project started life as a mock Microsoft ADFS service, it since evolved into a compliant
OpenID version 1 service and covers most common authentication flows required by applications that 
use an OpenID type authentication provider. 

It is important to note, although a compliant OpenID API with authentication flows and tokens issued, it still 
behaves as a mock service in that there is no internal repository of end user or client app credentials. The 
values for client_id, client_secret, username, password, scope and resource are assumed to be valid as is input.
* UserName@domain / Password credentials entered assumed to be correct.
* client_id, resource and scope profiles/permissions are also assumed to be valid. 

### Microsoft Authentication Library MSAL
MSAL is used as 3rd party testing kit for additional verification the implemented authentication flows. The 
current MSAL code examples run through successfully:
* device_code_flow.py
* username_and_password_example.py

## Development
Active development is on Python 3.11 on both Windows 10 and macOS 13.4. Testing is run using PyTest against these 
environments as well as under Ubuntu 22.04 through GitHub Actions.

## Environment Setup
1. Install Python, this project is developed with CPython ^3.11
2. Upgrade pip
```commandline
python -m pip --upgrade pip
```
3. Install Poetry, this is the package manager for this project. Currently, using 1.5.1
```
python -m pip install poetry
```
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
INTERNAL_HOST=${INTERNAL_HOST:-localhost}
GATEWAY_HOST=${GATEWAY_HOST:-localhost}

API_HOST=${INTERNAL_HOST:-localhost}
API_PORT=${API_PORT:-5700}
API_HOST_GW=${GATEWAY_HOST:-localhost}
API_PORT_GW=${API_PORT_GW:-8100}

ID_SERVICE_PORT=${ID_SERVICE_PORT:-5000}
ID_SERVICE_HOST=${INTERNAL_HOST:-localhost}
ID_SERVICE_BIND=${ID_SERVICE_BIND:-0.0.0.0}
ID_SERVICE_PORT_GW=${ID_SERVICE_PORT_GW:-8100}
ID_SERVICE_HOST_GW=${GATEWAY_HOST:-localhost}

CA_KEY_FILENAME=${CA_KEY_FILENAME:-certs/ca_key.pem}
CA_CERT_FILENAME=${CA_CERT_FILENAME:-certs/ca_cert.pem}
ORG_KEY_FILENAME=${ORG_KEY_FILENAME:-certs/key.pem}
ORG_CERT_FILENAME=${ORG_CERT_FILENAME:-certs/cert.pem}

NO_PROXY=${NO_PROXY:-127.0.0.1,localhost},${GATEWAY_HOST:-localhost},${INTERNAL_HOST:-localhost}
VALIDATE_CERTS=${VALIDATE_CERTS:-False}
```

## Running Code
### PyTest unit tests
Code test coverage objective is 100%. there are currently no unit tests for the module mocking_examples
```
poetry run coverage run -m pytest && poetry run coverage report -m
```

### Application Instances
Run OpenID Whisperer (from project root)
```
poetry run python -m openid_whisperer.main 
```

Run Mock API Service (from project root)
```
poetry run python -m mocking_examples
```

Run Mock API Service Client (from project root)
```
poetry run python -m mocking_examples.mock_api_client 
```

## Containerisation
To Build and Run a Docker Container
```
docker build -t opendid-whisperer:0.1.0 .
docker run --name=openid-whisperer -p5005:5000  -eID_SERVICE_PORT_GW=5005 opendid-whisperer:0.1.0
```