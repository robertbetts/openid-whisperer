# OpenID Whisperer - Identity Service
OpenID Compliant Identity Service

[![codecov](https://codecov.io/gh/robertbetts/openid-whisperer/branch/main/graph/badge.svg?token=DVSBZY794D)](https://codecov.io/gh/robertbetts/openid-whisperer)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Sometimes you want to stand up an application fast, and you don't want to compromise on its design or access control.
Openid-Whisperer provides a quick and efficient set of solutions where applications have a requirement for OpenID 1.0
or Oauth 2.0 authentication and access control.

1. OpenID Identity Service run either standalone or as Docker container
2. Python OpenID class library
3. Flask OpenID blueprint
4. Customised or mock end user information claims 
5. Sandbox for learning and experimenting

There are numerous opensource projects that offer specifications, patterns and solutions around OpenID
authentication and authorisation. This project aims to take a lightweight approach with as complete functional flow and
api coverage as possible. Some of the references that have been useful to this effort are:

* https://openid.net/developers/specs/
* https://auth0.com/docs/
* https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/overview/ad-fs-openid-connect-oauth-flows-scenarios
* https://github.com/AzureAD/microsoft-authentication-library-for-python

## History
This project started life as a mock for Microsoft ADFS, it has since evolved into a lightweight, compliant,
OpenID version 1 service and covers most of the common authentication flows required when running or testing against  
an OpenID type service provider. 

Important to note is that although a compliant OpenID API, with authentication flows and tokens issued, it still 
designed as a protocol mock or authentication flow validator. By default there is no internal repository of 
protected resources of end user credentials. 

Any values input for client_id, client_secret, username, password, scope, resource are assumed to be valid.
* UserName@domain and non-empty password credentials entered assumed to be correct.
* client_id, resource and scope profiles/permissions are also assumed to exist and to be valid.

## User Information Claim Extensions:
This is a relatively new feature to further support testing of resource permissions and end user claims. The 
base extension echoes back the input information gathered from the client/resource owner together with the 
credentials of the end user and generates a set of user claims. The claims follow the published OpenID
specification. 

There is an extended Faker based implementation which for any input username, randomly generates a fake 
end user profile. This profile is cached against the input username and is used to populate the token claim 
information. An example of the Faker extension can be seen implemented in the API Service code example 
`example_src/openid_examples/mock_openid_service.py`

A typical further customisation to the user information extension, is dropping in a set of predefined users and scopes. 
This is very helpful when building and testing and OpenID protect API where different users have 
different roles and access to different API resources.

## Example code for various OpenID use cases

### `example_src/openid_examples/`
* `mock_openid_service.py`: A custom implementation of Openid-Whisperer
* `mock_api_server.py`: An example Web/API service, with resources protected through OpenID
* `mock_api_end_user.py`: An example where a client app access an API Service
* `mock_openid_client_lib.py`: A lightweight OpenID protocol library used by the examples
* `mock_shared_config.py`: A common config class for synchronising configuration across the examples

When the example code is run from the project_root folder, the configuration loads default environment
variables from `.env_TEST`

### `example_src/msal_flows`
The MSAL library is used as an alternative method for verifying OpenID protocol compliance, more
specifically the complaince of ADFS or that of Azure.
The following flow examples run through successfully:
* `device_code_flow.py`
* `username_and_password_example.py`
* `interactive_sample.py`
* `migrate_rt.py` This example has API compatibility, however there is no functional implementation.

To run these examples, you may have to alter the configuration parameters to suite you environment
and by default an instance of Openid-Whisperer and OpenID Web/API protected service.

## Microsoft Authentication Library MSAL
MSAL is used for alternative testing kit to verify ADFS and Azure OpenID authentication flows. The
following MSAL code examples run through successfully:
* `device_code_flow.py`
* `username_and_password_example.py`
* `interactive_sample.py`
* `migrate_rt.py` This example has API compatibility, however there is no functional implementation.

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

## Running the Code
### Pytest unit tests
Code test coverage objective is 100%. there are currently no unit tests for the module mocking_examples
```
poetry run coverage run -m pytest && poetry run coverage report -m
```

### Running Openid-Whisperer
Run OpenID Whisperer (from project root)
```
poetry run python -m openid_whisperer.main 
```

Run within a Docker Container
```
docker build -t opendid-whisperer:0.1.4 .
docker run --name=openid-whisperer -p5005:5005  -eID_SERVICE_PORT_GW=5005 opendid-whisperer:0.1.4
```