# Example code for various OpenID use cases

## `example_src/openid_examples/`
* `mock_openid_service.py`: An example of a custom implementation of Openid-Whisperer
* `mock_api_server.py`: An example of a Web/API service, with resources protected through OpenID
* `mock_api_end_user.py`: An example of an API client application
* `mock_openid_client_lib.py`: A lightweight OpenID protocol library used by the examples
* `mock_shared_config.py`: A common config class for synchronising configuration across the examples

When the example code is run from the project_root folder, the configuration loads default environment 
variables from `.env_TEST`

## `example_src/msal_flows`
The MSAL library is used as an alternative method for verifying OpenID protocol compliance, more 
specifically the complaince of ADFS or that of Azure.
The following flow examples run through successfully:
* `device_code_flow.py`
* `username_and_password_example.py`
* `interactive_sample.py`
* `migrate_rt.py` This example has API compatibility, however there is no functional implementation.

To run these examples, you may have to alter the configuration parameters to suite you environment 
and by default an instance of Openid-Whisperer and OpenID Web/API protected service.

