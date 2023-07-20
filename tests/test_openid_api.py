import pytest
from openid_whisperer.openid_interface import (
    validate_response_type,
    validate_response_mode,
    OpenidApiInterfaceException,
)
from openid_whisperer.utils.common import get_audience, validate_grant_type


def test_assemble_audience(scenario_api_a):
    audience = get_audience(
        client_id=scenario_api_a["client_id"],
        scope=scenario_api_a["scope"],
        resource=scenario_api_a["resource"],
    )
    print(audience)
    assert all(
        [
            item in audience
            for item in [
                scenario_api_a["client_id"],
                scenario_api_a["resource"],
            ]
        ]
    )


def test_valid_response_types():
    # Check invalid
    with pytest.raises(OpenidApiInterfaceException):
        validate_response_type("none")
    with pytest.raises(OpenidApiInterfaceException):
        validate_response_type("token")

    # Check Valid
    assert validate_response_type("code") == "code"
    assert validate_response_type("id_token") == "id_token"
    assert validate_response_type("code id_token") == "code id_token"
    assert validate_response_type("id_token token") == "id_token token"
    assert validate_response_type("code token") == "code token"
    assert validate_response_type("code id_token token") == "code id_token token"

    # Check upper case input or extra spacing or different orders
    with pytest.raises(OpenidApiInterfaceException):
        validate_response_type("code Token") is False
    assert validate_response_type(" code id_token  token ") == "code id_token token"
    assert validate_response_type(" code token  id_token   ") == "code id_token token"


def test_validate_response_mode():
    response_type: str = ""
    response_mode: str = ""

    response_type, response_mode = "code", ""
    adjusted_response_mode = validate_response_mode(response_type, response_mode)
    assert adjusted_response_mode == "query"

    response_type, response_mode = "token", ""
    adjusted_response_mode = validate_response_mode(response_type, response_mode)
    assert adjusted_response_mode == "fragment"

    response_type, response_mode = "code", "fragment"
    try:
        adjusted_response_mode = validate_response_mode(response_type, response_mode)
    except OpenidApiInterfaceException as e:
        assert (
            e.error_description
            == "Invalid response_mode of fragment for request_type code. response_mode 'query' expected."
        )

    response_type, response_mode = "token", "query"
    try:
        adjusted_response_mode = validate_response_mode(response_type, response_mode)
    except OpenidApiInterfaceException as e:
        assert (
            e.error_description
            == "Invalid response_mode of query for request_type token. response_mode 'fragment' expected."
        )

    response_type, response_mode = "token", "xunsupportedx"
    try:
        adjusted_response_mode, error_message = validate_response_mode(
            response_type, response_mode
        )
    except OpenidApiInterfaceException as e:
        assert e.error_description == f"Unsupported response_mode of {response_mode}."

    response_type, response_mode = "code", "form_post"
    adjusted_response_mode = validate_response_mode(response_type, response_mode)
    assert adjusted_response_mode == response_mode


def test_logoff(openid_api, scenario_api_a):
    openid_api.logoff(
        tenant=scenario_api_a["tenant"],
        client_id=scenario_api_a["client_id"],
        username=scenario_api_a["username"],
    )
    with pytest.raises(OpenidApiInterfaceException):
        openid_api.logoff(
            tenant=scenario_api_a["tenant"],
            client_id="",
            username=scenario_api_a["username"],
        )
    with pytest.raises(OpenidApiInterfaceException):
        openid_api.logoff(
            tenant=scenario_api_a["tenant"],
            client_id=scenario_api_a["client_id"],
            username="",
        )


def test_validate_client(openid_api):
    client_id: str = None
    client_secret: str | None = None
    assert openid_api.validate_client(client_id, client_secret) is False


def test_validate_grant_type():
    grant_type: str = ""
    try:
        validate_grant_type(grant_type)
    except OpenidApiInterfaceException as e:
        assert e.error_description == f"An empty input for grant_type is not supported"

    grant_type = "xxinvalid_grantxx"
    try:
        validate_grant_type(grant_type)
    except OpenidApiInterfaceException as e:
        assert (
            e.error_description == f"The grant_type of '{grant_type}' is not supported"
        )

    grant_type = "urn:ietf:params:oauth:grant-type:device_code"
    grant_type_echo = validate_grant_type(grant_type)
    assert grant_type_echo == grant_type

    grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer-unsupported"
    try:
        validate_grant_type(grant_type)
        assert False, "validate_grant_type test failed"  # pragma: no cover
    except OpenidApiInterfaceException as e:
        assert (
            e.error_description
            == f"The grant_type of '{grant_type}' is not supported"
        )

    grant_type = "implicit"
    try:
        validate_grant_type(grant_type)
        assert False, "validate_grant_type test failed"  # pragma: no cover
    except OpenidApiInterfaceException as e:
        assert (
                e.error_description
                == f"The grant_type of '{grant_type}' is not implemented"
        )
