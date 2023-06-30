import pytest
from openid_whisperer.openid_api import validate_response_type, validate_response_mode, OpenidException


def test_valid_response_types():
    # Check invalid
    with pytest.raises(OpenidException):
        validate_response_type("none")
    with pytest.raises(OpenidException):
        validate_response_type("token")

    # Check Valid
    assert validate_response_type("code") == "code"
    assert validate_response_type("id_token") == "id_token"
    assert validate_response_type("code id_token") == "code id_token"
    assert validate_response_type("id_token token") == "id_token token"
    assert validate_response_type("code token") == "code token"
    assert validate_response_type("code id_token token") == "code id_token token"

    # Check upper case input or extra spacing or different orders
    with pytest.raises(OpenidException):
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
    except OpenidException as e:
        assert e.error_description == "Invalid response_mode of fragment for request_type code. response_mode 'query' expected."

    response_type, response_mode = "token", "query"
    try:
        adjusted_response_mode = validate_response_mode(response_type, response_mode)
    except OpenidException as e:
        assert e.error_description == "Invalid response_mode of query for request_type token. response_mode 'fragment' expected."

    response_type, response_mode = "token", "xunsupportedx"
    try:
        adjusted_response_mode, error_message = validate_response_mode(response_type, response_mode)
    except OpenidException as e:
        assert e.error_description == f"Unsupported response_mode of {response_mode}."

    response_type, response_mode = "code", "form_post"
    adjusted_response_mode = validate_response_mode(response_type, response_mode)
    assert adjusted_response_mode == response_mode
