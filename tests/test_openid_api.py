from openid_whisperer.openid_api import valid_response_type, validate_response_mode


def test_valid_response_types():
    # Check invalid
    assert valid_response_type("none") is False
    assert valid_response_type("token") is False

    # Check Valid
    assert valid_response_type("code") is True
    assert valid_response_type("id_token") is True
    assert valid_response_type("code id_token") is True
    assert valid_response_type("id_token token") is True
    assert valid_response_type("code token") is True
    assert valid_response_type("code id_token token") is True

    # Check upper case input or extra spacing or different orders
    assert valid_response_type("code Token") is False
    assert valid_response_type(" code id_token  token ") is True
    assert valid_response_type(" code token  id_token   ") is True


def test_validate_response_mode():
    response_type: str = ""
    response_mode: str = ""

    response_type, response_mode = "code", ""
    adjusted_response_mode, error_message = validate_response_mode(response_type, response_mode)
    assert error_message is None
    assert adjusted_response_mode == "query"

    response_type, response_mode = "token", ""
    adjusted_response_mode, error_message = validate_response_mode(response_type, response_mode)
    assert error_message is None
    assert adjusted_response_mode == "fragment"

    response_type, response_mode = "code", "fragment"
    adjusted_response_mode, error_message = validate_response_mode(response_type, response_mode)
    assert error_message == "Invalid response_mode of fragment for request_type code. response_mode 'query' expected."
    assert adjusted_response_mode == response_mode

    response_type, response_mode = "token", "query"
    adjusted_response_mode, error_message = validate_response_mode(response_type, response_mode)
    assert error_message == "Invalid response_mode of query for request_type token. response_mode 'fragment' expected."
    assert adjusted_response_mode == response_mode

    response_type, response_mode = "token", "xunsupportedx"
    adjusted_response_mode, error_message = validate_response_mode(response_type, response_mode)
    assert error_message == f"Unsupported response_mode of {response_mode}."
    assert adjusted_response_mode == response_mode

    response_type, response_mode = "code", "form_post"
    adjusted_response_mode, error_message = validate_response_mode(response_type, response_mode)
    assert error_message is None
    assert adjusted_response_mode == response_mode