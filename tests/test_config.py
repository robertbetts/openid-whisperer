import logging
import pytest
import openid_whisperer.config


def test_cert_config():
    _ = openid_whisperer.config.init_certs()
    with pytest.raises(FileNotFoundError):
        _ = openid_whisperer.config.init_certs("BadName")
