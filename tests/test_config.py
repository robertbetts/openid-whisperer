import logging
import os

import pytest

import openid_whisperer.config
from openid_whisperer.utils.config_utils import default_config_type, initialize_logging, load_environment_variables, \
    get_bind_address
from openid_whisperer.config import Config, get_cached_config


def test_messing_with_config_class():
    with pytest.raises(ValueError):
        config = Config(
            defaults={"bad-property-name": (str, "property-value")}
        )


def test_config_type_renderer(caplog):
    config = Config(
        defaults={"int_property_name": (int, "bad-property-value")}
    )
    logger_name = "openid_whisperer.config"
    expected_entry = (
        logger_name,
        30,
        'Unable to set config parameter int_property_name, using default value '
        'bad-property-value\n'
        "Error: invalid literal for int() with base 10: 'bad-property-value'"
    )
    assert expected_entry in caplog.record_tuples


def test_load_environment_variables(caplog):
    before_test = os.environ.get("ENVIRONMENT")
    try:
        logger_name = "openid_whisperer.utils.config_utils"

        os.environ["ENVIRONMENT"] = ""
        caplog.clear()
        load_environment_variables()
        assert os.environ["ENVIRONMENT"] == "DEV"
        assert (logger_name, logging.WARNING, "Defaulting target environment variable ENVIRONMENT to DEV") \
               in caplog.record_tuples

        os.environ["ENVIRONMENT"] = ""
        caplog.clear()
        load_environment_variables(env_target="TEST")
        assert os.environ["ENVIRONMENT"] == "TEST"
        assert (logger_name, logging.WARNING, "Defaulting os environment variable ENVIRONMENT to TEST") \
               in caplog.record_tuples

        os.environ["ENVIRONMENT"] = "DEV"
        caplog.clear()
        load_environment_variables()
        assert os.environ["ENVIRONMENT"] == "DEV"
        assert (logger_name, logging.WARNING, "Using target environment from variable ENVIRONMENT, DEV") \
               in caplog.record_tuples

        os.environ["ENVIRONMENT"] = "DEV"
        caplog.clear()
        load_environment_variables("TEST")
        assert os.environ["ENVIRONMENT"] == "TEST"
        assert (logger_name, logging.WARNING, "Overriding os environment variable ENVIRONMENT from DEV to TEST") \
               in caplog.record_tuples

        os.environ["ENVIRONMENT"] = "TEST"
        caplog.clear()
        load_environment_variables("TEST")
        assert os.environ["ENVIRONMENT"] == "TEST"
        assert (logger_name, logging.INFO, "Target environment is TEST") \
               in caplog.record_tuples

    except Exception:  # pragma: no cover
        raise  # pragma: no cover

    finally:
        os.environ["ENVIRONMENT"] = before_test


def test_get_config():
    openid_whisperer.config.cached_config = None
    config = get_cached_config()
    assert openid_whisperer.config.cached_config.instance_id == config.instance_id
    config2 = get_cached_config()
    assert config.instance_id == config2.instance_id


def test_init_config():
    empty_defaults: default_config_type = {}
    config = Config(defaults=empty_defaults, env_target="testing")
    assert config.bind_address == ["0.0.0.0:8100", "[::]:8100"]
    assert config.gateway_address == "localhost:8100"

    assert get_bind_address("bad-bind-address") == []


def test_initialize_logging():
    """ happy just to run through the code, trying to
    """
    initialize_logging(log_level="DEBUG")

