import logging
from openid_whisperer.utils.common import package_get_logger, LOGGER_NAME


def test_get_logger():
    logger = package_get_logger("this_value")
    assert logger.name == "this_value"

    logger = package_get_logger(LOGGER_NAME)
    assert logger.name == LOGGER_NAME

    from openid_whisperer.utils.common import __name__ as test_name

    logger = package_get_logger(test_name)
    assert logger.name == "openid_whisperer.utils"
