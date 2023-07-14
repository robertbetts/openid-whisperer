import logging
from logging import Formatter as LogFormatter
import os
import sys
from typing import Dict, Any, Callable, Tuple

from dotenv import load_dotenv

from openid_whisperer.utils.common import package_get_logger

logger = package_get_logger(__name__)

default_config_type = Dict[str, Tuple[Callable[[Any], Any], Any]]

DEFAULT_LOGGING_FORMAT = "[%(levelname)1.1s %(asctime)s.%(msecs)06d %(process)d %(module)s:%(lineno)d %(name)s] %(message)s"


def load_environment_variables(env_target: str | None = None) -> None:
    """Initialises environment variables from .env and .env_{env_target} named files,
    and in the order mentioned. if env_target is none and the environment variable ENVIRONMENT not set, then
    default both to "DEV". if there are valid values for both, then env_target is applied.

    Environment variables are loaded in the following order:
    1. Process .env if exists in the current directory
    2. Process .env_{env_target} if exists in the current directory

    Parameters
    ----------
    env_target: str | None

    Returns
    -------
        None:
    """
    if "PYTEST_CURRENT_TEST" in os.environ:
        logger.warning(
            "Skipping the loading of the DotEnv file .env when pytest is running."
        )
    else:
        if not os.path.exists(".env"):
            logger.warning(
                "DotEnv file .env not found in the current directory: %s", os.getcwd()
            )  # pragma: no cover
        else:
            logger.warning("loading DotEnv file .env")
            load_dotenv(".env", override=True)

    os_env_target = os.getenv("ENVIRONMENT", "")
    if not os_env_target and not env_target:
        env_target = "DEV"
        logger.warning(
            "Defaulting target environment variable ENVIRONMENT to %s", env_target
        )
        os.environ["ENVIRONMENT"] = env_target
    elif not os_env_target and env_target:
        logger.warning(
            "Defaulting os environment variable ENVIRONMENT to %s", env_target
        )
        os.environ["ENVIRONMENT"] = env_target
    elif not env_target:
        env_target = os_env_target
        logger.warning(
            "Using target environment from variable ENVIRONMENT, %s", env_target
        )
    elif (
        env_target.upper() != os_env_target.upper()
    ):  # check for collision prioritise env_target
        logger.warning(
            "Overriding os environment variable ENVIRONMENT from %s to %s",
            os_env_target,
            env_target,
        )
        os.environ["ENVIRONMENT"] = env_target
    else:
        logger.info("Target environment is %s", env_target)

    env_file_name: str = f".env_{env_target.lower()}"
    if not os.path.exists(env_file_name):
        logger.warning(
            "DotEnv file %s, not found in the current directory, %s",
            env_file_name,
            os.getcwd(),
        )
    else:
        logger.warning("loading DotEnv file %s", env_file_name)
        load_dotenv(env_file_name, override=True)


def get_bind_address(input_value: str) -> list[str]:
    """splits a bind address input string into a list and checks the format.
    if any format issues are found, an empty list is returned

    Parameters
    ----------
    input_value: str
        must be in the form (host|ip):port[,(host|ip):port]
    Returns
    -------
        str

    """
    addresses = [item.strip() for item in input_value.split(",")]
    if any(
        [
            (":" not in item) or (not item.split(":")[-1].isdecimal())
            for item in addresses
        ]
    ):
        logging.warning(
            "Invalid bind address value, must be in the form (host|ip):port[,(host|ip):port] : %s",
            input_value,
        )
        return []
    else:
        return addresses


def initialize_logging(
    log_level: str = "INFO",
    logger_name: str | None = None,
    initialize_flask: bool = False,
) -> None:
    """Returns None after configuring either a package logger or the root logger. Where
    logger_name is 'root' or None, then the root logger is re-initialized. When configuring
    the root logger all active handlers are replaced with a stream handler to stdout, and
    its formatter updated to DEFAULT_LOGGING_FORMAT.

    For all non-root loggers, only the log_level is updated.

    This info is from the Flask docs and is here as a reminder and for reference
    dictConfig({
        'version': 1,
        'formatters': {'default': {
            'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
        }},
        'handlers': {'wsgi': {
            'class': 'logging.StreamHandler',
            'stream': 'ext://flask.logging.wsgi_errors_stream',
            'formatter': 'default'
        }},
        'root': {
            'level': 'INFO',
            'handlers': ['wsgi']
        }
    })

    Parameters
    ----------
    log_level: str
        To specify the logging level, defaults to "INFO"
    logger_name: str | None
        alternative logger name, None == root logger
    initialize_flask: bool
        configures logging for Flask / Werkzeug
    Returns
    -------
        str
    """
    log_level = log_level.upper() if log_level else "INFO"
    root_logger = logging.getLogger(logger_name)
    # perform complete logging initialisation
    if logger_name in ("root", None):
        root_logger.handlers = []
        # initialise a stream logger to stdout
        channel = logging.StreamHandler(stream=sys.stdout)
        channel.setFormatter(LogFormatter(fmt=DEFAULT_LOGGING_FORMAT))
        root_logger.addHandler(channel)
        root_logger.setLevel(logging.INFO)
        root_logger.info("root logger initialized with log_level of %s", log_level)
        if initialize_flask:
            raise NotImplementedError(
                "Flask request logging override feature not implemented"
            )

        root_logger.setLevel(log_level)
    else:
        this_logger = logging.getLogger(logger_name)
        this_logger.setLevel(logging.INFO)
        root_logger.info("%s logger set to log_level %s", logger_name, log_level)
        this_logger.setLevel(log_level)
