""" Module for initialising the openid_whisperer running service
"""
from flask import Flask
from openid_whisperer.cert_utils import get_ssl_context
from openid_whisperer.openid_blueprint import openid_blueprint

from openid_whisperer.config import config
from openid_whisperer.config import FLASK_DEBUG, IDP_SERVICE_PORT, IDP_SERVICE_BINDING


def app() -> Flask:
    """ returns WSGI compliant Object wrapper for openid_whisperer
    """
    config.initialize_logging()
    flask_app = Flask(__name__)
    flask_app.register_blueprint(openid_blueprint)
    return flask_app


def main() -> None:  # pragma: no cover
    """ Main entrypoint for a standalone Python running instance
    """
    flask_app: Flask = app()
    flask_app.run(
        ssl_context=get_ssl_context(verify=False),
        host=IDP_SERVICE_BINDING,
        port=IDP_SERVICE_PORT,
        debug=FLASK_DEBUG
    )


if __name__ == "__main__":  # pragma: no cover
    main()
    