""" Module for initialising the OpenID Whisperer running service
"""
from flask import Flask
from openid_whisperer.cert_utils import get_ssl_context
from openid_whisperer.openid_blueprint import openid_blueprint

from openid_whisperer.config import get_cached_config


def app() -> Flask:
    """returns WSGI compliant Object wrapper for openid_whisperer"""
    config = get_cached_config()
    flask_app = Flask(__name__)
    flask_app.register_blueprint(openid_blueprint)
    config.init_logging()
    return flask_app


def main() -> None:  # pragma: no cover
    """Main entrypoint for a standalone Python running instance"""
    config = get_cached_config()
    flask_app: Flask = app()
    flask_app.run(
        ssl_context=get_ssl_context(
            certificate=config.org_cert,
            private_key=config.org_key,
            issuer_certs=[config.ca_cert],
            verify=False,
        ),
        host=config.id_service_bind,
        port=config.id_service_port,
        debug=config.flask_debug,
    )


if __name__ == "__main__":  # pragma: no cover
    main()
