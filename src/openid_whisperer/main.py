""" Module for initialising the OpenID Whisperer running service
"""
from typing import Optional
import secrets
from openid_whisperer.utils.cert_utils import get_ssl_context
from openid_whisperer.openid_blueprint import openid_blueprint
from openid_whisperer.config import get_cached_config

config = get_cached_config()
config.init_logging()


def app(session_cookie_name: Optional[str] = None) -> "Flask":
    """returns WSGI compliant Object wrapper for openid_whisperer"""
    from flask import Flask
    from werkzeug.middleware.proxy_fix import ProxyFix
    from flask_session import Session
    flask_app = Flask(
        "openid_whisperer",
        static_folder=None,
    )
    flask_app.secret_key = secrets.token_urlsafe(46)
    session_cookie_name = session_cookie_name if session_cookie_name else "openid-whisperer"
    flask_app.config.update(
        SESSION_COOKIE_NAME=session_cookie_name,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_PERMANENT=True,
        SESSION_TYPE="filesystem",
    )
    flask_app.wsgi_app = ProxyFix(
        flask_app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
    )
    Session(flask_app)
    flask_app.register_blueprint(openid_blueprint)
    return flask_app


def main() -> None:  # pragma: no cover
    """Main entrypoint for a standalone Python running instance"""
    ca_certs = [config.ca_cert] if config.ca_cert else None
    flask_app: "Flask" = app()
    flask_app.run(
        ssl_context=get_ssl_context(
            certificate=config.org_cert,
            private_key=config.org_key,
            issuer_certs=ca_certs,
            verify=config.validate_certs,
        ),
        host=config.id_service_bind,
        port=config.id_service_port,
        debug=config.flask_debug,
    )


if __name__ == "__main__":  # pragma: no cover
    main()
