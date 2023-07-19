""" Module for initialising the OpenID Whisperer running service
"""
from openid_whisperer.utils.cert_utils import get_ssl_context
from openid_whisperer.openid_blueprint import openid_blueprint
from openid_whisperer.config import get_cached_config

config = get_cached_config()
config.init_logging()


def add_mock_client_secret_key():
    from openid_whisperer.openid_blueprint import openid_api_interface as openid_api
    client_id = "CLIENT-90274-DEV"
    client_key_info = {
        "key_id": "dGh1bWJwcmludF92YWx1ZQ==",
        "key_issuer": client_id,
        "algorithm": "RS256",
        "public_key": openid_api.token_store.token_issuer_private_key.public_key()
    }
    try:
        openid_api.token_store.add_client_secret(client_id=client_id, **client_key_info)
    except KeyError:
        pass


def app() -> "Flask":
    """returns WSGI compliant Object wrapper for openid_whisperer"""
    from flask import Flask
    flask_app = Flask("openid_whisperer")
    flask_app.register_blueprint(openid_blueprint)

    add_mock_client_secret_key()

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
            verify=False,
        ),
        host=config.id_service_bind,
        port=config.id_service_port,
        debug=config.flask_debug,
    )


if __name__ == "__main__":  # pragma: no cover
    main()
