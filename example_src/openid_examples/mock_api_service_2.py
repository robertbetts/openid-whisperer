import logging

from openid_examples.mock_openid_client_lib import OpenIDClient
from openid_examples import mock_api_service_a
from openid_examples.mock_shared_config import config


config.initialize_logging()
logger = logging.getLogger(__name__)

logger.info("Connecting to the identity provider: %s", config.identity_endpoint)
mock_api_service_a.openid_client = OpenIDClient = OpenIDClient(
    provider_url=config.identity_endpoint,
    tenant=config.tenant,
    client_id="CLIENT-5800-DEV",
    scope=config.scope,
    resource="URI:API:CLIENT-5800-API",
    verify_server=config.validate_certs,
)


def main() -> None:
    instance_id = "instance_b"
    app = mock_api_service_a.service_app(instance_id)
    app.run(
        ssl_context="adhoc",
        debug=config.flask_debug,
        host="0.0.0.0",
        # port=config.api_port,
        port=5800,
    )


if __name__ == "__main__":
    main()
