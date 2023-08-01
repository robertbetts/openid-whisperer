import logging

from openid_examples.mock_shared_config import config
from openid_examples.mock_api_service_a import service_app

config.initialize_logging()
logger = logging.getLogger(__name__)


def main() -> None:
    instance_id = "instance_b"
    app = service_app(instance_id)
    app.run(
        ssl_context="adhoc",
        debug=config.flask_debug,
        host="0.0.0.0",
        # port=config.api_port,
        port=5701,
    )


if __name__ == "__main__":
    main()
