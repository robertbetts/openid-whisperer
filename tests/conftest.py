import pytest

from openid_whisperer import main
from openid_whisperer.config import get_cached_config


@pytest.fixture
def app():
    app = main.app()
    yield app


@pytest.fixture
def config():
    yield get_cached_config()


@pytest.fixture
def client(app):
    return app.test_client()
