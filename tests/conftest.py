import pytest

from openid_whisperer import main
from openid_whisperer.config import config as whisperer_config

@pytest.fixture
def app():
    app = main.app()
    yield app


@pytest.fixture
def config():
    yield whisperer_config


@pytest.fixture
def client(app):
    return app.test_client()
