import pytest

from openid_whisperer import main


@pytest.fixture
def app():
    app = main.app()
    yield app


@pytest.fixture
def client(app):
    return app.test_client()
