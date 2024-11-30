from unittest.mock import MagicMock
import pytest
from main import app
from database import get_session

mock_session = MagicMock()


def ovveride_get_session():
    try:
        yield mock_session
    finally:
        pass

app.dependency_overrides[get_session] = ovveride_get_session

@pytest.fixture
def mock_db_session():
    return mock_session