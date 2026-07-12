import pytest

from app.auth import authenticate_client, get_auth_config
from app.main import init_config
from tests.conftest import ALLOWED_CLIENT_ID, ALLOWED_CLIENT_SECRET


@pytest.fixture(autouse=True)
def _init_config() -> None:
    init_config()


def test_get_auth_config_reads_allowed_credentials_from_config() -> None:
    auth_config = get_auth_config()

    assert auth_config.allowed_client_id == ALLOWED_CLIENT_ID
    assert auth_config.allowed_client_secret == ALLOWED_CLIENT_SECRET


def test_get_auth_config_is_cached() -> None:
    assert get_auth_config() is get_auth_config()


def test_authenticate_client_accepts_valid_credentials() -> None:
    assert authenticate_client(ALLOWED_CLIENT_ID, ALLOWED_CLIENT_SECRET) is True


def test_authenticate_client_rejects_invalid_client_id() -> None:
    assert authenticate_client("wrong-client", ALLOWED_CLIENT_SECRET) is False


def test_authenticate_client_rejects_invalid_client_secret() -> None:
    assert authenticate_client(ALLOWED_CLIENT_ID, "wrong-secret") is False


def test_authenticate_client_rejects_empty_credentials() -> None:
    assert authenticate_client("", "") is False
