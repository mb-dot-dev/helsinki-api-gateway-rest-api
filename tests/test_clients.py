from app.clients import get_sqs_client


def test_get_sqs_client_returns_an_sqs_client() -> None:
    client = get_sqs_client()

    assert client.meta.service_model.service_name == "sqs"


def test_get_sqs_client_is_cached() -> None:
    assert get_sqs_client() is get_sqs_client()
