import json
from typing import TYPE_CHECKING, Any

import boto3
from moto import mock_aws
import pytest

from app.main import lambda_handler
from tests.conftest import QUEUE_NAME, QUEUE_URL

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from botocore.client import BaseClient

    from tests.conftest import LambdaContext


@pytest.fixture(autouse=True)
def sqs_client() -> Iterator[BaseClient]:
    with mock_aws():
        client = boto3.client("sqs", region_name="eu-west-1")
        client.create_queue(QueueName=QUEUE_NAME)
        yield client


def _enqueue_event(
    make_event: Callable[..., dict[str, Any]],
    token: str | None = None,
    body: str | None = "hello",
    *,
    authorization_header: str = "Authorization",
) -> dict[str, Any]:
    headers = {authorization_header: f"Bearer {token}"} if token is not None else {}
    return make_event("POST", "/", headers=headers, body=body)


class TestEnqueue:
    def test_accepts_request_with_valid_token(
        self,
        make_event: Callable[..., dict[str, Any]],
        make_token: Callable[..., str],
        lambda_context: LambdaContext,
        sqs_client: BaseClient,
    ) -> None:
        event = _enqueue_event(make_event, token=make_token())

        response = lambda_handler(event, lambda_context)

        assert response["statusCode"] == 202
        messages = sqs_client.receive_message(QueueUrl=QUEUE_URL).get("Messages", [])
        assert messages[0]["Body"] == "hello"

    def test_accepts_lowercase_authorization_header(
        self,
        make_event: Callable[..., dict[str, Any]],
        make_token: Callable[..., str],
        lambda_context: LambdaContext,
    ) -> None:
        event = _enqueue_event(make_event, token=make_token(), authorization_header="authorization")

        response = lambda_handler(event, lambda_context)

        assert response["statusCode"] == 202

    def test_rejects_missing_authorization_header(
        self,
        make_event: Callable[..., dict[str, Any]],
        lambda_context: LambdaContext,
    ) -> None:
        event = _enqueue_event(make_event, token=None)

        response = lambda_handler(event, lambda_context)

        assert response["statusCode"] == 401
        assert json.loads(response["body"])["message"] == "Unauthorized"

    def test_rejects_non_bearer_scheme(
        self,
        make_event: Callable[..., dict[str, Any]],
        lambda_context: LambdaContext,
    ) -> None:
        event = make_event("POST", "/", headers={"Authorization": "Basic dXNlcjpwYXNz"}, body="hello")

        response = lambda_handler(event, lambda_context)

        assert response["statusCode"] == 401

    def test_rejects_expired_token(
        self,
        make_event: Callable[..., dict[str, Any]],
        make_token: Callable[..., str],
        lambda_context: LambdaContext,
    ) -> None:
        event = _enqueue_event(make_event, token=make_token(expires_in=-10))

        response = lambda_handler(event, lambda_context)

        assert response["statusCode"] == 401
        assert json.loads(response["body"])["message"] == "Token has expired"

    def test_rejects_token_signed_with_wrong_secret(
        self,
        make_event: Callable[..., dict[str, Any]],
        make_token: Callable[..., str],
        lambda_context: LambdaContext,
    ) -> None:
        event = _enqueue_event(make_event, token=make_token(secret="a-completely-different-signing-secret"))

        response = lambda_handler(event, lambda_context)

        assert response["statusCode"] == 401
        assert json.loads(response["body"])["message"] == "Unauthorized"

    def test_rejects_token_with_wrong_audience(
        self,
        make_event: Callable[..., dict[str, Any]],
        make_token: Callable[..., str],
        lambda_context: LambdaContext,
    ) -> None:
        event = _enqueue_event(make_event, token=make_token(audience="wrong-audience"))

        response = lambda_handler(event, lambda_context)

        assert response["statusCode"] == 401

    def test_rejects_malformed_token(
        self,
        make_event: Callable[..., dict[str, Any]],
        lambda_context: LambdaContext,
    ) -> None:
        event = make_event("POST", "/", headers={"Authorization": "Bearer not-a-jwt"}, body="hello")

        response = lambda_handler(event, lambda_context)

        assert response["statusCode"] == 401

    def test_rejects_empty_body(
        self,
        make_event: Callable[..., dict[str, Any]],
        make_token: Callable[..., str],
        lambda_context: LambdaContext,
    ) -> None:
        event = _enqueue_event(make_event, token=make_token(), body="")

        response = lambda_handler(event, lambda_context)

        assert response["statusCode"] == 400

    def test_rejects_missing_body(
        self,
        make_event: Callable[..., dict[str, Any]],
        make_token: Callable[..., str],
        lambda_context: LambdaContext,
    ) -> None:
        event = _enqueue_event(make_event, token=make_token(), body=None)

        response = lambda_handler(event, lambda_context)

        assert response["statusCode"] == 400

    def test_returns_server_error_when_queue_does_not_exist(
        self,
        monkeypatch: pytest.MonkeyPatch,
        make_event: Callable[..., dict[str, Any]],
        make_token: Callable[..., str],
        lambda_context: LambdaContext,
    ) -> None:
        monkeypatch.setenv("QUEUE_URL", "https://sqs.eu-west-1.amazonaws.com/123456789012/does-not-exist")
        event = _enqueue_event(make_event, token=make_token())

        response = lambda_handler(event, lambda_context)

        assert response["statusCode"] == 500
