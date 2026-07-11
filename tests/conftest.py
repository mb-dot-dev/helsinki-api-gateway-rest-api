import time
from typing import TYPE_CHECKING, Any

import jwt
import pytest

if TYPE_CHECKING:
    from collections.abc import Callable

JWT_SIGNING_SECRET = "unit-test-signing-secret-0123456789"
AUDIENCE = "api://default"
ISSUER = "https://auth.molnarbence.dev/"
QUEUE_NAME = "test-queue"
QUEUE_URL = f"https://sqs.eu-west-1.amazonaws.com/123456789012/{QUEUE_NAME}"
ALLOWED_CLIENT_ID = "test-client"
ALLOWED_CLIENT_SECRET = "test-secret"


@pytest.fixture(autouse=True)
def _lambda_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("JWT_SIGNING_SECRET", JWT_SIGNING_SECRET)
    monkeypatch.setenv("QUEUE_URL", QUEUE_URL)
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("ALLOWED_CLIENT_ID", ALLOWED_CLIENT_ID)
    monkeypatch.setenv("ALLOWED_CLIENT_SECRET", ALLOWED_CLIENT_SECRET)


class LambdaContext:
    function_name = "test-function"
    memory_limit_in_mb = 128
    invoked_function_arn = "arn:aws:lambda:eu-west-1:123456789012:function:test-function"
    aws_request_id = "test-request-id"


@pytest.fixture
def lambda_context() -> LambdaContext:
    return LambdaContext()


@pytest.fixture
def make_event() -> Callable[..., dict[str, Any]]:
    def _make_event(
        method: str,
        path: str,
        headers: dict[str, str] | None = None,
        body: str | None = None,
    ) -> dict[str, Any]:
        return {
            "httpMethod": method,
            "path": path,
            "headers": headers or {},
            "multiValueHeaders": {},
            "queryStringParameters": None,
            "multiValueQueryStringParameters": None,
            "pathParameters": None,
            "body": body,
            "isBase64Encoded": False,
            "requestContext": {
                "httpMethod": method,
                "resourcePath": path,
                "path": path,
            },
        }

    return _make_event


@pytest.fixture
def make_token() -> Callable[..., str]:
    def _make_token(
        *,
        secret: str = JWT_SIGNING_SECRET,
        audience: str | None = AUDIENCE,
        expires_in: int = 3600,
        subject: str = "mock-client",
    ) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": ISSUER,
            "sub": subject,
            "azp": subject,
            "iat": now,
            "exp": now + expires_in,
            "scp": ["openid"],
        }
        if audience is not None:
            claims["aud"] = audience
        return jwt.encode(claims, secret, algorithm="HS256")

    return _make_token
