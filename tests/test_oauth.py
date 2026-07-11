import json
from typing import TYPE_CHECKING, Any

import jwt

from app.main import lambda_handler
from app.oauth import _get_client_credentials
from tests.conftest import ALLOWED_CLIENT_ID, ALLOWED_CLIENT_SECRET, AUDIENCE, JWT_SIGNING_SECRET

if TYPE_CHECKING:
    from collections.abc import Callable

    from tests.conftest import LambdaContext


def test_get_client_credentials_returns_empty_strings_for_empty_json_body() -> None:
    assert _get_client_credentials("", "application/json") == ("", "")


def test_get_client_credentials_reads_credentials_from_json_body() -> None:
    body = json.dumps({"client_id": "json-client", "client_secret": "json-secret"})

    assert _get_client_credentials(body, "application/json") == ("json-client", "json-secret")


def test_get_client_credentials_returns_empty_strings_for_malformed_json() -> None:
    assert _get_client_credentials("{not json", "application/json") == ("", "")


def test_get_client_credentials_returns_empty_strings_when_json_body_is_not_an_object() -> None:
    assert _get_client_credentials("[1, 2, 3]", "application/json") == ("", "")


def test_get_client_credentials_reads_credentials_from_form_encoded_body() -> None:
    body = "client_id=form-client&client_secret=hunter2"

    assert _get_client_credentials(body, "application/x-www-form-urlencoded") == ("form-client", "hunter2")


def test_get_client_credentials_returns_empty_strings_for_form_encoded_body_without_credentials() -> None:
    body = "other_param=value"

    assert _get_client_credentials(body, "application/x-www-form-urlencoded") == ("", "")


def test_issue_token_rejects_for_empty_body(
    make_event: Callable[..., dict[str, Any]],
    lambda_context: LambdaContext,
) -> None:
    event = make_event("POST", "/oauth/token", body="")

    response = lambda_handler(event, lambda_context)

    assert response["statusCode"] == 401
    payload = json.loads(response["body"])
    assert payload["message"] == "Invalid client credentials"


def test_issue_token_with_valid_credentials_from_json_body(
    make_event: Callable[..., dict[str, Any]],
    lambda_context: LambdaContext,
) -> None:
    event = make_event(
        "POST",
        "/oauth/token",
        headers={"Content-Type": "application/json"},
        body=json.dumps({"client_id": ALLOWED_CLIENT_ID, "client_secret": ALLOWED_CLIENT_SECRET}),
    )

    response = lambda_handler(event, lambda_context)

    assert response["statusCode"] == 200
    payload = json.loads(response["body"])
    assert payload["token_type"] == "Bearer"
    assert payload["expires_in"] == 3600
    assert payload["scope"] == "openid"

    claims = jwt.decode(payload["access_token"], JWT_SIGNING_SECRET, algorithms=["HS256"], audience=AUDIENCE)
    assert claims["sub"] == ALLOWED_CLIENT_ID
    assert claims["azp"] == ALLOWED_CLIENT_ID


def test_issue_token_rejects_with_invalid_client_id(
    make_event: Callable[..., dict[str, Any]],
    lambda_context: LambdaContext,
) -> None:
    event = make_event(
        "POST",
        "/oauth/token",
        headers={"Content-Type": "application/json"},
        body=json.dumps({"client_id": "wrong-client", "client_secret": ALLOWED_CLIENT_SECRET}),
    )

    response = lambda_handler(event, lambda_context)

    assert response["statusCode"] == 401
    payload = json.loads(response["body"])
    assert payload["message"] == "Invalid client credentials"


def test_issue_token_rejects_with_invalid_client_secret(
    make_event: Callable[..., dict[str, Any]],
    lambda_context: LambdaContext,
) -> None:
    event = make_event(
        "POST",
        "/oauth/token",
        headers={"Content-Type": "application/json"},
        body=json.dumps({"client_id": ALLOWED_CLIENT_ID, "client_secret": "wrong-secret"}),
    )

    response = lambda_handler(event, lambda_context)

    assert response["statusCode"] == 401
    payload = json.loads(response["body"])
    assert payload["message"] == "Invalid client credentials"


def test_issue_token_with_credentials_from_form_body(
    make_event: Callable[..., dict[str, Any]],
    lambda_context: LambdaContext,
) -> None:
    event = make_event(
        "POST",
        "/oauth/token",
        headers={"content-type": "application/x-www-form-urlencoded"},
        body=f"client_id={ALLOWED_CLIENT_ID}&client_secret={ALLOWED_CLIENT_SECRET}",
    )

    response = lambda_handler(event, lambda_context)

    assert response["statusCode"] == 200
    payload = json.loads(response["body"])
    claims = jwt.decode(payload["access_token"], JWT_SIGNING_SECRET, algorithms=["HS256"], audience=AUDIENCE)
    assert claims["sub"] == ALLOWED_CLIENT_ID
