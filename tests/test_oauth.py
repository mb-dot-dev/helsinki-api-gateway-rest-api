import json
from typing import TYPE_CHECKING, Any

import jwt

from app.main import lambda_handler
from app.oauth import _parse_client_id
from tests.conftest import AUDIENCE, JWT_SIGNING_SECRET

if TYPE_CHECKING:
    from collections.abc import Callable

    from tests.conftest import LambdaContext


class TestParseClientId:
    def test_returns_mock_client_for_empty_body(self) -> None:
        assert _parse_client_id("", "application/json") == "mock-client"

    def test_reads_client_id_from_json_body(self) -> None:
        body = json.dumps({"client_id": "json-client"})

        assert _parse_client_id(body, "application/json") == "json-client"

    def test_returns_mock_client_for_malformed_json(self) -> None:
        assert _parse_client_id("{not json", "application/json") == "mock-client"

    def test_returns_mock_client_when_json_body_is_not_an_object(self) -> None:
        assert _parse_client_id("[1, 2, 3]", "application/json") == "mock-client"

    def test_reads_client_id_from_form_encoded_body(self) -> None:
        body = "client_id=form-client&client_secret=hunter2"

        assert _parse_client_id(body, "application/x-www-form-urlencoded") == "form-client"

    def test_returns_mock_client_for_form_encoded_body_without_client_id(self) -> None:
        body = "client_secret=hunter2"

        assert _parse_client_id(body, "application/x-www-form-urlencoded") == "mock-client"


class TestIssueToken:
    def test_issues_token_for_empty_body(
        self,
        make_event: Callable[..., dict[str, Any]],
        lambda_context: LambdaContext,
    ) -> None:
        event = make_event("POST", "/oauth/token", body="")

        response = lambda_handler(event, lambda_context)

        assert response["statusCode"] == 200
        payload = json.loads(response["body"])
        assert payload["token_type"] == "Bearer"
        assert payload["expires_in"] == 3600
        assert payload["scope"] == "openid"

        claims = jwt.decode(payload["access_token"], JWT_SIGNING_SECRET, algorithms=["HS256"], audience=AUDIENCE)
        assert claims["sub"] == "mock-client"
        assert claims["azp"] == "mock-client"

    def test_issues_token_with_client_id_from_json_body(
        self,
        make_event: Callable[..., dict[str, Any]],
        lambda_context: LambdaContext,
    ) -> None:
        event = make_event(
            "POST",
            "/oauth/token",
            headers={"Content-Type": "application/json"},
            body=json.dumps({"client_id": "acme-client"}),
        )

        response = lambda_handler(event, lambda_context)

        payload = json.loads(response["body"])
        claims = jwt.decode(payload["access_token"], JWT_SIGNING_SECRET, algorithms=["HS256"], audience=AUDIENCE)
        assert claims["sub"] == "acme-client"
        assert claims["azp"] == "acme-client"

    def test_issues_token_with_client_id_from_form_body(
        self,
        make_event: Callable[..., dict[str, Any]],
        lambda_context: LambdaContext,
    ) -> None:
        event = make_event(
            "POST",
            "/oauth/token",
            headers={"content-type": "application/x-www-form-urlencoded"},
            body="client_id=form-client",
        )

        response = lambda_handler(event, lambda_context)

        payload = json.loads(response["body"])
        claims = jwt.decode(payload["access_token"], JWT_SIGNING_SECRET, algorithms=["HS256"], audience=AUDIENCE)
        assert claims["sub"] == "form-client"
