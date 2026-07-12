import json
from typing import TYPE_CHECKING, Any, cast

from aws_lambda_powertools.event_handler import APIGatewayRestResolver
import pytest

from app.jwt import get_jwt_config, jwt_bearer
from app.main import init_config
from tests.conftest import AUDIENCE, JWT_SIGNING_SECRET

if TYPE_CHECKING:
    from collections.abc import Callable

    from aws_lambda_powertools.utilities.typing import LambdaContext as PowertoolsLambdaContext

    from tests.conftest import LambdaContext


@pytest.fixture(autouse=True)
def _init_config() -> None:
    init_config()


def _build_resolver() -> APIGatewayRestResolver:
    resolver = APIGatewayRestResolver()

    @resolver.get("/protected", middlewares=[jwt_bearer])
    def protected() -> dict[str, str]:
        return {"message": "ok"}

    return resolver


def _resolve(resolver: APIGatewayRestResolver, event: dict[str, Any], context: LambdaContext) -> dict[str, Any]:
    return resolver.resolve(event, cast("PowertoolsLambdaContext", context))


def test_get_jwt_config_reads_settings_from_config() -> None:
    jwt_config = get_jwt_config()

    assert jwt_config.signing_secret == JWT_SIGNING_SECRET
    assert jwt_config.audience == AUDIENCE


def test_get_jwt_config_is_cached() -> None:
    assert get_jwt_config() is get_jwt_config()


def test_jwt_bearer_rejects_missing_authorization_header(
    make_event: Callable[..., dict[str, Any]],
    lambda_context: LambdaContext,
) -> None:
    event = make_event("GET", "/protected")

    response = _resolve(_build_resolver(), event, lambda_context)

    assert response["statusCode"] == 401
    assert json.loads(response["body"])["message"] == "Unauthorized"


def test_jwt_bearer_rejects_non_bearer_scheme(
    make_event: Callable[..., dict[str, Any]],
    lambda_context: LambdaContext,
) -> None:
    event = make_event("GET", "/protected", headers={"Authorization": "Basic dXNlcjpwYXNz"})

    response = _resolve(_build_resolver(), event, lambda_context)

    assert response["statusCode"] == 401
    assert json.loads(response["body"])["message"] == "Unauthorized"


def test_jwt_bearer_rejects_expired_token(
    make_event: Callable[..., dict[str, Any]],
    make_token: Callable[..., str],
    lambda_context: LambdaContext,
) -> None:
    event = make_event("GET", "/protected", headers={"Authorization": f"Bearer {make_token(expires_in=-10)}"})

    response = _resolve(_build_resolver(), event, lambda_context)

    assert response["statusCode"] == 401
    assert json.loads(response["body"])["message"] == "Token has expired"


def test_jwt_bearer_rejects_token_signed_with_wrong_secret(
    make_event: Callable[..., dict[str, Any]],
    make_token: Callable[..., str],
    lambda_context: LambdaContext,
) -> None:
    token = make_token(secret="a-completely-different-signing-secret")
    event = make_event("GET", "/protected", headers={"Authorization": f"Bearer {token}"})

    response = _resolve(_build_resolver(), event, lambda_context)

    assert response["statusCode"] == 401
    assert json.loads(response["body"])["message"] == "Unauthorized"


def test_jwt_bearer_rejects_token_with_wrong_audience(
    make_event: Callable[..., dict[str, Any]],
    make_token: Callable[..., str],
    lambda_context: LambdaContext,
) -> None:
    token = make_token(audience="wrong-audience")
    event = make_event("GET", "/protected", headers={"Authorization": f"Bearer {token}"})

    response = _resolve(_build_resolver(), event, lambda_context)

    assert response["statusCode"] == 401


def test_jwt_bearer_rejects_malformed_token(
    make_event: Callable[..., dict[str, Any]],
    lambda_context: LambdaContext,
) -> None:
    event = make_event("GET", "/protected", headers={"Authorization": "Bearer not-a-jwt"})

    response = _resolve(_build_resolver(), event, lambda_context)

    assert response["statusCode"] == 401


def test_jwt_bearer_accepts_valid_token(
    make_event: Callable[..., dict[str, Any]],
    make_token: Callable[..., str],
    lambda_context: LambdaContext,
) -> None:
    event = make_event("GET", "/protected", headers={"Authorization": f"Bearer {make_token()}"})

    response = _resolve(_build_resolver(), event, lambda_context)

    assert response["statusCode"] == 200
    assert json.loads(response["body"]) == {"message": "ok"}
