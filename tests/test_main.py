from typing import TYPE_CHECKING, Any

from app.main import lambda_handler

if TYPE_CHECKING:
    from collections.abc import Callable

    from tests.conftest import LambdaContext


def test_unknown_route_returns_not_found(
    make_event: Callable[..., dict[str, Any]],
    lambda_context: LambdaContext,
) -> None:
    event = make_event("GET", "/unknown")

    response = lambda_handler(event, lambda_context)

    assert response["statusCode"] == 404
