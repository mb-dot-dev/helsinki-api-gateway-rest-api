import json
import os
from typing import TYPE_CHECKING

from aws_lambda_powertools.event_handler import Response
import jwt

if TYPE_CHECKING:
    from aws_lambda_powertools.event_handler import ApiGatewayResolver
    from aws_lambda_powertools.event_handler.middlewares import NextMiddleware

from pydantic import BaseModel


class JwtConfig(BaseModel):
    allowed_client_id: str
    allowed_client_secret: str
    signing_secret: str
    issuer: str = "https://auth.molnarbence.dev/"
    audience: str = "api://default"


def get_jwt_config() -> JwtConfig:
    return JwtConfig(
        allowed_client_id=os.environ["ALLOWED_CLIENT_ID"],
        allowed_client_secret=os.environ["ALLOWED_CLIENT_SECRET"],
        signing_secret=os.environ["JWT_SIGNING_SECRET"],
    )


def jwt_bearer(app: ApiGatewayResolver, next_middleware: NextMiddleware) -> Response:
    jwt_config = get_jwt_config()

    auth_header = app.current_event.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return Response(
            status_code=401,
            content_type="application/json",
            body=json.dumps({"message": "Unauthorized"}),
        )

    jwt_token = auth_header.split(" ")[1]

    try:
        jwt.decode(jwt_token, jwt_config.signing_secret, algorithms=["HS256"], audience=jwt_config.audience)
    except jwt.ExpiredSignatureError:
        return Response(
            status_code=401,
            content_type="application/json",
            body=json.dumps({"message": "Token has expired"}),
        )
    except jwt.InvalidTokenError:
        return Response(
            status_code=401,
            content_type="application/json",
            body=json.dumps({"message": "Unauthorized"}),
        )

    return next_middleware(app)
