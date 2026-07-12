import json
import time
import urllib.parse

from aws_lambda_powertools import Logger
from aws_lambda_powertools.event_handler.api_gateway import Response
from aws_lambda_powertools.event_handler.router import APIGatewayRouter
import jwt

from app.auth import authenticate_client
from app.jwt import get_jwt_config

logger = Logger()
router = APIGatewayRouter()


@router.post("/oauth/token")
def issue_token() -> Response:
    event = router.current_event
    headers = dict(event.headers or {})
    body = event.body or ""

    content_type = headers.get("content-type", "")
    client_id, client_secret = _get_client_credentials(body, content_type)

    if not authenticate_client(client_id, client_secret):
        logger.warning("OAuth token request with invalid credentials", extra={"clientId": client_id})
        return Response(
            status_code=401,
            content_type="application/json",
            body=json.dumps({"message": "Invalid client credentials"}),
        )

    logger.info("OAuth token request", extra={"contentType": content_type, "clientId": client_id})

    jwt_config = get_jwt_config()

    now = int(time.time())
    claims = {
        "iss": jwt_config.issuer,
        "sub": client_id,
        "azp": client_id,
        "aud": jwt_config.audience,
        "iat": now,
        "exp": now + 3600,
        "scp": ["openid"],
    }

    token = jwt.encode(claims, jwt_config.signing_secret, algorithm="HS256")

    return Response(
        status_code=200,
        content_type="application/json",
        body=json.dumps(
            {
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "openid",
            }
        ),
    )


def _get_client_credentials(body: str, content_type: str) -> tuple[str, str]:
    if "application/json" in content_type:
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                return data.get("client_id", ""), data.get("client_secret", "")
        except json.JSONDecodeError:
            pass
        return "", ""

    params = urllib.parse.parse_qs(body)
    client_id = params.get("client_id", [""])[0]
    client_secret = params.get("client_secret", [""])[0]
    return client_id, client_secret
