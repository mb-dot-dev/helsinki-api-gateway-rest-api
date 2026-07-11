import json
import os
import time
import urllib.parse

from aws_lambda_powertools import Logger
from aws_lambda_powertools.event_handler.api_gateway import Response
from aws_lambda_powertools.event_handler.router import APIGatewayRouter
import jwt

logger = Logger()
router = APIGatewayRouter()

_DEFAULT_ISSUER = "https://auth.molnarbence.dev/"


@router.post("/oauth/token")
def issue_token() -> Response:
    event = router.current_event
    headers = dict(event.headers or {})
    body = event.body or ""

    content_type = headers.get("content-type", "")
    client_id = _parse_client_id(body, content_type)

    logger.info("OAuth token request", extra={"contentType": content_type, "clientId": client_id})

    now = int(time.time())
    claims = {
        "iss": _DEFAULT_ISSUER,
        "sub": client_id,
        "azp": client_id,
        "aud": "api://default",
        "iat": now,
        "exp": now + 3600,
        "scp": ["openid"],
    }

    signing_secret = os.environ["JWT_SIGNING_SECRET"]

    token = jwt.encode(claims, signing_secret, algorithm="HS256")

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


def _parse_client_id(body: str, content_type: str) -> str:
    if not body:
        return "mock-client"
    if "application/json" in content_type:
        try:
            data = json.loads(body)
            return data.get("client_id", "mock-client") if isinstance(data, dict) else "mock-client"
        except json.JSONDecodeError:
            return "mock-client"
    params = urllib.parse.parse_qs(body)
    values = params.get("client_id", ["mock-client"])
    return values[0]
