import json
import os
from typing import TYPE_CHECKING

from aws_lambda_powertools import Logger, Metrics
from aws_lambda_powertools.event_handler.api_gateway import Response
from aws_lambda_powertools.event_handler.router import APIGatewayRouter
from aws_lambda_powertools.metrics import MetricUnit
from botocore.exceptions import ClientError
import jwt

from app.clients import get_sqs_client

if TYPE_CHECKING:
    from aws_lambda_powertools.event_handler.api_gateway import ApiGatewayResolver
    from aws_lambda_powertools.event_handler.middlewares import NextMiddleware

logger = Logger()
metrics = Metrics(namespace="Helsinki")
router = APIGatewayRouter()


def jwt_bearer(app: ApiGatewayResolver, next_middleware: NextMiddleware) -> Response:
    auth_header = app.current_event.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return Response(
            status_code=401,
            content_type="application/json",
            body=json.dumps({"message": "Unauthorized"}),
        )

    jwt_token = auth_header.split(" ")[1]

    signing_secret = os.environ["JWT_SIGNING_SECRET"]

    try:
        jwt.decode(jwt_token, signing_secret, algorithms=["HS256"], audience="api://default")
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


@router.post("/", middlewares=[jwt_bearer])
def enqueue() -> Response:
    event_body = router.current_event.body

    if not event_body:
        return Response(
            status_code=400,
            content_type="application/json",
            body=json.dumps({"message": "Request body is required"}),
        )

    try:
        result = get_sqs_client().send_message(QueueUrl=os.environ["QUEUE_URL"], MessageBody=event_body)
    except ClientError:
        metrics.add_metric(name="EnqueueFailure", unit=MetricUnit.Count, value=1)
        return Response(
            status_code=500,
            content_type="application/json",
            body=json.dumps({"message": "Internal Server Error"}),
        )

    logger.info(
        "Request allowed and enqueued",
        extra={
            "decision": "ALLOW",
            "messageId": result["MessageId"],
        },
    )
    return Response(status_code=202, content_type="application/json", body=json.dumps({"message": "Accepted"}))
