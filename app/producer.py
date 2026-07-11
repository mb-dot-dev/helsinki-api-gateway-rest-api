import json
import os

from aws_lambda_powertools import Logger, Metrics
from aws_lambda_powertools.event_handler.api_gateway import Response
from aws_lambda_powertools.event_handler.router import APIGatewayRouter
from aws_lambda_powertools.metrics import MetricUnit
from botocore.exceptions import ClientError

from app.clients import get_sqs_client
from app.jwt import jwt_bearer

logger = Logger()
metrics = Metrics(namespace="Helsinki")
router = APIGatewayRouter()


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
