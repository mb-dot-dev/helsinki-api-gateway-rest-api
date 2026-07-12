from functools import cache
from typing import ClassVar

from mb_config import get_config
from pydantic import BaseModel


class AuthConfig(BaseModel):
    section_name: ClassVar[str] = "auth"

    allowed_client_id: str
    allowed_client_secret: str


@cache
def get_auth_config() -> AuthConfig:
    app_config = get_config()
    return AuthConfig.model_validate(app_config[AuthConfig.section_name])


def authenticate_client(client_id: str, client_secret: str) -> bool:
    auth_config = get_auth_config()
    return client_id == auth_config.allowed_client_id and client_secret == auth_config.allowed_client_secret
