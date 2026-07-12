from typing import TYPE_CHECKING

from mb_config.config_manager import ConfigManager
from mb_config.loaders import ssm_param_loader

if TYPE_CHECKING:
    import pytest

FAKE_PARAMETERS = {
    "/projects/helsinki/allowed-client-id": {"Type": "String", "Value": "prod-client-id"},
    "/projects/helsinki/allowed-client-secret": {"Type": "SecureString", "Value": "prod-client-secret"},
    "/projects/helsinki/jwt-signing-secret": {"Type": "SecureString", "Value": "prod-signing-secret"},
}


class FakeSsmClient:
    def get_parameter(self, *, Name: str, WithDecryption: bool = False) -> dict:  # noqa: N803, ARG002
        parameter = FAKE_PARAMETERS[Name]
        return {"Parameter": {"Type": parameter["Type"], "Value": parameter["Value"]}}


def test_prod_config_resolves_ssm_parameters(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ssm_param_loader, "_create_client", FakeSsmClient)

    config = (
        ConfigManager()
        .add_yaml("app/configs/default.yaml")
        .add_yaml("app/configs/prod.yaml")
        .add_ssm_parameters()
        .get_config()
    )

    assert config["auth"]["allowed_client_id"] == FAKE_PARAMETERS["/projects/helsinki/allowed-client-id"]["Value"]
    assert (
        config["auth"]["allowed_client_secret"] == FAKE_PARAMETERS["/projects/helsinki/allowed-client-secret"]["Value"]
    )
    assert config["jwt"]["signing_secret"] == FAKE_PARAMETERS["/projects/helsinki/jwt-signing-secret"]["Value"]
    assert "ssm_params" not in config
