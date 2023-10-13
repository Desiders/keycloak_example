from fastapi import FastAPI

from src.config import Keycloak as KeycloakConfig

from .keycloak import KeycloakClient
from .stub import Stub


def setup_providers(app: FastAPI, keycloak_config: KeycloakConfig) -> None:
    keycloak_admin_client = KeycloakClient(
        base_url=f"{keycloak_config.host_for_api}:{keycloak_config.port}",
        realm_id=keycloak_config.realm_id,
        client_id=keycloak_config.client_id,
        client_secret=keycloak_config.client_secret,
        admin_client_id=keycloak_config.admin_client_id,
        admin_client_secret=keycloak_config.admin_client_secret,
        callback_url=keycloak_config.callback_url,
    )

    app.dependency_overrides[Stub(KeycloakClient)] = lambda: keycloak_admin_client
