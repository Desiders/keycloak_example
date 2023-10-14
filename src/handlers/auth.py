import logging
from typing import Annotated

from fastapi import APIRouter, Depends, status
from fastapi.responses import ORJSONResponse, RedirectResponse

from src.adapters.keycloak import KeycloakClient, KeycloakTokens
from src.providers import Stub

logger = logging.getLogger(__name__)

auth_router = APIRouter(
    prefix="/auth",
    tags=["auth"],
)


@auth_router.get(
    "/login",
    response_class=RedirectResponse,
    status_code=status.HTTP_307_TEMPORARY_REDIRECT,
    description="Redirect to keycloak login URL",
)
async def login(
    keycloak: Annotated[KeycloakClient, Depends(Stub(KeycloakClient))],
) -> str:
    login_url = await keycloak.get_login_url()

    logger.debug("Redirecting to login URL", extra={"login_url": login_url})

    return login_url


@auth_router.get(
    "/token",
    response_class=RedirectResponse,
    status_code=status.HTTP_307_TEMPORARY_REDIRECT,
    description="Redirect to keycloak token URL",
)
async def token(
    keycloak: Annotated[KeycloakClient, Depends(Stub(KeycloakClient))],
) -> str:
    openid_configuration = await keycloak.get_openid_configuration()

    token_url = openid_configuration.token_endpoint

    logger.debug("Redirecting to token URL", extra={"token_url": token_url})

    return token_url


@auth_router.get(
    "/callback",
    response_model=KeycloakTokens,
    response_class=ORJSONResponse,
    status_code=status.HTTP_200_OK,
)
async def get_tokens(
    session_state: str,
    code: str,
    keycloak: Annotated[KeycloakClient, Depends(Stub(KeycloakClient))],
) -> KeycloakTokens:
    logger.debug("Got callback", extra={"session_state": session_state, "code": code})

    keycloak_tokens = await keycloak.exchange_authorization_code(session_state, code)

    logger.debug("Got tokens", extra={"keycloak_tokens": keycloak_tokens})

    return keycloak_tokens
