import logging
from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import RedirectResponse

from src.adapters.keycloak import KeycloakClient
from src.providers import Stub

logger = logging.getLogger(__name__)

auth_router = APIRouter(
    prefix="/auth",
    tags=["auth"],
)


@auth_router.get("/login")
async def login(
    keycloak: Annotated[KeycloakClient, Depends(Stub(KeycloakClient))],
):
    login_url = await keycloak.get_login_url()

    logger.debug("Redirecting to login URL", extra={"login_url": login_url})

    return RedirectResponse(login_url)


@auth_router.get("/token")
async def token(
    keycloak: Annotated[KeycloakClient, Depends(Stub(KeycloakClient))],
):
    openid_configuration = await keycloak.get_openid_configuration()

    token_url = openid_configuration.token_endpoint

    logger.debug("Redirecting to token URL", extra={"token_url": token_url})

    return RedirectResponse(token_url)


@auth_router.get("/callback")
async def get_user(
    session_state: str,
    code: str,
    keycloak: Annotated[KeycloakClient, Depends(Stub(KeycloakClient))],
):
    logger.debug("Got callback", extra={"session_state": session_state, "code": code})

    keycloak_tokens = await keycloak.exchange_authorization_code(session_state, code)

    logger.debug("Got tokens", extra={"keycloak_tokens": keycloak_tokens})

    return "Get callback"
