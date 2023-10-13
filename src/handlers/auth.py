import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, status
from fastapi.responses import RedirectResponse

from src.providers import Stub
from src.providers.keycloak import KeycloakClient

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
