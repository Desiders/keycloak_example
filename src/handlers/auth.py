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
    "/",
    response_class=RedirectResponse,
    status_code=status.HTTP_307_TEMPORARY_REDIRECT,
    description="Redirect to authorization URL",
)
async def login(
    keycloak: Annotated[KeycloakClient, Depends(Stub(KeycloakClient))],
) -> str:
    authorization_url = await keycloak.get_authorization_url()

    logger.debug(
        "Redirecting to authorization URL",
        extra={"authorization_url": authorization_url},
    )

    return authorization_url


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
