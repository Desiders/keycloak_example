import logging
from typing import Annotated

from fastapi import APIRouter, Depends, status
from fastapi.responses import ORJSONResponse
from fastapi.security import OAuth2PasswordRequestForm

from src.adapters.keycloak import KeycloakClient, KeycloakTokens
from src.providers import Stub

logger = logging.getLogger(__name__)

tokens_router = APIRouter(
    prefix="/tokens",
    tags=["tokens"],
)


@tokens_router.post(
    "/",
    responses={
        status.HTTP_200_OK: {"model": KeycloakTokens},
        status.HTTP_400_BAD_REQUEST: {"description": "Invalid username or password"},
    },
    response_class=ORJSONResponse,
    description="Get tokens by username and password",
)
async def get_tokens_by_username_and_password(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    keycloak: Annotated[KeycloakClient, Depends(Stub(KeycloakClient))],
) -> KeycloakTokens:
    logger.debug(
        "Getting tokens by username and password",
        extra={"form_data": form_data},
    )

    keycloak_tokens = await keycloak.get_tokens_by_username_and_password(
        form_data.username, form_data.password
    )

    logger.debug("Got tokens", extra={"keycloak_tokens": keycloak_tokens})

    return keycloak_tokens
