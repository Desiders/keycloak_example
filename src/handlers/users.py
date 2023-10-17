import logging
from typing import Annotated

from fastapi import APIRouter, Depends, status
from fastapi.responses import ORJSONResponse
from fastapi.security import OAuth2PasswordBearer

from src.adapters.keycloak import IDToken, KeycloakClient
from src.providers import Stub

logger = logging.getLogger(__name__)

user_router = APIRouter(
    prefix="/users",
    tags=["users"],
)


@user_router.get(
    "/id-token",
    responses={
        status.HTTP_200_OK: {
            "model": IDToken,
        },
        status.HTTP_401_UNAUTHORIZED: {
            "description": "Invalid access token",
        },
    },
    response_class=ORJSONResponse,
    status_code=status.HTTP_200_OK,
    description="Get id token by access token",
)
async def get_id_token(
    keycloak: Annotated[KeycloakClient, Depends(Stub(KeycloakClient))],
    token: Annotated[str, Depends(OAuth2PasswordBearer(tokenUrl="/tokens"))],
) -> IDToken:
    logger.info("Getting id token", extra={"access_token": token})

    id_token = await keycloak.get_id_token_by_access_token(token)

    logger.debug("Got id token", extra={"id_token": id_token})

    return id_token
