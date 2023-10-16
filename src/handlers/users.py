import logging
from typing import Annotated

from fastapi import APIRouter, Depends, status
from fastapi.responses import ORJSONResponse
from fastapi.security import OAuth2PasswordBearer

from src.adapters.keycloak import KeycloakClient, OIDCUser
from src.providers import Stub

logger = logging.getLogger(__name__)

user_router = APIRouter(
    prefix="/users",
    tags=["users"],
)


@user_router.get(
    "/",
    response_model=OIDCUser,
    response_class=ORJSONResponse,
    status_code=status.HTTP_200_OK,
    description="Get user by access token",
)
async def get_user(
    keycloak: Annotated[KeycloakClient, Depends(Stub(KeycloakClient))],
    token: Annotated[str, Depends(OAuth2PasswordBearer(tokenUrl="/tokens"))],
) -> OIDCUser:
    logger.info("Getting user", extra={"access_token": token})

    user = await keycloak.get_user_by_access_token(token)

    logger.debug("Got user", extra={"user": user})

    return user
