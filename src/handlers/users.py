import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.security import OAuth2PasswordBearer

from src.providers import Stub
from src.providers.keycloak.client import KeycloakClient, OIDCUser

logger = logging.getLogger(__name__)

user_router = APIRouter(
    prefix="/users",
    tags=["users"],
)


@user_router.get("/")
async def get_user(
    request: Request,
    keycloak: Annotated[KeycloakClient, Depends(Stub(KeycloakClient))],
) -> OIDCUser:
    logger.info("Getting user")

    openid_configuration = await keycloak.get_openid_configuration()

    token_endpoint = openid_configuration.token_endpoint

    user_access_token = await OAuth2PasswordBearer(tokenUrl=token_endpoint)(request)

    if user_access_token is None:
        logger.debug("No access token provided")

        raise Exception("No access token provided")

    user = await keycloak.get_user_by_token(user_access_token)

    logger.debug(f"User: {user}")

    return user
