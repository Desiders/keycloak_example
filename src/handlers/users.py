import logging
from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.security import OAuth2AuthorizationCodeBearer

from src.providers import Stub
from src.providers.keycloak.client import KeycloakClient, OIDCUser

logger = logging.getLogger(__name__)

user_router = APIRouter(
    prefix="/users",
    tags=["users"],
)


@user_router.get("/", response_model=OIDCUser)
async def get_user(
    keycloak: Annotated[KeycloakClient, Depends(Stub(KeycloakClient))],
    access_token: Annotated[
        str,
        Depends(
            OAuth2AuthorizationCodeBearer(
                authorizationUrl="/auth/login",
                tokenUrl="/auth/token",
            )
        ),
    ],
) -> OIDCUser:
    logger.info("Getting user", extra={"access_token": access_token})

    user = await keycloak.get_user_by_token(access_token)

    logger.debug("Got user", extra={"user": user})

    return user
