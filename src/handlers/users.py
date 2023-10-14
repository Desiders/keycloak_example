import logging
from typing import Annotated

from fastapi import APIRouter, Depends, status
from fastapi.responses import ORJSONResponse
from fastapi.security import OAuth2AuthorizationCodeBearer

from src.adapters.keycloak import KeycloakClient, OIDCUser
from src.providers import Stub

logger = logging.getLogger(__name__)

user_router = APIRouter(
    prefix="/users",
    tags=["users"],
)


@user_router.get(
    "/",
    responses={
        status.HTTP_200_OK: {"model": OIDCUser},
        status.HTTP_307_TEMPORARY_REDIRECT: {"description": "Redirect to login URL"},
    },
    response_class=ORJSONResponse,
    description="Get logged user info or redirect to login URL",
)
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
):
    logger.info("Getting user", extra={"access_token": access_token})

    user = await keycloak.get_user_by_token(access_token)

    logger.debug("Got user", extra={"user": user})

    return user
