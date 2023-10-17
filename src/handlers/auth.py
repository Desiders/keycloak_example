import logging
from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, HTTPException, Query, Response, status
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
    status_code=status.HTTP_307_TEMPORARY_REDIRECT,
    description="Redirect to authorization URL",
)
async def authorize(
    response: Response,
    keycloak: Annotated[KeycloakClient, Depends(Stub(KeycloakClient))],
    scope: str = Query(
        default="openid profile email",
        description="Space-separated list of scopes. ",
    ),
    state: str
    | None = Query(
        default=None,
        description="Opaque value used to maintain state between the request and the callback",
    ),
    state_cookie_max_age: int = Query(
        default=300,
        description="Maximum age of the state cookie in seconds",
    ),
    nonce: str
    | None = Query(
        default=None,
        description="String value used to associate a Client session with an ID Token, and to mitigate replay attacks",
    ),
) -> RedirectResponse:
    authorization_url = await keycloak.get_authorization_url(scope, state, nonce)

    response = RedirectResponse(authorization_url)

    if state is not None:
        logger.debug(
            "Setting state in user's cookie",
            extra={"state": state, "state_cookie_max_age": state_cookie_max_age},
        )

        response.set_cookie("state", state, max_age=state_cookie_max_age)

    logger.debug(
        "Redirecting to authorization URL",
        extra={"authorization_url": authorization_url, "scope": scope},
    )

    return response


@auth_router.get(
    "/callback",
    responses={
        status.HTTP_200_OK: {
            "model": KeycloakTokens,
        },
        status.HTTP_401_UNAUTHORIZED: {
            "description": "User's cookie state does not match state parameter from callback",
        },
    },
    status_code=status.HTTP_200_OK,
)
async def get_tokens(
    session_state: str,
    code: str,
    keycloak: Annotated[KeycloakClient, Depends(Stub(KeycloakClient))],
    state: str
    | None = Query(
        default=None,
        description="Opaque value used to maintain state between the request and the callback",
    ),
    state_cookie: str
    | None = Cookie(
        default=None,
        alias="state",
        description="Opaque value from cookie used to compare with state parameter and mitigate CSRF attacks",
    ),
) -> ORJSONResponse:
    logger.debug(
        "Got callback",
        extra={
            "session_state": session_state,
            "code": code,
            "state": state,
            "state_cookie": state_cookie,
        },
    )

    if state is not None and state != state_cookie:
        logger.error(
            "State cookie is empty or does not match state parameter",
            extra={
                "state": state,
                "state_cookie": state_cookie,
            },
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="State cookie does not match state parameter",
        )

    keycloak_tokens = await keycloak.exchange_authorization_code(session_state, code)

    logger.debug("Got tokens", extra={"keycloak_tokens": keycloak_tokens})

    response = ORJSONResponse(keycloak_tokens)

    if state is not None:
        logger.debug("Deleting state cookie", extra={"state": state})

        response.delete_cookie("state")

    return response
