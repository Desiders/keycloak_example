import logging

from fastapi import HTTPException, Request
from fastapi.responses import RedirectResponse

logger = logging.getLogger(__name__)

AUTH_LOGIN_URL = "/auth/login"


async def unauthorized_handler(request: Request, exc: HTTPException):
    logger.debug(
        "Unauthorized exception. Redirecting to login URL",
        extra={"exc": exc, "login_url": AUTH_LOGIN_URL},
    )

    return RedirectResponse(AUTH_LOGIN_URL)
