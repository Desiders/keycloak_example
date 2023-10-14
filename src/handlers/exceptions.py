import logging

from fastapi import HTTPException, Request
from fastapi.responses import RedirectResponse

logger = logging.getLogger(__name__)


async def unauthorized_handler(request: Request, exc: HTTPException):
    logger.debug(
        "Unauthorized exception. Redirecting to login URL",
        extra={"exc": exc, "login_url": "/auth/login"},
    )

    return RedirectResponse("/auth/login")
