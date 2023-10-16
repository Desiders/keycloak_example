import logging

from fastapi import HTTPException, Request
from fastapi.responses import RedirectResponse

logger = logging.getLogger(__name__)


async def unauthorized_handler(_request: Request, exc: HTTPException):
    logger.debug(
        "Unauthorized exception. Redirecting to authorization URL",
        extra={"exc": exc, "authorization_url": "/auth"},
    )

    return RedirectResponse("/auth")
