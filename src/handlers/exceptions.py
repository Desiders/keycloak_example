import logging

from fastapi import Request, status
from fastapi.responses import ORJSONResponse
from jose import JWTError

logger = logging.getLogger(__name__)


async def jwt_exception_handler(_request: Request, exc: JWTError):
    logger.debug(
        "JWT exception",
        extra={"exc": exc},
    )

    return ORJSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"detail": str(exc)},
    )
