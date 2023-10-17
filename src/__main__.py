import asyncio
import logging

import uvicorn
from fastapi import FastAPI
from fastapi.responses import ORJSONResponse
from jose import JWTError

from .config import API as APIConfig
from .config import Keycloak as KeycloakConfig
from .config import configure_logging, load_config_from_env
from .handlers import auth_router, jwt_exception_handler, tokens_router, user_router
from .providers import setup_providers

logger = logging.getLogger(__name__)


def init_api(
    keycloak_config: KeycloakConfig,
    debug: bool = __debug__,
) -> FastAPI:
    logger.info("Initializing API")

    app = FastAPI(
        debug=debug,
        title="Keycloak FastAPI Example",
        description="Example of using Keycloak with FastAPI",
        version="0.1.0",
        default_response_class=ORJSONResponse,
    )

    setup_providers(app, keycloak_config)

    app.include_router(auth_router)
    app.include_router(tokens_router)
    app.include_router(user_router)

    app.add_exception_handler(JWTError, jwt_exception_handler)

    return app


async def run_api(app: FastAPI, api_config: APIConfig) -> None:
    uvicorn_config = uvicorn.Config(
        app,
        host=api_config.host,
        port=api_config.port,
        log_level=logging.DEBUG,
    )

    server = uvicorn.Server(uvicorn_config)

    logger.info("Running API")

    await server.serve()


async def main() -> None:
    config = load_config_from_env()
    configure_logging(config.logging)

    logger.info("Starting application", extra={"config": config})

    app = init_api(config.keycloak, config.api.debug)
    await run_api(app, config.api)


if __name__ == "__main__":
    asyncio.run(main())
