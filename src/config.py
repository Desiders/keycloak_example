import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, MutableMapping

import orjson
import structlog


@dataclass
class API:
    host: str = "0.0.0.0"
    port: int = 5000
    debug: bool = __debug__


@dataclass
class Keycloak:
    realm_id: str
    client_id: str
    client_secret: str
    admin_client_secret: str
    host: str = "localhost"
    host_for_api: str = "keycloak-example.keycloak"
    port: int = 8080
    admin_client_id: str = "admin-cli"
    callback_url: str = "http://localhost:5000/auth/callback"


@dataclass
class Logging:
    render_json_logs: bool = False
    path: Path | None = None
    level: str = "DEBUG"


@dataclass
class Config:
    api: API
    keycloak: Keycloak
    logging: Logging


def load_config_from_env() -> Config:
    raw_path = os.environ.get("LOGGING_PATH")

    return Config(
        api=API(
            host=os.environ.get("API_HOST", "0.0.0.0"),
            port=int(os.environ.get("API_PORT", 5000)),
        ),
        keycloak=Keycloak(
            host=os.environ.get("KEYCLOAK_HOST", "localhost"),
            host_for_api=os.environ.get(
                "KEYCLOAK_HOSTNAME_FOR_API", "keycloak-example.keycloak"
            ),
            port=int(os.environ.get("KEYCLOAK_PORT", 8080)),
            realm_id=os.environ["KEYCLOAK_REALM_ID"],
            client_id=os.environ["KEYCLOAK_CLIENT_ID"],
            client_secret=os.environ["KEYCLOAK_CLIENT_SECRET"],
            admin_client_id=os.environ.get("KEYCLOAK_ADMIN_CLIENT_ID", "admin-cli"),
            admin_client_secret=os.environ["KEYCLOAK_ADMIN_CLIENT_SECRET"],
            callback_url=os.environ.get(
                "KEYCLOAK_CALLBACK_URL", "http://localhost:5000/auth/callback"
            ),
        ),
        logging=Logging(
            render_json_logs=bool(
                os.environ.get("LOGGING_RENDER_JSON_LOGS", "false").lower() == "true"
            ),
            path=Path(raw_path) if raw_path else None,
            level=os.environ.get("LOGGING_LEVEL", "DEBUG"),
        ),
    )


def configure_logging(logging_config: Logging) -> None:
    common_processors = (
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.ExtraAdder(),
        structlog.dev.set_exc_info,
        structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S.%f", utc=True),
        structlog.contextvars.merge_contextvars,
        structlog.processors.dict_tracebacks,
        structlog.processors.CallsiteParameterAdder(
            (
                structlog.processors.CallsiteParameter.FUNC_NAME,
                structlog.processors.CallsiteParameter.LINENO,
            )
        ),
    )
    structlog_processors = (
        structlog.processors.StackInfoRenderer(),
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.UnicodeDecoder(),
        structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
    )
    logging_processors = (structlog.stdlib.ProcessorFormatter.remove_processors_meta,)

    logging_console_processors: tuple[
        Callable[[Any, str, MutableMapping[str, Any]], MutableMapping[str, Any]],
        structlog.dev.ConsoleRenderer,
    ] | tuple[
        Callable[[Any, str, MutableMapping[str, Any]], MutableMapping[str, Any]],
        structlog.processors.JSONRenderer,
    ]
    logging_file_processors: tuple[
        Callable[[Any, str, MutableMapping[str, Any]], MutableMapping[str, Any]],
        structlog.dev.ConsoleRenderer,
    ] | tuple[
        Callable[[Any, str, MutableMapping[str, Any]], MutableMapping[str, Any]],
        structlog.processors.JSONRenderer,
    ]
    if logging_config.render_json_logs:
        logging_console_processors = (
            *logging_processors,
            structlog.processors.JSONRenderer(orjson.dumps),
        )
        logging_file_processors = (
            *logging_processors,
            structlog.processors.JSONRenderer(orjson.dumps),
        )
    else:
        logging_console_processors = (
            *logging_processors,
            structlog.dev.ConsoleRenderer(colors=True),
        )
        logging_file_processors = (
            *logging_processors,
            structlog.dev.ConsoleRenderer(colors=False),
        )

    handler = logging.StreamHandler()
    handler.set_name("default")
    handler.setLevel(logging_config.level)

    console_formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=common_processors,  # type: ignore
        processors=logging_console_processors,
    )
    handler.setFormatter(console_formatter)

    handlers: list[logging.Handler] = [handler]
    logging_path = logging_config.path
    if logging_path:
        logging_path.parent.mkdir(parents=True, exist_ok=True)

        logging_path = (
            logging_path / "logs.log" if logging_path.is_dir() else logging_path
        )

        file_handler = logging.FileHandler(logging_path)
        file_handler.set_name("file")
        file_handler.setLevel(logging_config.level)
        file_formatter = structlog.stdlib.ProcessorFormatter(
            foreign_pre_chain=common_processors,  # type: ignore
            processors=logging_file_processors,
        )
        file_handler.setFormatter(file_formatter)
        handlers.append(file_handler)

    logging.basicConfig(handlers=handlers, level=logging_config.level)

    structlog.configure(
        processors=common_processors + structlog_processors,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,  # type: ignore  # noqa
        cache_logger_on_first_use=True,
    )
