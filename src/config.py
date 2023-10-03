import logging
import os
from dataclasses import dataclass
from pathlib import Path

import orjson
import structlog


@dataclass
class API:
    host: str = "127.0.0.1"
    port: int = 5000
    debug: bool = __debug__


@dataclass
class Keycloak:
    host: str = "localhost"
    port: int = 8080


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
    raw_path: str = os.environ.get("LOGGING_PATH")

    return Config(
        api=API(
            host=os.environ.get("API_HOST", "127.0.0.1"),
            port=int(os.environ.get("API_PORT", 5000)),
        ),
        keycloak=Keycloak(
            host=os.environ.get("KEYCLOAK_HOST", "localhost"),
            port=int(os.environ.get("KEYCLOAK_PORT", 8080)),
        ),
        logging=Logging(
            render_json_logs=bool(os.environ.get(
                "LOGGING_RENDER_JSON_LOGS", False)),
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
    logging_processors = (
        structlog.stdlib.ProcessorFormatter.remove_processors_meta,
    )

    if logging_config.render_json_logs:
        logging_console_processors = (
            *logging_processors,
            structlog.processors.JSONRenderer(orjson.dumps, colors=True),
        )
        logging_file_processors = (
            *logging_processors,
            structlog.processors.JSONRenderer(orjson.dumps, colors=False),
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

        logging_path = logging_path / "logs.log" if logging_path.is_dir() else logging_path

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
