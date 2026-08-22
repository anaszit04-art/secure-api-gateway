from __future__ import annotations

import json
import logging

from datetime import (
    datetime,
    timezone,
)
from typing import Final


REQUEST_LOGGER_NAME: Final[str] = (
    "gateway.request"
)


STRUCTURED_FIELDS: Final[
    tuple[str, ...]
] = (
    "event",
    "request_id",
    "method",
    "route",
    "status_code",
    "duration_ms",
)


class JsonLogFormatter(
    logging.Formatter
):
    """
    Serialize Gateway operational events as JSON.

    Only explicitly approved structured fields are
    emitted. Arbitrary LogRecord attributes are not
    copied into the output.
    """

    def format(
        self,
        record: logging.LogRecord,
    ) -> str:
        payload: dict[str, object] = {
            "timestamp": (
                datetime.now(
                    timezone.utc
                )
                .isoformat(
                    timespec="milliseconds"
                )
                .replace(
                    "+00:00",
                    "Z",
                )
            ),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        for field_name in STRUCTURED_FIELDS:
            value = getattr(
                record,
                field_name,
                None,
            )

            if value is not None:
                payload[field_name] = value

        return json.dumps(
            payload,
            separators=(",", ":"),
            ensure_ascii=False,
        )


def get_request_logger() -> logging.Logger:
    """
    Return the dedicated structured request logger.

    The logger owns one JSON StreamHandler and does
    not propagate records to the root logger, avoiding
    duplicate operational events under Uvicorn.
    """

    logger = logging.getLogger(
        REQUEST_LOGGER_NAME
    )

    handler_exists = any(
        getattr(
            handler,
            "_gateway_json_handler",
            False,
        )
        for handler in logger.handlers
    )

    if not handler_exists:
        handler = logging.StreamHandler()

        handler.setFormatter(
            JsonLogFormatter()
        )

        setattr(
            handler,
            "_gateway_json_handler",
            True,
        )

        logger.addHandler(
            handler
        )

    logger.setLevel(
        logging.INFO
    )

    logger.propagate = False

    return logger
