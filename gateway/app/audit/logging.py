from __future__ import annotations

import json
import logging

from typing import Final

from gateway.app.audit.models import (
    SecurityAuditEvent,
)


AUDIT_LOGGER_NAME: Final[str] = (
    "gateway.audit"
)


AUDIT_LOG_FIELDS: Final[
    tuple[str, ...]
] = (
    "event_id",
    "occurred_at",
    "event_type",
    "outcome",
    "request_id",
    "actor_user_id",
    "target_user_id",
    "permission_code",
    "role_name",
    "service_name",
    "method",
    "status_code",
    "reason_code",
)


class AuditJsonFormatter(
    logging.Formatter
):
    """
    Serialize only explicitly approved audit fields.

    Arbitrary LogRecord attributes are intentionally
    ignored to prevent accidental secret disclosure.
    """

    def format(
        self,
        record: logging.LogRecord,
    ) -> str:
        payload: dict[str, object] = {
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        for field_name in AUDIT_LOG_FIELDS:
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


def security_audit_event_to_log_fields(
    event: SecurityAuditEvent,
) -> dict[str, object]:
    """
    Convert an audit event to an explicitly bounded
    logging payload.
    """

    fields: dict[str, object] = {
        "event_id": str(
            event.event_id
        ),
        "occurred_at": (
            event.occurred_at
            .isoformat(
                timespec="milliseconds"
            )
            .replace(
                "+00:00",
                "Z",
            )
        ),
        "event_type": (
            event.event_type.value
        ),
        "outcome": (
            event.outcome.value
        ),
        "request_id": str(
            event.request_id
        ),
    }

    optional_values: dict[
        str,
        object | None,
    ] = {
        "actor_user_id": (
            str(event.actor_user_id)
            if event.actor_user_id
            is not None
            else None
        ),
        "target_user_id": (
            str(event.target_user_id)
            if event.target_user_id
            is not None
            else None
        ),
        "permission_code": (
            event.permission_code
        ),
        "role_name": event.role_name,
        "service_name": (
            event.service_name
        ),
        "method": event.method,
        "status_code": (
            event.status_code
        ),
        "reason_code": (
            event.reason_code
        ),
    }

    fields.update(
        {
            key: value
            for key, value
            in optional_values.items()
            if value is not None
        }
    )

    return fields


def get_audit_logger() -> logging.Logger:
    """
    Return the dedicated security-audit logger.
    """

    logger = logging.getLogger(
        AUDIT_LOGGER_NAME
    )

    handler_exists = any(
        getattr(
            handler,
            "_gateway_audit_handler",
            False,
        )
        for handler in logger.handlers
    )

    if not handler_exists:
        handler = logging.StreamHandler()

        handler.setFormatter(
            AuditJsonFormatter()
        )

        setattr(
            handler,
            "_gateway_audit_handler",
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


def emit_security_audit_event(
    event: SecurityAuditEvent,
) -> None:
    """
    Emit one security event to the dedicated audit
    logger.

    Persistent storage will be introduced separately
    in the next Phase 6 step.
    """

    logger = get_audit_logger()

    logger.info(
        event.event_type.value,
        extra=(
            security_audit_event_to_log_fields(
                event
            )
        ),
    )
