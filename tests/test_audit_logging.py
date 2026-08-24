import json
import logging

from uuid import uuid4

from gateway.app.audit.logging import (
    AuditJsonFormatter,
    security_audit_event_to_log_fields,
)
from gateway.app.audit.models import (
    AuditEventType,
    AuditOutcome,
    create_security_audit_event,
)


def test_audit_log_fields_are_explicitly_bounded() -> None:
    event = create_security_audit_event(
        event_type=(
            AuditEventType.ROLE_ASSIGNED
        ),
        outcome=AuditOutcome.SUCCESS,
        request_id=uuid4(),
        actor_user_id=uuid4(),
        target_user_id=uuid4(),
        role_name="operator",
        status_code=200,
    )

    fields = (
        security_audit_event_to_log_fields(
            event
        )
    )

    assert fields["event_type"] == (
        "role_assigned"
    )

    assert fields["outcome"] == (
        "success"
    )

    assert fields["role_name"] == (
        "operator"
    )

    assert "password" not in fields
    assert "authorization" not in fields
    assert "token" not in fields
    assert "request_body" not in fields
    assert "query_string" not in fields


def test_audit_json_formatter_ignores_arbitrary_sensitive_fields() -> None:
    record = logging.LogRecord(
        name="gateway.audit",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="login_failed",
        args=(),
        exc_info=None,
    )

    record.event_type = (
        "login_failed"
    )
    record.outcome = "failure"
    record.request_id = str(
        uuid4()
    )
    record.status_code = 401

    record.password = (
        "super-secret-password"
    )
    record.authorization = (
        "Bearer super-secret-token"
    )

    rendered = (
        AuditJsonFormatter()
        .format(
            record
        )
    )

    payload = json.loads(
        rendered
    )

    assert payload["logger"] == (
        "gateway.audit"
    )

    assert payload["event_type"] == (
        "login_failed"
    )

    assert payload["status_code"] == 401

    assert "password" not in payload
    assert "authorization" not in payload

    assert (
        "super-secret-password"
        not in rendered
    )

    assert (
        "super-secret-token"
        not in rendered
    )


def test_audit_persistence_warning_uses_bounded_fields() -> None:
    from gateway.app.audit.logging import (
        emit_audit_persistence_failure,
        get_audit_persistence_logger,
    )

    event = create_security_audit_event(
        event_type=(
            AuditEventType.ROLE_ASSIGNED
        ),
        outcome=AuditOutcome.SUCCESS,
        request_id=uuid4(),
        actor_user_id=uuid4(),
        target_user_id=uuid4(),
        role_name="operator",
        status_code=200,
    )

    captured = []

    class CaptureHandler(
        logging.Handler
    ):
        def emit(
            self,
            record: logging.LogRecord,
        ) -> None:
            captured.append(
                json.loads(
                    AuditJsonFormatter()
                    .format(
                        record
                    )
                )
            )

    logger = (
        get_audit_persistence_logger()
    )

    original_handlers = list(
        logger.handlers
    )

    logger.handlers.clear()

    logger.addHandler(
        CaptureHandler()
    )

    try:
        emit_audit_persistence_failure(
            event
        )

    finally:
        logger.handlers.clear()

        for handler in original_handlers:
            logger.addHandler(
                handler
            )

    assert len(captured) == 1

    payload = captured[0]

    assert payload["level"] == (
        "WARNING"
    )

    assert payload["logger"] == (
        "gateway.audit.persistence"
    )

    assert payload["message"] == (
        "audit_persistence_unavailable"
    )

    assert payload["event_type"] == (
        "role_assigned"
    )

    assert payload["outcome"] == (
        "unavailable"
    )

    assert payload["reason_code"] == (
        "audit_persistence_unavailable"
    )

    rendered = json.dumps(
        payload
    )

    assert "password" not in rendered
    assert "Authorization" not in rendered
    assert "Bearer " not in rendered
