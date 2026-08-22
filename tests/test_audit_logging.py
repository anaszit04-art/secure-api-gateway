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
