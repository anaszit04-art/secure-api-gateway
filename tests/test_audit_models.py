from datetime import (
    datetime,
)
from uuid import (
    UUID,
    uuid4,
)

import pytest

from gateway.app.audit.models import (
    AuditEventType,
    AuditOutcome,
    SecurityAuditEvent,
    create_security_audit_event,
)


def test_create_security_audit_event_uses_trusted_ids() -> None:
    request_id = uuid4()
    actor_user_id = uuid4()
    target_user_id = uuid4()

    event = create_security_audit_event(
        event_type=(
            AuditEventType.ROLE_ASSIGNED
        ),
        outcome=AuditOutcome.SUCCESS,
        request_id=request_id,
        actor_user_id=actor_user_id,
        target_user_id=target_user_id,
        role_name="operator",
        status_code=200,
    )

    assert isinstance(
        event.event_id,
        UUID,
    )

    assert event.request_id == request_id
    assert (
        event.actor_user_id
        == actor_user_id
    )
    assert (
        event.target_user_id
        == target_user_id
    )

    assert event.role_name == "operator"
    assert event.status_code == 200

    assert (
        event.occurred_at.tzinfo
        is not None
    )


def test_create_security_audit_event_normalizes_method() -> None:
    event = create_security_audit_event(
        event_type=(
            AuditEventType
            .AUTHORIZATION_DENIED
        ),
        outcome=AuditOutcome.DENIED,
        request_id=uuid4(),
        permission_code=(
            "proxy:service-a:write"
        ),
        service_name="service-a",
        method="post",
        status_code=403,
    )

    assert event.method == "POST"


def test_invalid_request_id_is_rejected() -> None:
    with pytest.raises(
        ValueError
    ):
        create_security_audit_event(
            event_type=(
                AuditEventType.LOGIN_FAILED
            ),
            outcome=(
                AuditOutcome.FAILURE
            ),
            request_id=(
                "attacker-controlled-id"
            ),
            status_code=401,
        )


def test_invalid_status_code_is_rejected() -> None:
    with pytest.raises(
        ValueError
    ):
        SecurityAuditEvent(
            event_id=uuid4(),
            occurred_at=(
                datetime.now()
                .astimezone()
            ),
            event_type=(
                AuditEventType.LOGIN_FAILED
            ),
            outcome=(
                AuditOutcome.FAILURE
            ),
            request_id=uuid4(),
            status_code=999,
        )


def test_free_form_sensitive_metadata_is_not_part_of_schema() -> None:
    event = create_security_audit_event(
        event_type=(
            AuditEventType.LOGIN_FAILED
        ),
        outcome=AuditOutcome.FAILURE,
        request_id=uuid4(),
        status_code=401,
        reason_code=(
            "invalid_credentials"
        ),
    )

    assert not hasattr(
        event,
        "password"
    )

    assert not hasattr(
        event,
        "authorization"
    )

    assert not hasattr(
        event,
        "request_body"
    )

    assert not hasattr(
        event,
        "metadata"
    )
