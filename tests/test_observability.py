import json
import logging

from gateway.app.observability.logging import (
    JsonLogFormatter,
)


def test_json_formatter_emits_bounded_structured_fields() -> None:
    record = logging.LogRecord(
        name="gateway.request",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="request_completed",
        args=(),
        exc_info=None,
    )

    record.event = "request_completed"
    record.request_id = (
        "123e4567-e89b-42d3-a456-426614174000"
    )
    record.method = "GET"
    record.route = "/health"
    record.status_code = 200
    record.duration_ms = 1.25

    # These attributes simulate sensitive or arbitrary
    # data attached accidentally to a LogRecord.
    record.authorization = (
        "Bearer secret-token"
    )
    record.password = (
        "secret-password"
    )
    record.database_url = (
        "postgresql://user:secret@example/db"
    )

    rendered = JsonLogFormatter().format(
        record
    )

    payload = json.loads(
        rendered
    )

    assert payload["level"] == "INFO"
    assert payload["logger"] == (
        "gateway.request"
    )
    assert payload["event"] == (
        "request_completed"
    )
    assert payload["method"] == "GET"
    assert payload["route"] == "/health"
    assert payload["status_code"] == 200
    assert payload["duration_ms"] == 1.25

    assert "timestamp" in payload

    assert "authorization" not in payload
    assert "password" not in payload
    assert "database_url" not in payload

    assert "secret-token" not in rendered
    assert "secret-password" not in rendered
