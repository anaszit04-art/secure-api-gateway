from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
from prometheus_client import (
    generate_latest,
)

from gateway.app.observability.metrics import (
    GatewayMetrics,
    MetricsSettings,
    parse_boolean_environment,
    status_class,
)
from gateway.app.observability.middleware import (
    RequestContextMiddleware,
)


def render(
    metrics: GatewayMetrics,
) -> str:
    return generate_latest(
        metrics.registry
    ).decode(
        "utf-8"
    )


def test_status_class_is_bounded() -> None:
    assert status_class(200) == "2xx"
    assert status_class(401) == "4xx"
    assert status_class(503) == "5xx"
    assert status_class(999) == "unknown"


def test_metrics_settings_are_disabled_by_default(
    monkeypatch,
) -> None:
    monkeypatch.delenv(
        "METRICS_ENABLED",
        raising=False,
    )

    monkeypatch.delenv(
        "METRICS_HOST",
        raising=False,
    )

    monkeypatch.delenv(
        "METRICS_PORT",
        raising=False,
    )

    settings = (
        MetricsSettings.from_environment()
    )

    assert settings.enabled is False
    assert settings.host == "0.0.0.0"
    assert settings.port == 9100


def test_metrics_settings_load_environment(
    monkeypatch,
) -> None:
    monkeypatch.setenv(
        "METRICS_ENABLED",
        "true",
    )

    monkeypatch.setenv(
        "METRICS_HOST",
        "127.0.0.1",
    )

    monkeypatch.setenv(
        "METRICS_PORT",
        "9200",
    )

    settings = (
        MetricsSettings.from_environment()
    )

    assert settings.enabled is True
    assert settings.host == "127.0.0.1"
    assert settings.port == 9200


def test_invalid_boolean_is_rejected(
    monkeypatch,
) -> None:
    monkeypatch.setenv(
        "TEST_BOOLEAN",
        "maybe",
    )

    try:
        parse_boolean_environment(
            "TEST_BOOLEAN",
            default=False,
        )
    except ValueError:
        pass
    else:
        raise AssertionError(
            "Invalid boolean was accepted."
        )


def test_http_metrics_use_bounded_labels() -> None:
    metrics = GatewayMetrics()

    metrics.record_http_request(
        method="get",
        route=(
            "/authorization/users/"
            "{username}/roles"
        ),
        status_code=403,
        duration_seconds=0.025,
    )

    rendered = render(
        metrics
    )

    assert (
        'method="GET"'
        in rendered
    )

    assert (
        'route="/authorization/users/'
        '{username}/roles"'
        in rendered
    )

    assert (
        'status_class="4xx"'
        in rendered
    )

    assert "username=" not in rendered
    assert "request_id=" not in rendered
    assert "user_id=" not in rendered


def test_security_metric_has_only_event_and_outcome() -> None:
    metrics = GatewayMetrics()

    metrics.record_security_event(
        event_type="login_failed",
        outcome="failure",
    )

    rendered = render(
        metrics
    )

    assert (
        'event_type="login_failed"'
        in rendered
    )

    assert (
        'outcome="failure"'
        in rendered
    )

    assert "username=" not in rendered
    assert "actor_user_id=" not in rendered


def test_rate_limit_metric_is_bounded() -> None:
    metrics = GatewayMetrics()

    metrics.record_rate_limit_decision(
        scope="login",
        decision="rejected",
    )

    rendered = render(
        metrics
    )

    assert 'scope="login"' in rendered

    assert (
        'decision="rejected"'
        in rendered
    )

    assert "ip=" not in rendered
    assert "request_id=" not in rendered


def test_upstream_metric_has_no_raw_path() -> None:
    metrics = GatewayMetrics()

    metrics.record_upstream_request(
        service="service-a",
        outcome="2xx",
        duration_seconds=0.1,
    )

    rendered = render(
        metrics
    )

    assert (
        'service="service-a"'
        in rendered
    )

    assert 'outcome="2xx"' in rendered

    assert "path=" not in rendered
    assert "query=" not in rendered


def test_middleware_uses_route_template_not_path_value() -> None:
    test_app = FastAPI()

    metrics = GatewayMetrics()

    test_app.state.metrics = metrics

    test_app.add_middleware(
        RequestContextMiddleware
    )

    @test_app.get(
        "/users/{username}"
    )
    async def read_user(
        username: str,
    ) -> dict[str, str]:
        return {
            "username": username,
        }

    with TestClient(
        test_app
    ) as client:
        response = client.get(
            "/users/private-user-name"
        )

    assert response.status_code == 200

    rendered = render(
        metrics
    )

    assert (
        'route="/users/{username}"'
        in rendered
    )

    assert (
        "private-user-name"
        not in rendered
    )


def test_security_metric_best_effort_records_event() -> None:
    from types import SimpleNamespace

    from gateway.app.observability.metrics import (
        record_security_metric_best_effort,
    )

    metrics = GatewayMetrics()

    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                metrics=metrics,
            )
        )
    )

    record_security_metric_best_effort(
        request=request,
        event_type="authorization_denied",
        outcome="denied",
    )

    rendered = render(
        metrics
    )

    assert (
        'gateway_security_events_total'
        '{event_type="authorization_denied",'
        'outcome="denied"} 1.0'
        in rendered
    )


def test_rate_limit_metric_best_effort_records_decision() -> None:
    from types import SimpleNamespace

    from gateway.app.observability.metrics import (
        record_rate_limit_metric_best_effort,
    )

    metrics = GatewayMetrics()

    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                metrics=metrics,
            )
        )
    )

    record_rate_limit_metric_best_effort(
        request=request,
        scope="proxy",
        decision="rejected",
    )

    rendered = render(
        metrics
    )

    assert (
        'gateway_rate_limit_decisions_total'
        '{decision="rejected",scope="proxy"} '
        '1.0'
        in rendered
    )


def test_upstream_metric_best_effort_records_bounded_outcome() -> None:
    from types import SimpleNamespace

    from gateway.app.observability.metrics import (
        record_upstream_metric_best_effort,
    )

    metrics = GatewayMetrics()

    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                metrics=metrics,
            )
        )
    )

    record_upstream_metric_best_effort(
        request=request,
        service="service-a",
        outcome="2xx",
        duration_seconds=0.025,
    )

    rendered = render(
        metrics
    )

    assert (
        'gateway_upstream_requests_total'
        '{outcome="2xx",service="service-a"} '
        '1.0'
        in rendered
    )

    assert "path=" not in rendered
    assert "request_id=" not in rendered


def test_metric_helpers_never_change_business_outcome() -> None:
    from types import SimpleNamespace

    from gateway.app.observability.metrics import (
        record_rate_limit_metric_best_effort,
        record_security_metric_best_effort,
        record_upstream_metric_best_effort,
    )

    class FailingGatewayMetrics(
        GatewayMetrics
    ):
        def record_security_event(
            self,
            *,
            event_type: str,
            outcome: str,
        ) -> None:
            del event_type, outcome

            raise RuntimeError(
                "metrics backend failure"
            )

        def record_rate_limit_decision(
            self,
            *,
            scope: str,
            decision: str,
        ) -> None:
            del scope, decision

            raise RuntimeError(
                "metrics backend failure"
            )

        def record_upstream_request(
            self,
            *,
            service: str,
            outcome: str,
            duration_seconds: float,
        ) -> None:
            del (
                service,
                outcome,
                duration_seconds,
            )

            raise RuntimeError(
                "metrics backend failure"
            )

    metrics = FailingGatewayMetrics()

    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                metrics=metrics,
            )
        )
    )

    # None of these calls may propagate the metrics
    # failure into application/security processing.
    record_security_metric_best_effort(
        request=request,
        event_type="login_failed",
        outcome="failure",
    )

    record_rate_limit_metric_best_effort(
        request=request,
        scope="login",
        decision="rejected",
    )

    record_upstream_metric_best_effort(
        request=request,
        service="service-a",
        outcome="2xx",
        duration_seconds=0.1,
    )


def test_upstream_resilience_metric_is_bounded() -> None:
    from types import SimpleNamespace

    from gateway.app.observability.metrics import (
        record_upstream_resilience_metric_best_effort,
    )

    metrics = GatewayMetrics()

    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                metrics=metrics,
            )
        )
    )

    record_upstream_resilience_metric_best_effort(
        request=request,
        service="service-a",
        event="retry",
    )

    rendered = render(
        metrics
    )

    assert (
        'gateway_upstream_resilience_events_total'
        '{event="retry",service="service-a"} '
        '1.0'
        in rendered
    )

    assert "path=" not in rendered
    assert "request_id=" not in rendered
    assert "user_id=" not in rendered


def test_arbitrary_http_method_is_normalized_to_other() -> None:
    metrics = GatewayMetrics()

    attacker_method = (
        "X-CUSTOM-ATTACK-"
        "7f8d5b4c"
    )

    metrics.record_http_request(
        method=attacker_method,
        route="<unmatched>",
        status_code=405,
        duration_seconds=0.001,
    )

    rendered = render(
        metrics
    )

    assert (
        'method="OTHER"'
        in rendered
    )

    assert (
        attacker_method
        not in rendered
    )
