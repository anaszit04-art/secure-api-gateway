from __future__ import annotations

import os

from dataclasses import dataclass
from threading import Thread
from typing import Final
from wsgiref.simple_server import WSGIServer

from fastapi import Request
from prometheus_client import (
    CollectorRegistry,
    Counter,
    Histogram,
    start_http_server,
)


DEFAULT_METRICS_HOST: Final[str] = (
    "0.0.0.0"
)

DEFAULT_METRICS_PORT: Final[int] = 9100


HTTP_DURATION_BUCKETS: Final[
    tuple[float, ...]
] = (
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
)


UPSTREAM_DURATION_BUCKETS: Final[
    tuple[float, ...]
] = (
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
)


def parse_boolean_environment(
    name: str,
    *,
    default: bool,
) -> bool:
    """
    Read a strict boolean environment variable.
    """

    raw_value = os.environ.get(
        name
    )

    if raw_value is None:
        return default

    normalized = (
        raw_value.strip().casefold()
    )

    if normalized in {
        "1",
        "true",
        "yes",
        "on",
    }:
        return True

    if normalized in {
        "0",
        "false",
        "no",
        "off",
    }:
        return False

    raise ValueError(
        f"{name} must be a boolean value."
    )


@dataclass(
    frozen=True,
    slots=True,
)
class MetricsSettings:
    """
    Runtime configuration for the internal Prometheus
    exposition server.
    """

    enabled: bool = False
    host: str = DEFAULT_METRICS_HOST
    port: int = DEFAULT_METRICS_PORT

    def __post_init__(self) -> None:
        if not self.host.strip():
            raise ValueError(
                "Metrics host cannot be empty."
            )

        if not 1 <= self.port <= 65535:
            raise ValueError(
                "Metrics port must be between "
                "1 and 65535."
            )

    @classmethod
    def from_environment(
        cls,
    ) -> MetricsSettings:
        enabled = parse_boolean_environment(
            "METRICS_ENABLED",
            default=False,
        )

        host = os.environ.get(
            "METRICS_HOST",
            DEFAULT_METRICS_HOST,
        ).strip()

        raw_port = os.environ.get(
            "METRICS_PORT",
            str(DEFAULT_METRICS_PORT),
        )

        try:
            port = int(
                raw_port
            )
        except ValueError as exc:
            raise ValueError(
                "METRICS_PORT must be an integer."
            ) from exc

        return cls(
            enabled=enabled,
            host=host,
            port=port,
        )


def status_class(
    status_code: int,
) -> str:
    """
    Convert an HTTP status code into a bounded label.

    Examples:
        200 -> 2xx
        404 -> 4xx
        503 -> 5xx
    """

    if 100 <= status_code <= 599:
        return (
            f"{status_code // 100}xx"
        )

    return "unknown"


class GatewayMetrics:
    """
    Own all Gateway Prometheus collectors.

    Every collector uses an isolated registry so tests
    do not leak counters between application instances
    and the exporter exposes only explicitly approved
    metrics.
    """

    def __init__(
        self,
        *,
        registry: (
            CollectorRegistry | None
        ) = None,
    ) -> None:
        self.registry = (
            registry
            if registry is not None
            else CollectorRegistry(
                auto_describe=True
            )
        )

        self.http_requests_total = Counter(
            "gateway_http_requests_total",
            (
                "Total HTTP requests processed "
                "by the Gateway."
            ),
            (
                "method",
                "route",
                "status_class",
            ),
            registry=self.registry,
        )

        self.http_request_duration_seconds = (
            Histogram(
                (
                    "gateway_http_request_"
                    "duration_seconds"
                ),
                (
                    "Gateway HTTP request "
                    "duration in seconds."
                ),
                (
                    "method",
                    "route",
                ),
                buckets=HTTP_DURATION_BUCKETS,
                registry=self.registry,
            )
        )

        self.security_events_total = Counter(
            "gateway_security_events_total",
            (
                "Total security audit events "
                "emitted by the Gateway."
            ),
            (
                "event_type",
                "outcome",
            ),
            registry=self.registry,
        )

        self.rate_limit_decisions_total = (
            Counter(
                (
                    "gateway_rate_limit_"
                    "decisions_total"
                ),
                (
                    "Total rate-limit decisions "
                    "made by the Gateway."
                ),
                (
                    "scope",
                    "decision",
                ),
                registry=self.registry,
            )
        )

        self.upstream_requests_total = Counter(
            "gateway_upstream_requests_total",
            (
                "Total requests issued to "
                "registered upstream services."
            ),
            (
                "service",
                "outcome",
            ),
            registry=self.registry,
        )

        self.upstream_resilience_events_total = (
            Counter(
                (
                    "gateway_upstream_"
                    "resilience_events_total"
                ),
                (
                    "Total bounded upstream "
                    "resilience events."
                ),
                (
                    "service",
                    "event",
                ),
                registry=self.registry,
            )
        )

        self.upstream_request_duration_seconds = (
            Histogram(
                (
                    "gateway_upstream_request_"
                    "duration_seconds"
                ),
                (
                    "Upstream request duration "
                    "in seconds."
                ),
                (
                    "service",
                ),
                buckets=UPSTREAM_DURATION_BUCKETS,
                registry=self.registry,
            )
        )

    def record_http_request(
        self,
        *,
        method: str,
        route: str,
        status_code: int,
        duration_seconds: float,
    ) -> None:
        normalized_method = (
            method.upper()
        )

        self.http_requests_total.labels(
            method=normalized_method,
            route=route,
            status_class=status_class(
                status_code
            ),
        ).inc()

        self.http_request_duration_seconds.labels(
            method=normalized_method,
            route=route,
        ).observe(
            max(
                duration_seconds,
                0.0,
            )
        )

    def record_security_event(
        self,
        *,
        event_type: str,
        outcome: str,
    ) -> None:
        self.security_events_total.labels(
            event_type=event_type,
            outcome=outcome,
        ).inc()

    def record_rate_limit_decision(
        self,
        *,
        scope: str,
        decision: str,
    ) -> None:
        self.rate_limit_decisions_total.labels(
            scope=scope,
            decision=decision,
        ).inc()

    def record_upstream_resilience_event(
        self,
        *,
        service: str,
        event: str,
    ) -> None:
        allowed_events = {
            "retry",
            "circuit_open",
            "circuit_rejected",
            "circuit_recovered",
        }

        if event not in allowed_events:
            raise ValueError(
                "Unknown upstream resilience event."
            )

        self.upstream_resilience_events_total.labels(
            service=service,
            event=event,
        ).inc()

    def record_upstream_request(
        self,
        *,
        service: str,
        outcome: str,
        duration_seconds: float,
    ) -> None:
        self.upstream_requests_total.labels(
            service=service,
            outcome=outcome,
        ).inc()

        self.upstream_request_duration_seconds.labels(
            service=service,
        ).observe(
            max(
                duration_seconds,
                0.0,
            )
        )


def get_gateway_metrics(
    request: Request,
) -> GatewayMetrics | None:
    """
    Resolve the in-process Gateway metrics registry.

    Metrics remain optional so isolated tests and
    degraded observability cannot affect business
    processing.
    """

    metrics = getattr(
        request.app.state,
        "metrics",
        None,
    )

    if not isinstance(
        metrics,
        GatewayMetrics,
    ):
        return None

    return metrics


def record_security_metric_best_effort(
    *,
    request: Request,
    event_type: str,
    outcome: str,
) -> None:
    """
    Record one security metric without ever changing
    the security decision already made by the Gateway.
    """

    metrics = get_gateway_metrics(
        request
    )

    if metrics is None:
        return

    try:
        metrics.record_security_event(
            event_type=event_type,
            outcome=outcome,
        )
    except Exception:
        return


def record_rate_limit_metric_best_effort(
    *,
    request: Request,
    scope: str,
    decision: str,
) -> None:
    """
    Record one bounded rate-limit decision.
    """

    metrics = get_gateway_metrics(
        request
    )

    if metrics is None:
        return

    try:
        metrics.record_rate_limit_decision(
            scope=scope,
            decision=decision,
        )
    except Exception:
        return


def record_upstream_resilience_metric_best_effort(
    *,
    request: Request,
    service: str,
    event: str,
) -> None:
    """
    Export one bounded retry/circuit event without
    allowing monitoring failures to affect proxy
    processing.
    """

    metrics = get_gateway_metrics(
        request
    )

    if metrics is None:
        return

    try:
        metrics.record_upstream_resilience_event(
            service=service,
            event=event,
        )
    except Exception:
        return


def record_upstream_metric_best_effort(
    *,
    request: Request,
    service: str,
    outcome: str,
    duration_seconds: float,
) -> None:
    """
    Record one bounded upstream observation.

    No path, query string or correlation identifier is
    exported as a Prometheus label.
    """

    metrics = get_gateway_metrics(
        request
    )

    if metrics is None:
        return

    try:
        metrics.record_upstream_request(
            service=service,
            outcome=outcome,
            duration_seconds=(
                duration_seconds
            ),
        )
    except Exception:
        return


@dataclass(
    slots=True,
)
class MetricsServerHandle:
    """
    Handle used to stop the Prometheus exposition
    thread cleanly during application shutdown.
    """

    server: WSGIServer
    thread: Thread

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

        self.thread.join(
            timeout=5
        )


def start_metrics_server(
    *,
    metrics: GatewayMetrics,
    settings: MetricsSettings,
) -> MetricsServerHandle:
    """
    Start the internal Prometheus HTTP exporter.
    """

    server, thread = start_http_server(
        port=settings.port,
        addr=settings.host,
        registry=metrics.registry,
    )

    return MetricsServerHandle(
        server=server,
        thread=thread,
    )
