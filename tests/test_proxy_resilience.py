from __future__ import annotations

import asyncio

import httpx
import pytest

from gateway.app.proxy.resilience import (
    CircuitBreakerRegistry,
    CircuitOpenError,
    CircuitState,
    ServiceCircuitBreaker,
    UpstreamResilienceSettings,
    method_is_retryable,
    response_counts_for_circuit_failure,
    transport_error_counts_for_circuit,
    transport_error_is_retryable,
)


class FakeClock:
    def __init__(
        self,
    ) -> None:
        self.value = 100.0

    def __call__(
        self,
    ) -> float:
        return self.value

    def advance(
        self,
        seconds: float,
    ) -> None:
        self.value += seconds


def test_default_resilience_settings_are_bounded(
    monkeypatch,
) -> None:
    for name in (
        "UPSTREAM_MAX_ATTEMPTS",
        "UPSTREAM_RETRY_BASE_DELAY_SECONDS",
        "UPSTREAM_CIRCUIT_FAILURE_THRESHOLD",
        "UPSTREAM_CIRCUIT_RECOVERY_SECONDS",
    ):
        monkeypatch.delenv(
            name,
            raising=False,
        )

    settings = (
        UpstreamResilienceSettings
        .from_environment()
    )

    assert settings.max_attempts == 2

    assert (
        settings.retry_base_delay_seconds
        == 0.1
    )

    assert settings.failure_threshold == 3

    assert (
        settings.recovery_timeout_seconds
        == 10.0
    )


def test_invalid_resilience_settings_are_rejected() -> None:
    with pytest.raises(
        ValueError
    ):
        UpstreamResilienceSettings(
            max_attempts=20
        )

    with pytest.raises(
        ValueError
    ):
        UpstreamResilienceSettings(
            failure_threshold=0
        )

    with pytest.raises(
        ValueError
    ):
        UpstreamResilienceSettings(
            recovery_timeout_seconds=0
        )


def test_only_safe_methods_are_retryable() -> None:
    assert method_is_retryable(
        "GET"
    )

    assert method_is_retryable(
        "head"
    )

    assert method_is_retryable(
        "OPTIONS"
    )

    assert not method_is_retryable(
        "POST"
    )

    assert not method_is_retryable(
        "PATCH"
    )

    assert not method_is_retryable(
        "PUT"
    )

    assert not method_is_retryable(
        "DELETE"
    )


def test_only_connection_failures_are_retried() -> None:
    request = httpx.Request(
        "GET",
        "http://service-a/ping",
    )

    assert transport_error_is_retryable(
        method="GET",
        error=httpx.ConnectError(
            "connection failed",
            request=request,
        ),
    )

    assert transport_error_is_retryable(
        method="GET",
        error=httpx.ConnectTimeout(
            "connect timeout",
            request=request,
        ),
    )

    assert not transport_error_is_retryable(
        method="GET",
        error=httpx.ReadTimeout(
            "read timeout",
            request=request,
        ),
    )

    assert not transport_error_is_retryable(
        method="POST",
        error=httpx.ConnectError(
            "connection failed",
            request=request,
        ),
    )


def test_pool_timeout_does_not_penalize_upstream_circuit() -> None:
    request = httpx.Request(
        "GET",
        "http://service-a/ping",
    )

    assert not transport_error_counts_for_circuit(
        httpx.PoolTimeout(
            "pool timeout",
            request=request,
        )
    )

    assert transport_error_counts_for_circuit(
        httpx.ConnectError(
            "connection failed",
            request=request,
        )
    )

    assert transport_error_counts_for_circuit(
        httpx.ReadTimeout(
            "read timeout",
            request=request,
        )
    )


def test_only_upstream_5xx_response_counts_as_failure() -> None:
    assert not (
        response_counts_for_circuit_failure(
            200
        )
    )

    assert not (
        response_counts_for_circuit_failure(
            404
        )
    )

    assert (
        response_counts_for_circuit_failure(
            500
        )
    )

    assert (
        response_counts_for_circuit_failure(
            503
        )
    )


def test_circuit_opens_after_consecutive_failures() -> None:
    async def scenario() -> None:
        clock = FakeClock()

        breaker = ServiceCircuitBreaker(
            settings=(
                UpstreamResilienceSettings(
                    failure_threshold=3,
                    recovery_timeout_seconds=10,
                )
            ),
            clock=clock,
        )

        await breaker.before_request()
        await breaker.record_failure()

        await breaker.before_request()
        await breaker.record_failure()

        snapshot = await breaker.snapshot()

        assert snapshot.state == (
            CircuitState.CLOSED
        )

        assert (
            snapshot.consecutive_failures
            == 2
        )

        await breaker.before_request()
        await breaker.record_failure()

        snapshot = await breaker.snapshot()

        assert snapshot.state == (
            CircuitState.OPEN
        )

        assert (
            snapshot.consecutive_failures
            == 3
        )

    asyncio.run(
        scenario()
    )


def test_open_circuit_rejects_without_calling_upstream() -> None:
    async def scenario() -> None:
        clock = FakeClock()

        breaker = ServiceCircuitBreaker(
            settings=(
                UpstreamResilienceSettings(
                    failure_threshold=1,
                    recovery_timeout_seconds=10,
                )
            ),
            clock=clock,
        )

        await breaker.before_request()
        await breaker.record_failure()

        with pytest.raises(
            CircuitOpenError
        ) as captured:
            await breaker.before_request()

        assert (
            captured.value
            .retry_after_seconds
            == 10
        )

    asyncio.run(
        scenario()
    )


def test_circuit_allows_one_half_open_probe_after_cooldown() -> None:
    async def scenario() -> None:
        clock = FakeClock()

        breaker = ServiceCircuitBreaker(
            settings=(
                UpstreamResilienceSettings(
                    failure_threshold=1,
                    recovery_timeout_seconds=10,
                )
            ),
            clock=clock,
        )

        await breaker.before_request()
        await breaker.record_failure()

        clock.advance(
            10
        )

        await breaker.before_request()

        snapshot = await breaker.snapshot()

        assert snapshot.state == (
            CircuitState.HALF_OPEN
        )

        assert (
            snapshot
            .half_open_probe_in_flight
            is True
        )

        with pytest.raises(
            CircuitOpenError
        ):
            await breaker.before_request()

    asyncio.run(
        scenario()
    )


def test_successful_half_open_probe_closes_circuit() -> None:
    async def scenario() -> None:
        clock = FakeClock()

        breaker = ServiceCircuitBreaker(
            settings=(
                UpstreamResilienceSettings(
                    failure_threshold=1,
                    recovery_timeout_seconds=5,
                )
            ),
            clock=clock,
        )

        await breaker.before_request()
        await breaker.record_failure()

        clock.advance(
            5
        )

        await breaker.before_request()
        await breaker.record_success()

        snapshot = await breaker.snapshot()

        assert snapshot.state == (
            CircuitState.CLOSED
        )

        assert (
            snapshot.consecutive_failures
            == 0
        )

        assert (
            snapshot
            .half_open_probe_in_flight
            is False
        )

    asyncio.run(
        scenario()
    )


def test_failed_half_open_probe_reopens_circuit() -> None:
    async def scenario() -> None:
        clock = FakeClock()

        settings = (
            UpstreamResilienceSettings(
                failure_threshold=1,
                recovery_timeout_seconds=5,
            )
        )

        breaker = ServiceCircuitBreaker(
            settings=settings,
            clock=clock,
        )

        await breaker.before_request()
        await breaker.record_failure()

        clock.advance(
            5
        )

        await breaker.before_request()
        await breaker.record_failure()

        snapshot = await breaker.snapshot()

        assert snapshot.state == (
            CircuitState.OPEN
        )

        assert (
            snapshot.retry_after_seconds
            == 5
        )

    asyncio.run(
        scenario()
    )


def test_service_circuits_are_isolated() -> None:
    async def scenario() -> None:
        registry = CircuitBreakerRegistry(
            service_names=(
                "service-a",
                "service-b",
            ),
            settings=(
                UpstreamResilienceSettings(
                    failure_threshold=1
                )
            ),
        )

        service_a = registry.get(
            "service-a"
        )

        service_b = registry.get(
            "service-b"
        )

        await service_a.before_request()
        await service_a.record_failure()

        service_a_snapshot = (
            await service_a.snapshot()
        )

        service_b_snapshot = (
            await service_b.snapshot()
        )

        assert (
            service_a_snapshot.state
            == CircuitState.OPEN
        )

        assert (
            service_b_snapshot.state
            == CircuitState.CLOSED
        )

    asyncio.run(
        scenario()
    )


def test_neutral_half_open_result_releases_probe_without_failure_increment() -> None:
    async def scenario() -> None:
        clock = FakeClock()

        settings = (
            UpstreamResilienceSettings(
                failure_threshold=1,
                recovery_timeout_seconds=5,
            )
        )

        breaker = ServiceCircuitBreaker(
            settings=settings,
            clock=clock,
        )

        await breaker.before_request()
        await breaker.record_failure()

        clock.advance(
            5
        )

        await breaker.before_request()

        before = await breaker.snapshot()

        assert before.state == (
            CircuitState.HALF_OPEN
        )

        await breaker.record_neutral()

        after = await breaker.snapshot()

        assert after.state == (
            CircuitState.OPEN
        )

        assert (
            after.consecutive_failures
            == 1
        )

        assert (
            after.half_open_probe_in_flight
            is False
        )

        assert (
            after.retry_after_seconds
            == 5
        )

    asyncio.run(
        scenario()
    )
