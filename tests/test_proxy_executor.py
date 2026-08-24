from __future__ import annotations

import asyncio

from typing import Any

import httpx
import pytest

from gateway.app.proxy.executor import (
    ResilientUpstreamExecutor,
)
from gateway.app.proxy.resilience import (
    CircuitBreakerRegistry,
    CircuitOpenError,
    CircuitState,
    UpstreamResilienceSettings,
)


class SequenceAsyncClient:
    def __init__(
        self,
        outcomes: list[
            httpx.Response | Exception
        ],
    ) -> None:
        self.outcomes = list(
            outcomes
        )

        self.calls: list[
            dict[str, Any]
        ] = []

    async def request(
        self,
        **kwargs: Any,
    ) -> httpx.Response:
        self.calls.append(
            kwargs
        )

        if not self.outcomes:
            raise AssertionError(
                "No fake upstream outcome remains."
            )

        outcome = self.outcomes.pop(
            0
        )

        if isinstance(
            outcome,
            Exception,
        ):
            raise outcome

        return outcome


class RecordingSleep:
    def __init__(self) -> None:
        self.delays: list[
            float
        ] = []

    async def __call__(
        self,
        delay: float,
    ) -> None:
        self.delays.append(
            delay
        )


class FakeClock:
    def __init__(self) -> None:
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


def request_error(
    exception_type,
):
    request = httpx.Request(
        "GET",
        "http://service-a/ping",
    )

    return exception_type(
        "upstream failure",
        request=request,
    )


def build_executor(
    *,
    outcomes: list[
        httpx.Response | Exception
    ],
    settings: (
        UpstreamResilienceSettings | None
    ) = None,
    clock=None,
):
    resolved_settings = (
        settings
        or UpstreamResilienceSettings()
    )

    client = SequenceAsyncClient(
        outcomes
    )

    sleep = RecordingSleep()

    circuits = CircuitBreakerRegistry(
        service_names=(
            "service-a",
            "service-b",
        ),
        settings=resolved_settings,
        **(
            {
                "clock": clock
            }
            if clock is not None
            else {}
        ),
    )

    executor = ResilientUpstreamExecutor(
        client=client,
        circuits=circuits,
        settings=resolved_settings,
        sleep=sleep,
    )

    return (
        executor,
        client,
        circuits,
        sleep,
    )


def test_success_uses_single_attempt() -> None:
    async def scenario() -> None:
        (
            executor,
            client,
            circuits,
            sleep,
        ) = build_executor(
            outcomes=[
                httpx.Response(
                    200,
                    json={
                        "message": "pong",
                    },
                )
            ]
        )

        result = await executor.execute(
            service_name="service-a",
            method="GET",
            url="http://service-a/ping",
        )

        assert result.response.status_code == 200
        assert result.attempts == 1
        assert len(client.calls) == 1
        assert sleep.delays == []

        snapshot = await (
            circuits
            .get("service-a")
            .snapshot()
        )

        assert snapshot.state == (
            CircuitState.CLOSED
        )

        assert (
            snapshot.consecutive_failures
            == 0
        )

    asyncio.run(
        scenario()
    )


def test_get_retries_connect_error_once_then_succeeds() -> None:
    async def scenario() -> None:
        (
            executor,
            client,
            circuits,
            sleep,
        ) = build_executor(
            outcomes=[
                request_error(
                    httpx.ConnectError
                ),
                httpx.Response(
                    200
                ),
            ]
        )

        result = await executor.execute(
            service_name="service-a",
            method="GET",
            url="http://service-a/ping",
        )

        assert result.attempts == 2
        assert len(client.calls) == 2

        assert sleep.delays == [
            0.1
        ]

        snapshot = await (
            circuits
            .get("service-a")
            .snapshot()
        )

        assert (
            snapshot.consecutive_failures
            == 0
        )

    asyncio.run(
        scenario()
    )


def test_get_retries_connect_timeout_once() -> None:
    async def scenario() -> None:
        (
            executor,
            client,
            circuits,
            sleep,
        ) = build_executor(
            outcomes=[
                request_error(
                    httpx.ConnectTimeout
                ),
                httpx.Response(
                    204
                ),
            ]
        )

        result = await executor.execute(
            service_name="service-a",
            method="GET",
            url="http://service-a/ping",
        )

        assert result.attempts == 2
        assert len(client.calls) == 2
        assert sleep.delays == [0.1]

        snapshot = await (
            circuits
            .get("service-a")
            .snapshot()
        )

        assert (
            snapshot.consecutive_failures
            == 0
        )

    asyncio.run(
        scenario()
    )


def test_post_connect_error_is_never_retried() -> None:
    async def scenario() -> None:
        (
            executor,
            client,
            circuits,
            sleep,
        ) = build_executor(
            outcomes=[
                request_error(
                    httpx.ConnectError
                ),
                httpx.Response(
                    200
                ),
            ]
        )

        with pytest.raises(
            httpx.ConnectError
        ):
            await executor.execute(
                service_name="service-a",
                method="POST",
                url="http://service-a/echo",
                content=b"payload",
            )

        assert len(client.calls) == 1
        assert sleep.delays == []

        snapshot = await (
            circuits
            .get("service-a")
            .snapshot()
        )

        assert (
            snapshot.consecutive_failures
            == 1
        )

    asyncio.run(
        scenario()
    )


def test_read_timeout_is_never_retried() -> None:
    async def scenario() -> None:
        (
            executor,
            client,
            circuits,
            sleep,
        ) = build_executor(
            outcomes=[
                request_error(
                    httpx.ReadTimeout
                ),
                httpx.Response(
                    200
                ),
            ]
        )

        with pytest.raises(
            httpx.ReadTimeout
        ):
            await executor.execute(
                service_name="service-a",
                method="GET",
                url="http://service-a/ping",
            )

        assert len(client.calls) == 1
        assert sleep.delays == []

        snapshot = await (
            circuits
            .get("service-a")
            .snapshot()
        )

        assert (
            snapshot.consecutive_failures
            == 1
        )

    asyncio.run(
        scenario()
    )


def test_two_failed_attempts_count_as_one_logical_failure() -> None:
    async def scenario() -> None:
        settings = (
            UpstreamResilienceSettings(
                failure_threshold=3
            )
        )

        (
            executor,
            client,
            circuits,
            sleep,
        ) = build_executor(
            settings=settings,
            outcomes=[
                request_error(
                    httpx.ConnectError
                ),
                request_error(
                    httpx.ConnectError
                ),
            ],
        )

        with pytest.raises(
            httpx.ConnectError
        ):
            await executor.execute(
                service_name="service-a",
                method="GET",
                url="http://service-a/ping",
            )

        assert len(client.calls) == 2
        assert sleep.delays == [0.1]

        snapshot = await (
            circuits
            .get("service-a")
            .snapshot()
        )

        assert (
            snapshot.consecutive_failures
            == 1
        )

        assert snapshot.state == (
            CircuitState.CLOSED
        )

    asyncio.run(
        scenario()
    )


def test_upstream_5xx_is_not_retried_and_counts_failure() -> None:
    async def scenario() -> None:
        (
            executor,
            client,
            circuits,
            sleep,
        ) = build_executor(
            outcomes=[
                httpx.Response(
                    503
                ),
                httpx.Response(
                    200
                ),
            ]
        )

        result = await executor.execute(
            service_name="service-a",
            method="GET",
            url="http://service-a/ping",
        )

        assert result.response.status_code == 503
        assert result.attempts == 1
        assert len(client.calls) == 1
        assert sleep.delays == []

        snapshot = await (
            circuits
            .get("service-a")
            .snapshot()
        )

        assert (
            snapshot.consecutive_failures
            == 1
        )

    asyncio.run(
        scenario()
    )


def test_upstream_404_resets_failure_counter() -> None:
    async def scenario() -> None:
        settings = (
            UpstreamResilienceSettings(
                failure_threshold=3
            )
        )

        (
            executor,
            _,
            circuits,
            _,
        ) = build_executor(
            settings=settings,
            outcomes=[
                httpx.Response(
                    404
                )
            ]
        )

        breaker = circuits.get(
            "service-a"
        )

        permit = await breaker.before_request()
        await breaker.record_failure(permit)

        result = await executor.execute(
            service_name="service-a",
            method="GET",
            url="http://service-a/missing",
        )

        assert result.response.status_code == 404

        snapshot = await breaker.snapshot()

        assert (
            snapshot.consecutive_failures
            == 0
        )

    asyncio.run(
        scenario()
    )


def test_pool_timeout_does_not_increment_failure_counter() -> None:
    async def scenario() -> None:
        (
            executor,
            client,
            circuits,
            sleep,
        ) = build_executor(
            outcomes=[
                request_error(
                    httpx.PoolTimeout
                )
            ]
        )

        with pytest.raises(
            httpx.PoolTimeout
        ):
            await executor.execute(
                service_name="service-a",
                method="GET",
                url="http://service-a/ping",
            )

        assert len(client.calls) == 1
        assert sleep.delays == []

        snapshot = await (
            circuits
            .get("service-a")
            .snapshot()
        )

        assert (
            snapshot.consecutive_failures
            == 0
        )

        assert snapshot.state == (
            CircuitState.CLOSED
        )

    asyncio.run(
        scenario()
    )


def test_open_circuit_prevents_network_call() -> None:
    async def scenario() -> None:
        settings = (
            UpstreamResilienceSettings(
                failure_threshold=1,
                recovery_timeout_seconds=10,
            )
        )

        (
            executor,
            client,
            circuits,
            _,
        ) = build_executor(
            settings=settings,
            outcomes=[
                request_error(
                    httpx.ConnectError
                )
            ],
        )

        breaker = circuits.get(
            "service-a"
        )

        permit = await breaker.before_request()
        await breaker.record_failure(permit)

        with pytest.raises(
            CircuitOpenError
        ):
            await executor.execute(
                service_name="service-a",
                method="GET",
                url="http://service-a/ping",
            )

        assert client.calls == []

    asyncio.run(
        scenario()
    )


def test_half_open_probe_never_retries() -> None:
    async def scenario() -> None:
        clock = FakeClock()

        settings = (
            UpstreamResilienceSettings(
                max_attempts=2,
                failure_threshold=1,
                recovery_timeout_seconds=5,
            )
        )

        (
            executor,
            client,
            circuits,
            sleep,
        ) = build_executor(
            settings=settings,
            clock=clock,
            outcomes=[
                request_error(
                    httpx.ConnectError
                ),
                httpx.Response(
                    200
                ),
            ],
        )

        breaker = circuits.get(
            "service-a"
        )

        permit = await breaker.before_request()
        await breaker.record_failure(permit)

        clock.advance(
            5
        )

        with pytest.raises(
            httpx.ConnectError
        ):
            await executor.execute(
                service_name="service-a",
                method="GET",
                url="http://service-a/ping",
            )

        assert len(client.calls) == 1
        assert sleep.delays == []

        snapshot = await breaker.snapshot()

        assert snapshot.state == (
            CircuitState.OPEN
        )

    asyncio.run(
        scenario()
    )


def test_service_b_remains_healthy_when_service_a_opens() -> None:
    async def scenario() -> None:
        settings = (
            UpstreamResilienceSettings(
                failure_threshold=1
            )
        )

        (
            executor,
            _,
            circuits,
            _,
        ) = build_executor(
            settings=settings,
            outcomes=[
                request_error(
                    httpx.ConnectError
                ),
            ],
        )

        with pytest.raises(
            httpx.ConnectError
        ):
            await executor.execute(
                service_name="service-a",
                method="POST",
                url="http://service-a/echo",
            )

        service_a = await (
            circuits
            .get("service-a")
            .snapshot()
        )

        service_b = await (
            circuits
            .get("service-b")
            .snapshot()
        )

        assert service_a.state == (
            CircuitState.OPEN
        )

        assert service_b.state == (
            CircuitState.CLOSED
        )

    asyncio.run(
        scenario()
    )


def test_retry_emits_bounded_resilience_event() -> None:
    async def scenario() -> None:
        events = []

        (
            executor,
            client,
            _,
            _,
        ) = build_executor(
            outcomes=[
                request_error(
                    httpx.ConnectError
                ),
                httpx.Response(
                    200
                ),
            ]
        )

        executor._on_event = (
            lambda service, event:
            events.append(
                (
                    service,
                    event.value,
                )
            )
        )

        result = await executor.execute(
            service_name="service-a",
            method="GET",
            url="http://service-a/ping",
        )

        assert result.response.status_code == 200
        assert len(client.calls) == 2

        assert events == [
            (
                "service-a",
                "retry",
            )
        ]

    asyncio.run(
        scenario()
    )


def test_circuit_open_event_is_emitted_on_threshold() -> None:
    async def scenario() -> None:
        events = []

        settings = (
            UpstreamResilienceSettings(
                max_attempts=1,
                failure_threshold=1,
            )
        )

        (
            executor,
            _,
            _,
            _,
        ) = build_executor(
            settings=settings,
            outcomes=[
                request_error(
                    httpx.ConnectError
                )
            ],
        )

        executor._on_event = (
            lambda service, event:
            events.append(
                (
                    service,
                    event.value,
                )
            )
        )

        with pytest.raises(
            httpx.ConnectError
        ):
            await executor.execute(
                service_name="service-a",
                method="GET",
                url="http://service-a/ping",
            )

        assert (
            "service-a",
            "circuit_open",
        ) in events

    asyncio.run(
        scenario()
    )


def test_open_circuit_emits_rejected_event() -> None:
    async def scenario() -> None:
        events = []

        settings = (
            UpstreamResilienceSettings(
                max_attempts=1,
                failure_threshold=1,
                recovery_timeout_seconds=60,
            )
        )

        (
            executor,
            _,
            circuits,
            _,
        ) = build_executor(
            settings=settings,
            outcomes=[],
        )

        executor._on_event = (
            lambda service, event:
            events.append(
                (
                    service,
                    event.value,
                )
            )
        )

        breaker = circuits.get(
            "service-a"
        )

        permit = await breaker.before_request()
        await breaker.record_failure(permit)

        with pytest.raises(
            CircuitOpenError
        ):
            await executor.execute(
                service_name="service-a",
                method="GET",
                url="http://service-a/ping",
            )

        assert events == [
            (
                "service-a",
                "circuit_rejected",
            )
        ]

    asyncio.run(
        scenario()
    )


def test_half_open_success_emits_recovered_event() -> None:
    async def scenario() -> None:
        events = []
        clock = FakeClock()

        settings = (
            UpstreamResilienceSettings(
                max_attempts=2,
                failure_threshold=1,
                recovery_timeout_seconds=5,
            )
        )

        (
            executor,
            _,
            circuits,
            _,
        ) = build_executor(
            settings=settings,
            clock=clock,
            outcomes=[
                httpx.Response(
                    200
                )
            ],
        )

        executor._on_event = (
            lambda service, event:
            events.append(
                (
                    service,
                    event.value,
                )
            )
        )

        breaker = circuits.get(
            "service-a"
        )

        permit = await breaker.before_request()
        await breaker.record_failure(permit)

        clock.advance(
            5
        )

        result = await executor.execute(
            service_name="service-a",
            method="GET",
            url="http://service-a/ping",
        )

        assert result.response.status_code == 200

        assert events == [
            (
                "service-a",
                "circuit_recovered",
            )
        ]

    asyncio.run(
        scenario()
    )


def test_resilience_observer_failure_never_changes_result() -> None:
    async def scenario() -> None:
        (
            executor,
            _,
            _,
            _,
        ) = build_executor(
            outcomes=[
                request_error(
                    httpx.ConnectError
                ),
                httpx.Response(
                    200
                ),
            ]
        )

        def broken_observer(
            service,
            event,
        ) -> None:
            del service, event

            raise RuntimeError(
                "observability unavailable"
            )

        executor._on_event = (
            broken_observer
        )

        result = await executor.execute(
            service_name="service-a",
            method="GET",
            url="http://service-a/ping",
        )

        assert result.response.status_code == 200
        assert result.attempts == 2

    asyncio.run(
        scenario()
    )
