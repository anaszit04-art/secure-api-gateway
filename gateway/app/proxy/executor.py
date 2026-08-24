from __future__ import annotations

import asyncio

from collections.abc import (
    Awaitable,
    Callable,
)
from dataclasses import dataclass
from typing import Any

import httpx

from gateway.app.proxy.resilience import (
    CircuitBreakerRegistry,
    CircuitOpenError,
    CircuitPermit,
    ServiceCircuitBreaker,
    UpstreamResilienceEvent,
    UpstreamResilienceSettings,
    response_counts_for_circuit_failure,
    transport_error_counts_for_circuit,
    transport_error_is_retryable,
)


SleepCallable = Callable[
    [float],
    Awaitable[None],
]

ResilienceEventCallback = Callable[
    [
        str,
        UpstreamResilienceEvent,
    ],
    None,
]


@dataclass(
    frozen=True,
    slots=True,
)
class UpstreamExecutionResult:
    response: httpx.Response
    attempts: int


class ResilientUpstreamExecutor:
    """
    Execute one logical upstream operation with bounded
    retry and per-service circuit breaking.

    Resilience events are emitted through an optional
    callback. Callback failures are deliberately ignored
    so observability can never modify business behavior.
    """

    def __init__(
        self,
        *,
        client: httpx.AsyncClient,
        circuits: CircuitBreakerRegistry,
        settings: UpstreamResilienceSettings,
        sleep: SleepCallable = asyncio.sleep,
        on_event: (
            ResilienceEventCallback | None
        ) = None,
    ) -> None:
        self._client = client
        self._circuits = circuits
        self._settings = settings
        self._sleep = sleep
        self._on_event = on_event

    def _emit_event(
        self,
        *,
        service_name: str,
        event: UpstreamResilienceEvent,
    ) -> None:
        if self._on_event is None:
            return

        try:
            self._on_event(
                service_name,
                event,
            )
        except Exception:
            return

    async def _record_failure(
        self,
        *,
        breaker: ServiceCircuitBreaker,
        permit: CircuitPermit,
        service_name: str,
    ) -> None:
        opened = await breaker.record_failure(
            permit
        )

        if opened:
            self._emit_event(
                service_name=service_name,
                event=(
                    UpstreamResilienceEvent
                    .CIRCUIT_OPEN
                ),
            )

    async def _record_neutral(
        self,
        *,
        breaker: ServiceCircuitBreaker,
        permit: CircuitPermit,
        service_name: str,
    ) -> None:
        opened = await breaker.record_neutral(
            permit
        )

        if opened:
            self._emit_event(
                service_name=service_name,
                event=(
                    UpstreamResilienceEvent
                    .CIRCUIT_OPEN
                ),
            )

    async def _record_success(
        self,
        *,
        breaker: ServiceCircuitBreaker,
        permit: CircuitPermit,
        service_name: str,
    ) -> None:
        recovered = await breaker.record_success(
            permit
        )

        if recovered:
            self._emit_event(
                service_name=service_name,
                event=(
                    UpstreamResilienceEvent
                    .CIRCUIT_RECOVERED
                ),
            )

    def _retry_delay(
        self,
        *,
        failed_attempt: int,
    ) -> float:
        return min(
            (
                self._settings
                .retry_base_delay_seconds
                * (
                    2
                    ** (
                        failed_attempt
                        - 1
                    )
                )
            ),
            2.0,
        )

    async def execute(
        self,
        *,
        service_name: str,
        method: str,
        url: str,
        params: Any = None,
        headers: Any = None,
        content: Any = None,
    ) -> UpstreamExecutionResult:
        breaker = self._circuits.get(
            service_name
        )

        try:
            permit = await breaker.before_request()

        except CircuitOpenError:
            self._emit_event(
                service_name=service_name,
                event=(
                    UpstreamResilienceEvent
                    .CIRCUIT_REJECTED
                ),
            )

            raise

        max_attempts = (
            1
            if permit.half_open_probe
            else self._settings.max_attempts
        )

        attempts = 0

        try:
            while attempts < max_attempts:
                attempts += 1

                try:
                    response = (
                        await self._client.request(
                            method=method,
                            url=url,
                            params=params,
                            headers=headers,
                            content=content,
                        )
                    )

                except httpx.RequestError as exc:
                    should_retry = (
                        attempts < max_attempts
                        and transport_error_is_retryable(
                            method=method,
                            error=exc,
                        )
                    )

                    if should_retry:
                        self._emit_event(
                            service_name=service_name,
                            event=(
                                UpstreamResilienceEvent
                                .RETRY
                            ),
                        )

                        delay = self._retry_delay(
                            failed_attempt=attempts
                        )

                        if delay > 0:
                            await self._sleep(
                                delay
                            )

                        continue

                    if (
                        transport_error_counts_for_circuit(
                            exc
                        )
                    ):
                        await self._record_failure(
                            breaker=breaker,
                            permit=permit,
                            service_name=(
                                service_name
                            ),
                        )

                    else:
                        await self._record_neutral(
                            breaker=breaker,
                            permit=permit,
                            service_name=(
                                service_name
                            ),
                        )

                    raise

                if (
                    response_counts_for_circuit_failure(
                        response.status_code
                    )
                ):
                    await self._record_failure(
                        breaker=breaker,
                        permit=permit,
                        service_name=service_name,
                    )

                else:
                    await self._record_success(
                        breaker=breaker,
                        permit=permit,
                        service_name=service_name,
                    )

                return UpstreamExecutionResult(
                    response=response,
                    attempts=attempts,
                )

            raise RuntimeError(
                "Upstream retry loop exited "
                "without a result."
            )

        except asyncio.CancelledError:
            await self._record_neutral(
                breaker=breaker,
                permit=permit,
                service_name=service_name,
            )

            raise
