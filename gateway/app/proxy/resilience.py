from __future__ import annotations

import asyncio
import math
import os

from collections.abc import (
    Callable,
    Iterable,
)
from dataclasses import dataclass
from enum import StrEnum
from time import monotonic
from typing import Final

import httpx


SAFE_RETRY_METHODS: Final[
    frozenset[str]
] = frozenset(
    {
        "GET",
        "HEAD",
        "OPTIONS",
    }
)


class CircuitState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class UpstreamResilienceEvent(StrEnum):
    RETRY = "retry"
    CIRCUIT_OPEN = "circuit_open"
    CIRCUIT_REJECTED = "circuit_rejected"
    CIRCUIT_RECOVERED = "circuit_recovered"


class CircuitOpenError(RuntimeError):
    """
    Raised when an upstream circuit rejects a call
    before any network request is issued.
    """

    def __init__(
        self,
        *,
        retry_after_seconds: int,
    ) -> None:
        self.retry_after_seconds = max(
            1,
            retry_after_seconds,
        )

        super().__init__(
            "Upstream circuit is open."
        )


@dataclass(
    frozen=True,
    slots=True,
)
class UpstreamResilienceSettings:
    """
    Bounded resilience configuration.

    max_attempts includes the initial attempt.

    The default therefore means:
        one initial attempt
        + at most one retry
    """

    max_attempts: int = 2
    retry_base_delay_seconds: float = 0.1
    failure_threshold: int = 3
    recovery_timeout_seconds: float = 10.0

    def __post_init__(self) -> None:
        if not 1 <= self.max_attempts <= 3:
            raise ValueError(
                "max_attempts must be between "
                "1 and 3."
            )

        if not (
            0.0
            <= self.retry_base_delay_seconds
            <= 2.0
        ):
            raise ValueError(
                "retry_base_delay_seconds must "
                "be between 0 and 2 seconds."
            )

        if not 1 <= self.failure_threshold <= 20:
            raise ValueError(
                "failure_threshold must be "
                "between 1 and 20."
            )

        if not (
            1.0
            <= self.recovery_timeout_seconds
            <= 300.0
        ):
            raise ValueError(
                "recovery_timeout_seconds must "
                "be between 1 and 300 seconds."
            )

    @classmethod
    def from_environment(
        cls,
    ) -> UpstreamResilienceSettings:
        raw_max_attempts = os.environ.get(
            "UPSTREAM_MAX_ATTEMPTS",
            "2",
        )

        raw_retry_delay = os.environ.get(
            "UPSTREAM_RETRY_BASE_DELAY_SECONDS",
            "0.1",
        )

        raw_failure_threshold = os.environ.get(
            "UPSTREAM_CIRCUIT_FAILURE_THRESHOLD",
            "3",
        )

        raw_recovery_timeout = os.environ.get(
            "UPSTREAM_CIRCUIT_RECOVERY_SECONDS",
            "10",
        )

        try:
            max_attempts = int(
                raw_max_attempts
            )

            retry_base_delay_seconds = float(
                raw_retry_delay
            )

            failure_threshold = int(
                raw_failure_threshold
            )

            recovery_timeout_seconds = float(
                raw_recovery_timeout
            )

        except ValueError as exc:
            raise ValueError(
                "Invalid upstream resilience "
                "configuration."
            ) from exc

        return cls(
            max_attempts=max_attempts,
            retry_base_delay_seconds=(
                retry_base_delay_seconds
            ),
            failure_threshold=(
                failure_threshold
            ),
            recovery_timeout_seconds=(
                recovery_timeout_seconds
            ),
        )


@dataclass(
    frozen=True,
    slots=True,
)
class CircuitSnapshot:
    state: CircuitState
    consecutive_failures: int
    retry_after_seconds: int
    half_open_probe_in_flight: bool


@dataclass(
    frozen=True,
    slots=True,
)
class CircuitPermit:
    """
    Admission token for one logical upstream call.

    The generation prevents a completion admitted under
    an older circuit state from mutating a newer state.

    half_open_probe identifies the single recovery probe
    admitted while the circuit is HALF_OPEN.
    """

    generation: int
    half_open_probe: bool


def method_is_retryable(
    method: str,
) -> bool:
    """
    Retry only methods with safe HTTP semantics.

    PUT and DELETE are deliberately excluded because
    this Gateway cannot prove business-level
    idempotence for every upstream implementation.
    """

    return (
        method.upper()
        in SAFE_RETRY_METHODS
    )


def transport_error_is_retryable(
    *,
    method: str,
    error: Exception,
) -> bool:
    """
    Retry only failures occurring before a reliable
    upstream exchange has been established.

    ReadTimeout and WriteTimeout are deliberately not
    retried because the upstream may already have
    processed the request.
    """

    if not method_is_retryable(
        method
    ):
        return False

    return isinstance(
        error,
        (
            httpx.ConnectError,
            httpx.ConnectTimeout,
        ),
    )


def transport_error_counts_for_circuit(
    error: Exception,
) -> bool:
    """
    Return whether a transport failure indicates
    upstream unavailability/degradation.

    PoolTimeout is local Gateway saturation and must not
    penalize the upstream service's circuit.
    """

    if isinstance(
        error,
        httpx.PoolTimeout,
    ):
        return False

    return isinstance(
        error,
        httpx.RequestError,
    )


def response_counts_for_circuit_failure(
    status_code: int,
) -> bool:
    """
    Upstream 5xx responses contribute to the circuit.

    1xx-4xx responses prove that the upstream was
    reachable, even when the business response is an
    error such as 404.
    """

    return (
        500
        <= status_code
        <= 599
    )


class ServiceCircuitBreaker:
    """
    In-memory circuit breaker for one registered
    upstream service.

    CLOSED:
        requests pass normally.

    OPEN:
        requests fail immediately.

    HALF_OPEN:
        after the recovery timeout, exactly one probe is
        admitted. Concurrent requests remain rejected
        until that probe succeeds or fails.
    """

    def __init__(
        self,
        *,
        settings: UpstreamResilienceSettings,
        clock: Callable[
            [],
            float,
        ] = monotonic,
    ) -> None:
        self._settings = settings
        self._clock = clock

        self._state = (
            CircuitState.CLOSED
        )

        self._consecutive_failures = 0
        self._opened_at: float | None = None

        self._half_open_probe_in_flight = (
            False
        )

        # Incremented whenever the circuit transitions
        # between major lifecycle states. Completions
        # carrying an older generation are stale and
        # must not mutate the current circuit.
        self._generation = 0

        self._lock = asyncio.Lock()

    def _retry_after_unlocked(
        self,
    ) -> int:
        if self._opened_at is None:
            return 0

        remaining = (
            self._settings
            .recovery_timeout_seconds
            - (
                self._clock()
                - self._opened_at
            )
        )

        if remaining <= 0:
            return 0

        return max(
            1,
            math.ceil(
                remaining
            ),
        )

    async def before_request(
        self,
    ) -> CircuitPermit:
        """
        Admit or reject one logical upstream call.

        The returned permit binds the logical call to
        the circuit generation under which it was
        admitted.
        """

        async with self._lock:
            if (
                self._state
                == CircuitState.CLOSED
            ):
                return CircuitPermit(
                    generation=self._generation,
                    half_open_probe=False,
                )

            if (
                self._state
                == CircuitState.OPEN
            ):
                retry_after = (
                    self._retry_after_unlocked()
                )

                if retry_after > 0:
                    raise CircuitOpenError(
                        retry_after_seconds=(
                            retry_after
                        ),
                    )

                self._state = (
                    CircuitState.HALF_OPEN
                )

                self._half_open_probe_in_flight = (
                    True
                )

                self._generation += 1

                return CircuitPermit(
                    generation=self._generation,
                    half_open_probe=True,
                )

            if (
                self._half_open_probe_in_flight
            ):
                raise CircuitOpenError(
                    retry_after_seconds=1
                )

            self._half_open_probe_in_flight = (
                True
            )

            return CircuitPermit(
                generation=self._generation,
                half_open_probe=True,
            )

    async def record_success(
        self,
        permit: CircuitPermit,
    ) -> bool:
        """
        Record a healthy logical call.

        Returns True only when a valid HALF_OPEN probe
        recovered the circuit.

        Stale completions are ignored.
        """

        async with self._lock:
            if (
                permit.generation
                != self._generation
            ):
                return False

            if permit.half_open_probe:
                if (
                    self._state
                    != CircuitState.HALF_OPEN
                    or not (
                        self
                        ._half_open_probe_in_flight
                    )
                ):
                    return False

                self._state = (
                    CircuitState.CLOSED
                )

                self._consecutive_failures = 0
                self._opened_at = None

                self._half_open_probe_in_flight = (
                    False
                )

                self._generation += 1

                return True

            if (
                self._state
                != CircuitState.CLOSED
            ):
                return False

            self._consecutive_failures = 0
            self._opened_at = None

            return False

    async def record_failure(
        self,
        permit: CircuitPermit,
    ) -> bool:
        """
        Record one logical upstream failure.

        Returns True only when this completion caused
        the circuit to transition to OPEN.

        Stale completions are ignored.
        """

        async with self._lock:
            if (
                permit.generation
                != self._generation
            ):
                return False

            if permit.half_open_probe:
                if (
                    self._state
                    != CircuitState.HALF_OPEN
                    or not (
                        self
                        ._half_open_probe_in_flight
                    )
                ):
                    return False

                self._state = (
                    CircuitState.OPEN
                )

                self._opened_at = (
                    self._clock()
                )

                self._consecutive_failures = (
                    self._settings
                    .failure_threshold
                )

                self._half_open_probe_in_flight = (
                    False
                )

                self._generation += 1

                return True

            if (
                self._state
                != CircuitState.CLOSED
            ):
                return False

            self._consecutive_failures += 1

            if (
                self._consecutive_failures
                >= self._settings
                .failure_threshold
            ):
                self._state = (
                    CircuitState.OPEN
                )

                self._opened_at = (
                    self._clock()
                )

                self._half_open_probe_in_flight = (
                    False
                )

                self._generation += 1

                return True

            return False

    async def record_neutral(
        self,
        permit: CircuitPermit,
    ) -> bool:
        """
        Finish a logical call that cannot be attributed
        to upstream health.

        Returns True only when a valid HALF_OPEN probe
        is returned to OPEN.

        A stale completion cannot release or alter the
        current HALF_OPEN probe.
        """

        async with self._lock:
            if (
                permit.generation
                != self._generation
            ):
                return False

            if (
                permit.half_open_probe
                and self._state
                == CircuitState.HALF_OPEN
                and self
                ._half_open_probe_in_flight
            ):
                self._state = (
                    CircuitState.OPEN
                )

                self._opened_at = (
                    self._clock()
                )

                self._half_open_probe_in_flight = (
                    False
                )

                self._generation += 1

                return True

            return False

    async def snapshot(
        self,
    ) -> CircuitSnapshot:
        async with self._lock:
            return CircuitSnapshot(
                state=self._state,
                consecutive_failures=(
                    self._consecutive_failures
                ),
                retry_after_seconds=(
                    self._retry_after_unlocked()
                ),
                half_open_probe_in_flight=(
                    self
                    ._half_open_probe_in_flight
                ),
            )


class CircuitBreakerRegistry:
    """
    Explicit per-service circuit registry.

    Only service names supplied at construction exist;
    callers cannot dynamically create arbitrary circuit
    keys.
    """

    def __init__(
        self,
        *,
        service_names: Iterable[str],
        settings: UpstreamResilienceSettings,
        clock: Callable[
            [],
            float,
        ] = monotonic,
    ) -> None:
        names = tuple(
            dict.fromkeys(
                service_names
            )
        )

        if not names:
            raise ValueError(
                "At least one upstream service "
                "is required."
            )

        self._breakers = {
            service_name: ServiceCircuitBreaker(
                settings=settings,
                clock=clock,
            )
            for service_name in names
        }

    def get(
        self,
        service_name: str,
    ) -> ServiceCircuitBreaker:
        try:
            return self._breakers[
                service_name
            ]
        except KeyError as exc:
            raise LookupError(
                "No circuit breaker exists for "
                f"service: {service_name}"
            ) from exc
