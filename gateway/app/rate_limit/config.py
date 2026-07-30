from __future__ import annotations

import math
import os
import re

from dataclasses import dataclass, field
from typing import Mapping
from urllib.parse import (
    SplitResult,
    quote,
    urlsplit,
    urlunsplit,
)


DEFAULT_REDIS_URL = "redis://redis:6379/0"
DEFAULT_REDIS_KEY_PREFIX = "secure-api-gateway"
DEFAULT_CONNECT_TIMEOUT_SECONDS = 2.0
DEFAULT_SOCKET_TIMEOUT_SECONDS = 2.0
DEFAULT_MAX_CONNECTIONS = 20
DEFAULT_HEALTH_CHECK_INTERVAL_SECONDS = 30

_ALLOWED_REDIS_SCHEMES = frozenset(
    {
        "redis",
        "rediss",
    }
)

_KEY_PREFIX_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9:_-]{0,63}$"
)


class RateLimitConfigError(ValueError):
    """Raised when Redis rate-limit configuration is invalid."""


@dataclass(
    frozen=True,
    slots=True,
)
class RedisSettings:
    """
    Validated Redis configuration used by the rate limiter.

    The URL is excluded from the dataclass representation to avoid
    accidentally exposing Redis credentials in logs.
    """

    url: str = field(
        default=DEFAULT_REDIS_URL,
        repr=False,
    )
    key_prefix: str = DEFAULT_REDIS_KEY_PREFIX
    connect_timeout_seconds: float = (
        DEFAULT_CONNECT_TIMEOUT_SECONDS
    )
    socket_timeout_seconds: float = (
        DEFAULT_SOCKET_TIMEOUT_SECONDS
    )
    max_connections: int = DEFAULT_MAX_CONNECTIONS
    health_check_interval_seconds: int = (
        DEFAULT_HEALTH_CHECK_INTERVAL_SECONDS
    )

    def __post_init__(self) -> None:
        normalized_url = self.url.strip()
        normalized_prefix = self.key_prefix.strip()

        if normalized_prefix != self.key_prefix:
            raise RateLimitConfigError(
                "REDIS_KEY_PREFIX must not contain "
                "leading or trailing whitespace."
            )

        object.__setattr__(
            self,
            "url",
            normalized_url,
        )
        object.__setattr__(
            self,
            "key_prefix",
            normalized_prefix,
        )

        self._validate_url(normalized_url)
        self._validate_key_prefix(
            normalized_prefix
        )
        self._validate_positive_float(
            name="connect_timeout_seconds",
            value=self.connect_timeout_seconds,
            maximum=60.0,
        )
        self._validate_positive_float(
            name="socket_timeout_seconds",
            value=self.socket_timeout_seconds,
            maximum=60.0,
        )
        self._validate_integer(
            name="max_connections",
            value=self.max_connections,
            minimum=1,
            maximum=1000,
        )
        self._validate_integer(
            name="health_check_interval_seconds",
            value=(
                self.health_check_interval_seconds
            ),
            minimum=0,
            maximum=3600,
        )

    @classmethod
    def from_environment(
        cls,
        environ: Mapping[str, str] | None = None,
    ) -> RedisSettings:
        """
        Load and validate Redis configuration from environment
        variables.
        """

        source = (
            os.environ
            if environ is None
            else environ
        )

        return cls(
            url=source.get(
                "REDIS_URL",
                DEFAULT_REDIS_URL,
            ),
            key_prefix=source.get(
                "REDIS_KEY_PREFIX",
                DEFAULT_REDIS_KEY_PREFIX,
            ),
            connect_timeout_seconds=(
                _read_float(
                    source,
                    "REDIS_CONNECT_TIMEOUT_SECONDS",
                    DEFAULT_CONNECT_TIMEOUT_SECONDS,
                )
            ),
            socket_timeout_seconds=(
                _read_float(
                    source,
                    "REDIS_SOCKET_TIMEOUT_SECONDS",
                    DEFAULT_SOCKET_TIMEOUT_SECONDS,
                )
            ),
            max_connections=_read_integer(
                source,
                "REDIS_MAX_CONNECTIONS",
                DEFAULT_MAX_CONNECTIONS,
            ),
            health_check_interval_seconds=(
                _read_integer(
                    source,
                    (
                        "REDIS_HEALTH_CHECK_"
                        "INTERVAL_SECONDS"
                    ),
                    (
                        DEFAULT_HEALTH_CHECK_INTERVAL_SECONDS
                    ),
                )
            ),
        )

    @property
    def redacted_url(self) -> str:
        """
        Return the Redis URL with its password masked.

        This value is safe to use in diagnostic logs.
        """

        parsed = self._split_url()

        if parsed.password is None:
            return self.url

        hostname = parsed.hostname or ""

        if ":" in hostname:
            hostname = f"[{hostname}]"

        port = (
            f":{parsed.port}"
            if parsed.port is not None
            else ""
        )

        username = parsed.username

        if username:
            credentials = (
                f"{quote(username, safe='')}:***@"
            )
        else:
            credentials = ":***@"

        return urlunsplit(
            (
                parsed.scheme,
                (
                    f"{credentials}"
                    f"{hostname}"
                    f"{port}"
                ),
                parsed.path,
                parsed.query,
                "",
            )
        )

    def _split_url(self) -> SplitResult:
        try:
            parsed = urlsplit(self.url)
            _ = parsed.port
        except ValueError as exc:
            raise RateLimitConfigError(
                "REDIS_URL is malformed."
            ) from exc

        return parsed

    @classmethod
    def _validate_url(
        cls,
        value: str,
    ) -> None:
        if not value:
            raise RateLimitConfigError(
                "REDIS_URL must not be empty."
            )

        try:
            parsed = urlsplit(value)
            _ = parsed.port
        except ValueError as exc:
            raise RateLimitConfigError(
                "REDIS_URL is malformed."
            ) from exc

        if parsed.scheme not in (
            _ALLOWED_REDIS_SCHEMES
        ):
            raise RateLimitConfigError(
                "REDIS_URL must use redis:// "
                "or rediss://."
            )

        if not parsed.hostname:
            raise RateLimitConfigError(
                "REDIS_URL must include a hostname."
            )

        if parsed.fragment:
            raise RateLimitConfigError(
                "REDIS_URL must not include "
                "a fragment."
            )

        database_path = parsed.path.lstrip("/")

        if (
            database_path
            and not database_path.isdigit()
        ):
            raise RateLimitConfigError(
                "REDIS_URL database must be "
                "a non-negative integer."
            )

    @staticmethod
    def _validate_key_prefix(
        value: str,
    ) -> None:
        if not _KEY_PREFIX_PATTERN.fullmatch(
            value
        ):
            raise RateLimitConfigError(
                "REDIS_KEY_PREFIX must contain "
                "1 to 64 characters and use only "
                "letters, numbers, ':', '_' or '-'."
            )

    @staticmethod
    def _validate_positive_float(
        *,
        name: str,
        value: float,
        maximum: float,
    ) -> None:
        if (
            isinstance(value, bool)
            or not isinstance(
                value,
                (int, float),
            )
            or not math.isfinite(value)
            or value <= 0
            or value > maximum
        ):
            raise RateLimitConfigError(
                f"{name} must be greater than 0 "
                f"and at most {maximum}."
            )

    @staticmethod
    def _validate_integer(
        *,
        name: str,
        value: int,
        minimum: int,
        maximum: int,
    ) -> None:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value < minimum
            or value > maximum
        ):
            raise RateLimitConfigError(
                f"{name} must be an integer "
                f"between {minimum} and {maximum}."
            )


def _read_float(
    environ: Mapping[str, str],
    name: str,
    default: float,
) -> float:
    raw_value = environ.get(
        name,
        str(default),
    ).strip()

    try:
        return float(raw_value)
    except ValueError as exc:
        raise RateLimitConfigError(
            f"{name} must be numeric."
        ) from exc


def _read_integer(
    environ: Mapping[str, str],
    name: str,
    default: int,
) -> int:
    raw_value = environ.get(
        name,
        str(default),
    ).strip()

    try:
        return int(raw_value)
    except ValueError as exc:
        raise RateLimitConfigError(
            f"{name} must be an integer."
        ) from exc
