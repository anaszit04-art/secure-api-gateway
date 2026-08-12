from __future__ import annotations

import math
import os
import re

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final
from urllib.parse import (
    SplitResult,
    urlsplit,
    urlunsplit,
)


DEFAULT_POOL_SIZE: Final[int] = 5
DEFAULT_MAX_OVERFLOW: Final[int] = 10

DEFAULT_POOL_TIMEOUT_SECONDS: Final[float] = 5.0
DEFAULT_CONNECT_TIMEOUT_SECONDS: Final[float] = 5.0

DEFAULT_VERIFY_ON_STARTUP: Final[bool] = False

DEFAULT_APPLICATION_NAME: Final[str] = (
    "secure-api-gateway"
)

MAXIMUM_POOL_SIZE: Final[int] = 100
MAXIMUM_MAX_OVERFLOW: Final[int] = 200

MAXIMUM_TIMEOUT_SECONDS: Final[float] = 60.0

APPLICATION_NAME_PATTERN: Final[
    re.Pattern[str]
] = re.compile(
    r"^[A-Za-z0-9._-]{1,64}$"
)


class DatabaseConfigurationError(
    RuntimeError
):
    """
    Raised when PostgreSQL configuration is invalid.
    """


@dataclass(
    frozen=True,
    slots=True,
)
class DatabaseSettings:
    """
    Validated PostgreSQL/SQLAlchemy configuration.
    """

    url: str
    pool_size: int = DEFAULT_POOL_SIZE
    max_overflow: int = DEFAULT_MAX_OVERFLOW

    pool_timeout_seconds: float = (
        DEFAULT_POOL_TIMEOUT_SECONDS
    )

    connect_timeout_seconds: float = (
        DEFAULT_CONNECT_TIMEOUT_SECONDS
    )

    verify_on_startup: bool = (
        DEFAULT_VERIFY_ON_STARTUP
    )

    application_name: str = (
        DEFAULT_APPLICATION_NAME
    )

    def __post_init__(self) -> None:
        self._validate_url(
            self.url
        )

        self._validate_integer(
            name="pool_size",
            value=self.pool_size,
            minimum=1,
            maximum=MAXIMUM_POOL_SIZE,
        )

        self._validate_integer(
            name="max_overflow",
            value=self.max_overflow,
            minimum=0,
            maximum=MAXIMUM_MAX_OVERFLOW,
        )

        self._validate_timeout(
            name="pool_timeout_seconds",
            value=self.pool_timeout_seconds,
        )

        self._validate_timeout(
            name="connect_timeout_seconds",
            value=self.connect_timeout_seconds,
        )

        if not isinstance(
            self.verify_on_startup,
            bool,
        ):
            raise DatabaseConfigurationError(
                "verify_on_startup must be "
                "a boolean."
            )

        self._validate_application_name(
            self.application_name
        )

    @property
    def redacted_url(self) -> str:
        """
        Return a safe URL suitable for logs.
        """

        parsed = urlsplit(
            self.url
        )

        username = (
            parsed.username or ""
        )

        hostname = (
            parsed.hostname or ""
        )

        if ":" in hostname:
            hostname = (
                f"[{hostname}]"
            )

        authentication = username

        if parsed.password is not None:
            authentication += ":***"

        if authentication:
            authentication += "@"

        netloc = (
            authentication
            + hostname
        )

        if parsed.port is not None:
            netloc += (
                f":{parsed.port}"
            )

        safe_url = SplitResult(
            scheme=parsed.scheme,
            netloc=netloc,
            path=parsed.path,
            query=parsed.query,
            fragment="",
        )

        return urlunsplit(
            safe_url
        )

    @classmethod
    def from_environment(
        cls,
        environment: (
            Mapping[str, str] | None
        ) = None,
    ) -> DatabaseSettings:
        """
        Build settings from environment variables.
        """

        source = (
            os.environ
            if environment is None
            else environment
        )

        database_url = cls._required_string(
            source,
            "DATABASE_URL",
        )

        return cls(
            url=database_url,
            pool_size=cls._read_integer(
                source,
                "DATABASE_POOL_SIZE",
                DEFAULT_POOL_SIZE,
            ),
            max_overflow=cls._read_integer(
                source,
                "DATABASE_MAX_OVERFLOW",
                DEFAULT_MAX_OVERFLOW,
            ),
            pool_timeout_seconds=(
                cls._read_float(
                    source,
                    (
                        "DATABASE_POOL_TIMEOUT_"
                        "SECONDS"
                    ),
                    (
                        DEFAULT_POOL_TIMEOUT_SECONDS
                    ),
                )
            ),
            connect_timeout_seconds=(
                cls._read_float(
                    source,
                    (
                        "DATABASE_CONNECT_TIMEOUT_"
                        "SECONDS"
                    ),
                    (
                        DEFAULT_CONNECT_TIMEOUT_SECONDS
                    ),
                )
            ),
            verify_on_startup=(
                cls._read_boolean(
                    source,
                    (
                        "DATABASE_VERIFY_"
                        "ON_STARTUP"
                    ),
                    DEFAULT_VERIFY_ON_STARTUP,
                )
            ),
            application_name=(
                source.get(
                    "DATABASE_APPLICATION_NAME",
                    DEFAULT_APPLICATION_NAME,
                )
            ),
        )

    @staticmethod
    def _required_string(
        source: Mapping[str, str],
        name: str,
    ) -> str:
        raw_value = source.get(
            name
        )

        if raw_value is None:
            raise DatabaseConfigurationError(
                f"{name} is required."
            )

        value = raw_value.strip()

        if not value:
            raise DatabaseConfigurationError(
                f"{name} cannot be empty."
            )

        return value

    @staticmethod
    def _read_integer(
        source: Mapping[str, str],
        name: str,
        default: int,
    ) -> int:
        raw_value = source.get(
            name,
            str(default),
        ).strip()

        try:
            return int(
                raw_value
            )
        except ValueError as exc:
            raise DatabaseConfigurationError(
                f"{name} must be an integer."
            ) from exc

    @staticmethod
    def _read_float(
        source: Mapping[str, str],
        name: str,
        default: float,
    ) -> float:
        raw_value = source.get(
            name,
            str(default),
        ).strip()

        try:
            value = float(
                raw_value
            )
        except ValueError as exc:
            raise DatabaseConfigurationError(
                f"{name} must be a number."
            ) from exc

        if not math.isfinite(
            value
        ):
            raise DatabaseConfigurationError(
                f"{name} must be finite."
            )

        return value

    @staticmethod
    def _read_boolean(
        source: Mapping[str, str],
        name: str,
        default: bool,
    ) -> bool:
        raw_value = source.get(
            name,
            (
                "true"
                if default
                else "false"
            ),
        ).strip().casefold()

        if raw_value in {
            "true",
            "1",
            "yes",
            "on",
        }:
            return True

        if raw_value in {
            "false",
            "0",
            "no",
            "off",
        }:
            return False

        raise DatabaseConfigurationError(
            f"{name} must be a boolean."
        )

    @staticmethod
    def _validate_url(
        url: str,
    ) -> None:
        if not isinstance(
            url,
            str,
        ):
            raise DatabaseConfigurationError(
                "DATABASE_URL must be "
                "a string."
            )

        if url != url.strip():
            raise DatabaseConfigurationError(
                "DATABASE_URL must not contain "
                "leading or trailing whitespace."
            )

        try:
            parsed = urlsplit(
                url
            )

            port = parsed.port
        except ValueError as exc:
            raise DatabaseConfigurationError(
                "DATABASE_URL is invalid."
            ) from exc

        if (
            parsed.scheme
            != "postgresql+asyncpg"
        ):
            raise DatabaseConfigurationError(
                "DATABASE_URL must use the "
                "postgresql+asyncpg scheme."
            )

        if not parsed.username:
            raise DatabaseConfigurationError(
                "DATABASE_URL must include "
                "a username."
            )

        if parsed.password is None:
            raise DatabaseConfigurationError(
                "DATABASE_URL must include "
                "a password."
            )

        if not parsed.hostname:
            raise DatabaseConfigurationError(
                "DATABASE_URL must include "
                "a hostname."
            )

        if (
            port is not None
            and (
                port <= 0
                or port > 65_535
            )
        ):
            raise DatabaseConfigurationError(
                "DATABASE_URL contains "
                "an invalid port."
            )

        database_name = (
            parsed.path
            .strip("/")
            .strip()
        )

        if not database_name:
            raise DatabaseConfigurationError(
                "DATABASE_URL must include "
                "a database name."
            )

        if parsed.fragment:
            raise DatabaseConfigurationError(
                "DATABASE_URL must not "
                "contain a fragment."
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
            or not isinstance(
                value,
                int,
            )
            or value < minimum
            or value > maximum
        ):
            raise DatabaseConfigurationError(
                f"{name} must be an integer "
                f"between {minimum} "
                f"and {maximum}."
            )

    @staticmethod
    def _validate_timeout(
        *,
        name: str,
        value: float,
    ) -> None:
        if (
            isinstance(value, bool)
            or not isinstance(
                value,
                (int, float),
            )
            or not math.isfinite(
                float(value)
            )
            or value <= 0
            or value > MAXIMUM_TIMEOUT_SECONDS
        ):
            raise DatabaseConfigurationError(
                f"{name} must be greater "
                "than 0 and at most "
                f"{MAXIMUM_TIMEOUT_SECONDS}."
            )

    @staticmethod
    def _validate_application_name(
        value: str,
    ) -> None:
        if not isinstance(
            value,
            str,
        ):
            raise DatabaseConfigurationError(
                "application_name must be "
                "a string."
            )

        if value != value.strip():
            raise DatabaseConfigurationError(
                "application_name must not "
                "contain surrounding whitespace."
            )

        if (
            APPLICATION_NAME_PATTERN.fullmatch(
                value
            )
            is None
        ):
            raise DatabaseConfigurationError(
                "application_name must contain "
                "1 to 64 letters, numbers, "
                "dots, underscores or hyphens."
            )
