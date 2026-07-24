import os

from dataclasses import dataclass
from typing import Final


DEFAULT_JWT_ALGORITHM: Final[str] = "HS256"
DEFAULT_ACCESS_TOKEN_MINUTES: Final[int] = 15
DEFAULT_JWT_ISSUER: Final[str] = "secure-api-gateway"
DEFAULT_JWT_AUDIENCE: Final[str] = "secure-api-clients"

MINIMUM_SECRET_LENGTH: Final[int] = 32
MAXIMUM_ACCESS_TOKEN_MINUTES: Final[int] = 1440

SUPPORTED_JWT_ALGORITHMS: Final[frozenset[str]] = frozenset(
    {
        "HS256",
    }
)


class AuthConfigurationError(RuntimeError):
    """Raised when the authentication configuration is invalid."""


@dataclass(
    frozen=True,
    slots=True,
)
class AuthSettings:
    secret_key: str
    algorithm: str
    access_token_minutes: int
    issuer: str
    audience: str


def read_positive_integer(
    environment_name: str,
    default_value: int,
) -> int:
    raw_value = os.getenv(
        environment_name,
        str(default_value),
    ).strip()

    try:
        parsed_value = int(raw_value)
    except ValueError as exc:
        raise AuthConfigurationError(
            f"{environment_name} must be a positive integer."
        ) from exc

    if parsed_value <= 0:
        raise AuthConfigurationError(
            f"{environment_name} must be a positive integer."
        )

    return parsed_value


def load_auth_settings() -> AuthSettings:
    secret_key = os.getenv(
        "JWT_SECRET_KEY",
        "",
    ).strip()

    if len(secret_key) < MINIMUM_SECRET_LENGTH:
        raise AuthConfigurationError(
            "JWT_SECRET_KEY must contain at least "
            f"{MINIMUM_SECRET_LENGTH} characters."
        )

    algorithm = os.getenv(
        "JWT_ALGORITHM",
        DEFAULT_JWT_ALGORITHM,
    ).strip()

    if algorithm not in SUPPORTED_JWT_ALGORITHMS:
        raise AuthConfigurationError(
            f"Unsupported JWT algorithm: {algorithm}"
        )

    access_token_minutes = read_positive_integer(
        "JWT_ACCESS_TOKEN_MINUTES",
        DEFAULT_ACCESS_TOKEN_MINUTES,
    )

    if (
        access_token_minutes
        > MAXIMUM_ACCESS_TOKEN_MINUTES
    ):
        raise AuthConfigurationError(
            "JWT_ACCESS_TOKEN_MINUTES cannot exceed "
            f"{MAXIMUM_ACCESS_TOKEN_MINUTES}."
        )

    issuer = os.getenv(
        "JWT_ISSUER",
        DEFAULT_JWT_ISSUER,
    ).strip()

    audience = os.getenv(
        "JWT_AUDIENCE",
        DEFAULT_JWT_AUDIENCE,
    ).strip()

    if not issuer:
        raise AuthConfigurationError(
            "JWT_ISSUER cannot be empty."
        )

    if not audience:
        raise AuthConfigurationError(
            "JWT_AUDIENCE cannot be empty."
        )

    return AuthSettings(
        secret_key=secret_key,
        algorithm=algorithm,
        access_token_minutes=access_token_minutes,
        issuer=issuer,
        audience=audience,
    )
