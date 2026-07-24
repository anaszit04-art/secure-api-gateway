from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Final
from uuid import UUID, uuid4

import jwt

from jwt import InvalidTokenError as PyJWTInvalidTokenError

from gateway.app.auth.config import AuthSettings


ACCESS_TOKEN_TYPE: Final[str] = "access"

REQUIRED_ACCESS_TOKEN_CLAIMS: Final[tuple[str, ...]] = (
    "sub",
    "iat",
    "exp",
    "iss",
    "aud",
    "jti",
    "type",
)


class TokenCreationError(ValueError):
    """Raised when an access token cannot be created."""


class TokenValidationError(ValueError):
    """Raised when an access token is invalid or expired."""


@dataclass(
    frozen=True,
    slots=True,
)
class AccessTokenClaims:
    """
    Validated claims extracted from an access token.
    """

    subject: str
    token_id: UUID
    issued_at: datetime
    expires_at: datetime


def _ensure_aware_utc(
    value: datetime,
) -> datetime:
    """
    Convert a timezone-aware datetime to UTC.
    """
    if value.tzinfo is None:
        raise TokenCreationError(
            "Token timestamps must be timezone-aware."
        )

    return value.astimezone(timezone.utc)


def _numeric_date_to_datetime(
    value: Any,
    *,
    claim_name: str,
) -> datetime:
    """
    Convert a JWT NumericDate claim into a UTC datetime.
    """
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
    ):
        raise TokenValidationError(
            f"Invalid {claim_name} claim."
        )

    try:
        return datetime.fromtimestamp(
            value,
            tz=timezone.utc,
        )
    except (
        OverflowError,
        OSError,
        ValueError,
    ) as exc:
        raise TokenValidationError(
            f"Invalid {claim_name} claim."
        ) from exc


def create_access_token(
    *,
    subject: str,
    settings: AuthSettings,
    now: datetime | None = None,
) -> str:
    """
    Create a signed JWT access token.
    """
    normalized_subject = subject.strip()

    if not normalized_subject:
        raise TokenCreationError(
            "Token subject cannot be empty."
        )

    issued_at = _ensure_aware_utc(
        now or datetime.now(timezone.utc)
    )

    expires_at = issued_at + timedelta(
        minutes=settings.access_token_minutes
    )

    payload = {
        "sub": normalized_subject,
        "iat": issued_at,
        "exp": expires_at,
        "iss": settings.issuer,
        "aud": settings.audience,
        "jti": str(uuid4()),
        "type": ACCESS_TOKEN_TYPE,
    }

    encoded_token = jwt.encode(
        payload,
        settings.secret_key,
        algorithm=settings.algorithm,
    )

    if not isinstance(encoded_token, str):
        raise TokenCreationError(
            "JWT encoder returned an invalid token."
        )

    return encoded_token


def decode_access_token(
    *,
    token: str,
    settings: AuthSettings,
) -> AccessTokenClaims:
    """
    Verify and decode a JWT access token.
    """
    if not token.strip():
        raise TokenValidationError(
            "Access token cannot be empty."
        )

    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[
                settings.algorithm,
            ],
            audience=settings.audience,
            issuer=settings.issuer,
            options={
                "require": list(
                    REQUIRED_ACCESS_TOKEN_CLAIMS
                ),
            },
            leeway=0,
        )
    except PyJWTInvalidTokenError as exc:
        raise TokenValidationError(
            "Invalid or expired access token."
        ) from exc

    if payload.get("type") != ACCESS_TOKEN_TYPE:
        raise TokenValidationError(
            "Invalid access token type."
        )

    subject = payload.get("sub")

    if (
        not isinstance(subject, str)
        or not subject.strip()
    ):
        raise TokenValidationError(
            "Invalid token subject."
        )

    token_id_value = payload.get("jti")

    if not isinstance(token_id_value, str):
        raise TokenValidationError(
            "Invalid token identifier."
        )

    try:
        token_id = UUID(token_id_value)
    except ValueError as exc:
        raise TokenValidationError(
            "Invalid token identifier."
        ) from exc

    issued_at = _numeric_date_to_datetime(
        payload.get("iat"),
        claim_name="iat",
    )

    expires_at = _numeric_date_to_datetime(
        payload.get("exp"),
        claim_name="exp",
    )

    if expires_at <= issued_at:
        raise TokenValidationError(
            "Token expiration must be after issuance."
        )

    return AccessTokenClaims(
        subject=subject,
        token_id=token_id,
        issued_at=issued_at,
        expires_at=expires_at,
    )
