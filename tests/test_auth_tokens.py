from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import UUID

import jwt
import pytest

from gateway.app.auth.config import AuthSettings
from gateway.app.auth.tokens import (
    ACCESS_TOKEN_TYPE,
    TokenCreationError,
    TokenValidationError,
    create_access_token,
    decode_access_token,
)


@pytest.fixture
def auth_settings() -> AuthSettings:
    return AuthSettings(
        secret_key="a" * 48,
        algorithm="HS256",
        access_token_minutes=15,
        issuer="secure-api-gateway",
        audience="secure-api-clients",
    )


def build_payload(
    settings: AuthSettings,
) -> dict[str, object]:
    now = datetime.now(timezone.utc)

    return {
        "sub": "anas",
        "iat": now,
        "exp": now + timedelta(minutes=15),
        "iss": settings.issuer,
        "aud": settings.audience,
        "jti": "7f963fc4-f5de-4db0-b8ab-50949d63bc0a",
        "type": ACCESS_TOKEN_TYPE,
    }


def encode_payload(
    payload: dict[str, object],
    settings: AuthSettings,
) -> str:
    return jwt.encode(
        payload,
        settings.secret_key,
        algorithm=settings.algorithm,
    )


def test_access_token_round_trip(
    auth_settings: AuthSettings,
) -> None:
    token = create_access_token(
        subject="anas",
        settings=auth_settings,
    )

    claims = decode_access_token(
        token=token,
        settings=auth_settings,
    )

    assert claims.subject == "anas"
    assert isinstance(claims.token_id, UUID)
    assert claims.issued_at.tzinfo is not None
    assert claims.expires_at.tzinfo is not None
    assert claims.expires_at > claims.issued_at


def test_access_tokens_receive_unique_identifiers(
    auth_settings: AuthSettings,
) -> None:
    first_token = create_access_token(
        subject="anas",
        settings=auth_settings,
    )
    second_token = create_access_token(
        subject="anas",
        settings=auth_settings,
    )

    first_claims = decode_access_token(
        token=first_token,
        settings=auth_settings,
    )
    second_claims = decode_access_token(
        token=second_token,
        settings=auth_settings,
    )

    assert (
        first_claims.token_id
        != second_claims.token_id
    )


def test_access_token_strips_subject(
    auth_settings: AuthSettings,
) -> None:
    token = create_access_token(
        subject="  anas  ",
        settings=auth_settings,
    )

    claims = decode_access_token(
        token=token,
        settings=auth_settings,
    )

    assert claims.subject == "anas"


def test_access_token_rejects_empty_subject(
    auth_settings: AuthSettings,
) -> None:
    with pytest.raises(
        TokenCreationError,
        match="Token subject cannot be empty",
    ):
        create_access_token(
            subject="   ",
            settings=auth_settings,
        )


def test_access_token_rejects_naive_datetime(
    auth_settings: AuthSettings,
) -> None:
    with pytest.raises(
        TokenCreationError,
        match="timezone-aware",
    ):
        create_access_token(
            subject="anas",
            settings=auth_settings,
            now=datetime(2026, 7, 24, 12, 0),
        )


def test_decode_rejects_expired_token(
    auth_settings: AuthSettings,
) -> None:
    token = create_access_token(
        subject="anas",
        settings=auth_settings,
        now=(
            datetime.now(timezone.utc)
            - timedelta(minutes=16)
        ),
    )

    with pytest.raises(
        TokenValidationError,
        match="Invalid or expired access token",
    ):
        decode_access_token(
            token=token,
            settings=auth_settings,
        )


def test_decode_rejects_tampered_token(
    auth_settings: AuthSettings,
) -> None:
    token = create_access_token(
        subject="anas",
        settings=auth_settings,
    )

    header, payload, signature = token.split(".")

    replacement = (
        "A"
        if signature[0] != "A"
        else "B"
    )

    tampered_token = ".".join(
        (
            header,
            payload,
            replacement + signature[1:],
        )
    )

    with pytest.raises(TokenValidationError):
        decode_access_token(
            token=tampered_token,
            settings=auth_settings,
        )


def test_decode_rejects_wrong_secret(
    auth_settings: AuthSettings,
) -> None:
    token = create_access_token(
        subject="anas",
        settings=auth_settings,
    )

    wrong_settings = replace(
        auth_settings,
        secret_key="b" * 48,
    )

    with pytest.raises(TokenValidationError):
        decode_access_token(
            token=token,
            settings=wrong_settings,
        )


def test_decode_rejects_wrong_issuer(
    auth_settings: AuthSettings,
) -> None:
    token = create_access_token(
        subject="anas",
        settings=auth_settings,
    )

    wrong_settings = replace(
        auth_settings,
        issuer="another-gateway",
    )

    with pytest.raises(TokenValidationError):
        decode_access_token(
            token=token,
            settings=wrong_settings,
        )


def test_decode_rejects_wrong_audience(
    auth_settings: AuthSettings,
) -> None:
    token = create_access_token(
        subject="anas",
        settings=auth_settings,
    )

    wrong_settings = replace(
        auth_settings,
        audience="another-client",
    )

    with pytest.raises(TokenValidationError):
        decode_access_token(
            token=token,
            settings=wrong_settings,
        )


def test_decode_rejects_wrong_token_type(
    auth_settings: AuthSettings,
) -> None:
    payload = build_payload(auth_settings)
    payload["type"] = "refresh"

    token = encode_payload(
        payload,
        auth_settings,
    )

    with pytest.raises(
        TokenValidationError,
        match="Invalid access token type",
    ):
        decode_access_token(
            token=token,
            settings=auth_settings,
        )


def test_decode_rejects_missing_required_claim(
    auth_settings: AuthSettings,
) -> None:
    payload = build_payload(auth_settings)
    payload.pop("jti")

    token = encode_payload(
        payload,
        auth_settings,
    )

    with pytest.raises(TokenValidationError):
        decode_access_token(
            token=token,
            settings=auth_settings,
        )


def test_decode_rejects_malformed_token_identifier(
    auth_settings: AuthSettings,
) -> None:
    payload = build_payload(auth_settings)
    payload["jti"] = "not-a-valid-uuid"

    token = encode_payload(
        payload,
        auth_settings,
    )

    with pytest.raises(
        TokenValidationError,
        match="Invalid token identifier",
    ):
        decode_access_token(
            token=token,
            settings=auth_settings,
        )
