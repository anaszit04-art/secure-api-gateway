import pytest

from gateway.app.auth.passwords import (
    MAXIMUM_PASSWORD_LENGTH,
    MINIMUM_PASSWORD_LENGTH,
    PasswordPolicyError,
    hash_password,
    validate_password,
    verify_and_update_password,
    verify_password,
)


VALID_PASSWORD = "correct-horse-battery-staple"


def test_hash_password_returns_argon2_hash() -> None:
    hashed_password = hash_password(
        VALID_PASSWORD
    )

    assert hashed_password != VALID_PASSWORD
    assert hashed_password.startswith("$argon2")


def test_same_password_produces_different_hashes() -> None:
    first_hash = hash_password(
        VALID_PASSWORD
    )
    second_hash = hash_password(
        VALID_PASSWORD
    )

    assert first_hash != second_hash


def test_verify_password_accepts_correct_password() -> None:
    hashed_password = hash_password(
        VALID_PASSWORD
    )

    assert verify_password(
        VALID_PASSWORD,
        hashed_password,
    ) is True


def test_verify_password_rejects_wrong_password() -> None:
    hashed_password = hash_password(
        VALID_PASSWORD
    )

    assert verify_password(
        "incorrect-password-value",
        hashed_password,
    ) is False


def test_password_supports_unicode_characters() -> None:
    password = "Passphrase-sécurisée-🔐-2026"

    hashed_password = hash_password(password)

    assert verify_password(
        password,
        hashed_password,
    ) is True


def test_password_policy_accepts_minimum_length() -> None:
    password = "a" * MINIMUM_PASSWORD_LENGTH

    validate_password(password)


@pytest.mark.parametrize(
    "invalid_password",
    [
        "",
        "short",
        " " * MINIMUM_PASSWORD_LENGTH,
    ],
)
def test_password_policy_rejects_invalid_passwords(
    invalid_password: str,
) -> None:
    with pytest.raises(
        PasswordPolicyError,
    ):
        validate_password(invalid_password)


def test_password_policy_rejects_excessive_length() -> None:
    password = "a" * (
        MAXIMUM_PASSWORD_LENGTH + 1
    )

    with pytest.raises(
        PasswordPolicyError,
        match="Password cannot contain more than 128",
    ):
        validate_password(password)


def test_hash_password_applies_password_policy() -> None:
    with pytest.raises(
        PasswordPolicyError,
        match="Password must contain at least 12",
    ):
        hash_password("too-short")


def test_verify_and_update_accepts_current_hash() -> None:
    hashed_password = hash_password(
        VALID_PASSWORD
    )

    is_valid, updated_hash = (
        verify_and_update_password(
            VALID_PASSWORD,
            hashed_password,
        )
    )

    assert is_valid is True
    assert updated_hash is None


def test_verify_and_update_rejects_wrong_password() -> None:
    hashed_password = hash_password(
        VALID_PASSWORD
    )

    is_valid, updated_hash = (
        verify_and_update_password(
            "incorrect-password-value",
            hashed_password,
        )
    )

    assert is_valid is False
    assert updated_hash is None
