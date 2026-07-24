from typing import Final

from pwdlib import PasswordHash


MINIMUM_PASSWORD_LENGTH: Final[int] = 12
MAXIMUM_PASSWORD_LENGTH: Final[int] = 128


class PasswordPolicyError(ValueError):
    """Raised when a password does not satisfy the policy."""


PASSWORD_HASHER: Final[PasswordHash] = (
    PasswordHash.recommended()
)


def validate_password(password: str) -> None:
    """
    Validate a plaintext password before registration.

    The password must:
    - contain between 12 and 128 characters;
    - contain at least one non-whitespace character.
    """
    password_length = len(password)

    if password_length < MINIMUM_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            "Password must contain at least "
            f"{MINIMUM_PASSWORD_LENGTH} characters."
        )

    if password_length > MAXIMUM_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            "Password cannot contain more than "
            f"{MAXIMUM_PASSWORD_LENGTH} characters."
        )

    if not password.strip():
        raise PasswordPolicyError(
            "Password cannot contain only whitespace."
        )


def hash_password(password: str) -> str:
    """
    Validate and hash a plaintext password using Argon2.
    """
    validate_password(password)

    return PASSWORD_HASHER.hash(password)


def verify_password(
    password: str,
    hashed_password: str,
) -> bool:
    """
    Verify a plaintext password against a stored hash.
    """
    return PASSWORD_HASHER.verify(
        password,
        hashed_password,
    )


def verify_and_update_password(
    password: str,
    hashed_password: str,
) -> tuple[bool, str | None]:
    """
    Verify a password and return a newer hash if needed.

    The returned tuple contains:
    - whether the password is valid;
    - a replacement hash, or None if no update is needed.
    """
    return PASSWORD_HASHER.verify_and_update(
        password,
        hashed_password,
    )
