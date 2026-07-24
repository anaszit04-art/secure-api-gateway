import re
import unicodedata

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    field_validator,
)

from gateway.app.auth.passwords import (
    validate_password,
)


MINIMUM_USERNAME_LENGTH: Final[int] = 3
MAXIMUM_USERNAME_LENGTH: Final[int] = 64

USERNAME_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[a-z0-9][a-z0-9._-]*[a-z0-9]$"
)


class UsernamePolicyError(ValueError):
    """Raised when a username does not satisfy the policy."""


def normalize_username(username: str) -> str:
    """
    Normalize and validate a username.

    Usernames:
    - are normalized using Unicode NFKC;
    - are stripped and converted to lowercase;
    - contain between 3 and 64 characters;
    - use only ASCII letters, digits, dots,
      underscores and hyphens;
    - start and end with a letter or digit.
    """
    if not isinstance(username, str):
        raise UsernamePolicyError(
            "Username must be a string."
        )

    normalized_username = unicodedata.normalize(
        "NFKC",
        username,
    ).strip().casefold()

    username_length = len(normalized_username)

    if username_length < MINIMUM_USERNAME_LENGTH:
        raise UsernamePolicyError(
            "Username must contain at least "
            f"{MINIMUM_USERNAME_LENGTH} characters."
        )

    if username_length > MAXIMUM_USERNAME_LENGTH:
        raise UsernamePolicyError(
            "Username cannot contain more than "
            f"{MAXIMUM_USERNAME_LENGTH} characters."
        )

    if USERNAME_PATTERN.fullmatch(
        normalized_username
    ) is None:
        raise UsernamePolicyError(
            "Username may contain only lowercase letters, "
            "digits, dots, underscores and hyphens, and "
            "must start and end with a letter or digit."
        )

    return normalized_username


class UserRegistration(BaseModel):
    """
    Data accepted when registering a new user.
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    username: str
    password: str

    @field_validator(
        "username",
        mode="before",
    )
    @classmethod
    def validate_username(
        cls,
        value: Any,
    ) -> str:
        return normalize_username(value)

    @field_validator("password")
    @classmethod
    def validate_plaintext_password(
        cls,
        value: str,
    ) -> str:
        validate_password(value)

        return value


class UserPublic(BaseModel):
    """
    Safe user representation returned by the API.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    id: UUID
    username: str
    is_active: bool
    created_at: datetime

class TokenResponse(BaseModel):
    """
    OAuth2-compatible access-token response.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    access_token: str
    token_type: Literal["bearer"] = "bearer"



@dataclass(
    frozen=True,
    slots=True,
)
class StoredUser:
    """
    Internal user representation.

    This object contains the password hash and must never
    be returned directly by an API endpoint.
    """

    id: UUID
    username: str
    hashed_password: str
    is_active: bool
    created_at: datetime


def to_public_user(
    stored_user: StoredUser,
) -> UserPublic:
    """
    Convert an internal user into its safe public form.
    """
    return UserPublic(
        id=stored_user.id,
        username=stored_user.username,
        is_active=stored_user.is_active,
        created_at=stored_user.created_at,
    )
