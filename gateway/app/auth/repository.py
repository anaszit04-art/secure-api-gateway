from dataclasses import replace
from datetime import datetime, timezone
from threading import RLock
from uuid import uuid4

from gateway.app.auth.models import (
    StoredUser,
    normalize_username,
)


class UserAlreadyExistsError(ValueError):
    """Raised when a username is already registered."""


class UserNotFoundError(LookupError):
    """Raised when a requested user does not exist."""


class InMemoryUserRepository:
    """
    Thread-safe in-memory user repository.

    This repository is suitable for development and tests.
    It will later be replaced by a PostgreSQL repository.
    """

    def __init__(self) -> None:
        self._users_by_username: dict[
            str,
            StoredUser,
        ] = {}

        self._lock = RLock()

    def create_user(
        self,
        *,
        username: str,
        hashed_password: str,
    ) -> StoredUser:
        normalized_username = normalize_username(
            username
        )

        if not hashed_password.strip():
            raise ValueError(
                "Hashed password cannot be empty."
            )

        with self._lock:
            if (
                normalized_username
                in self._users_by_username
            ):
                raise UserAlreadyExistsError(
                    "Username is already registered."
                )

            user = StoredUser(
                id=uuid4(),
                username=normalized_username,
                hashed_password=hashed_password,
                is_active=True,
                created_at=datetime.now(
                    timezone.utc
                ),
            )

            self._users_by_username[
                normalized_username
            ] = user

            return user

    def get_by_username(
        self,
        username: str,
    ) -> StoredUser | None:
        normalized_username = normalize_username(
            username
        )

        with self._lock:
            return self._users_by_username.get(
                normalized_username
            )

    def update_password_hash(
        self,
        *,
        username: str,
        hashed_password: str,
    ) -> StoredUser:
        normalized_username = normalize_username(
            username
        )

        if not hashed_password.strip():
            raise ValueError(
                "Hashed password cannot be empty."
            )

        with self._lock:
            existing_user = (
                self._users_by_username.get(
                    normalized_username
                )
            )

            if existing_user is None:
                raise UserNotFoundError(
                    "User not found."
                )

            updated_user = replace(
                existing_user,
                hashed_password=hashed_password,
            )

            self._users_by_username[
                normalized_username
            ] = updated_user

            return updated_user

    def count(self) -> int:
        with self._lock:
            return len(
                self._users_by_username
            )
