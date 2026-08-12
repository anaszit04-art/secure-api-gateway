from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from threading import RLock
from typing import Protocol, cast
from uuid import uuid4

from gateway.app.auth.models import (
    StoredUser,
    normalize_username,
)


class UserAlreadyExistsError(ValueError):
    """Raised when a username is already registered."""


class UserNotFoundError(LookupError):
    """Raised when a requested user does not exist."""


class UserRepository(Protocol):
    """
    Asynchronous persistence contract used by the
    authentication domain service.

    Implementations may use PostgreSQL or an adapter
    around an in-memory repository.
    """

    async def create_user(
        self,
        *,
        username: str,
        hashed_password: str,
    ) -> StoredUser:
        ...

    async def get_by_username(
        self,
        username: str,
    ) -> StoredUser | None:
        ...

    async def update_password_hash(
        self,
        *,
        username: str,
        hashed_password: str,
    ) -> StoredUser:
        ...

    async def count(
        self,
    ) -> int:
        ...


class InMemoryUserRepository:
    """
    Thread-safe synchronous in-memory user repository.

    It remains useful for focused unit tests. Application
    services consume it through AsyncInMemoryUserRepository.
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


class AsyncInMemoryUserRepository:
    """
    Async adapter around the synchronous in-memory
    repository.

    In-memory operations are extremely short and contain
    no external I/O, therefore delegation can remain
    directly in-process.
    """

    def __init__(
        self,
        repository: InMemoryUserRepository,
    ) -> None:
        self._repository = repository

    async def create_user(
        self,
        *,
        username: str,
        hashed_password: str,
    ) -> StoredUser:
        return self._repository.create_user(
            username=username,
            hashed_password=hashed_password,
        )

    async def get_by_username(
        self,
        username: str,
    ) -> StoredUser | None:
        return self._repository.get_by_username(
            username
        )

    async def update_password_hash(
        self,
        *,
        username: str,
        hashed_password: str,
    ) -> StoredUser:
        return self._repository.update_password_hash(
            username=username,
            hashed_password=hashed_password,
        )

    async def count(
        self,
    ) -> int:
        return self._repository.count()


def adapt_user_repository(
    repository: (
        UserRepository
        | InMemoryUserRepository
    ),
) -> UserRepository:
    """
    Adapt legacy synchronous in-memory repositories to
    the asynchronous authentication contract.

    PostgreSQL repositories already satisfy the protocol
    and are returned unchanged.
    """

    if isinstance(
        repository,
        InMemoryUserRepository,
    ):
        return AsyncInMemoryUserRepository(
            repository
        )

    return cast(
        UserRepository,
        repository,
    )
