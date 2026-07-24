from dataclasses import FrozenInstanceError

import pytest

from pydantic import ValidationError

from gateway.app.auth.models import (
    StoredUser,
    UserRegistration,
    UsernamePolicyError,
    normalize_username,
    to_public_user,
)
from gateway.app.auth.passwords import (
    hash_password,
)
from gateway.app.auth.repository import (
    InMemoryUserRepository,
    UserAlreadyExistsError,
    UserNotFoundError,
)


VALID_PASSWORD = "correct-horse-battery-staple"


def create_repository_user(
    repository: InMemoryUserRepository,
    username: str = "anas",
) -> StoredUser:
    return repository.create_user(
        username=username,
        hashed_password=hash_password(
            VALID_PASSWORD
        ),
    )


def test_normalize_username_strips_and_lowercases() -> None:
    result = normalize_username(
        "  AnAs_2026  "
    )

    assert result == "anas_2026"


@pytest.mark.parametrize(
    "invalid_username",
    [
        "ab",
        "-user",
        "user-",
        "user name",
        "utilisateuré",
    ],
)
def test_normalize_username_rejects_invalid_values(
    invalid_username: str,
) -> None:
    with pytest.raises(
        UsernamePolicyError,
    ):
        normalize_username(invalid_username)


def test_registration_model_normalizes_username() -> None:
    registration = UserRegistration(
        username="  ANAS.Dev ",
        password=VALID_PASSWORD,
    )

    assert registration.username == "anas.dev"
    assert registration.password == VALID_PASSWORD


def test_registration_model_rejects_weak_password() -> None:
    with pytest.raises(ValidationError):
        UserRegistration(
            username="anas",
            password="short",
        )


def test_registration_model_forbids_extra_fields() -> None:
    with pytest.raises(ValidationError):
        UserRegistration(
            username="anas",
            password=VALID_PASSWORD,
            role="administrator",
        )


def test_repository_creates_and_finds_user() -> None:
    repository = InMemoryUserRepository()

    created_user = create_repository_user(
        repository,
        "Anas",
    )

    found_user = repository.get_by_username(
        " ANAS "
    )

    assert found_user == created_user
    assert created_user.username == "anas"
    assert created_user.is_active is True
    assert created_user.created_at.tzinfo is not None
    assert repository.count() == 1


def test_repository_rejects_duplicate_username() -> None:
    repository = InMemoryUserRepository()

    create_repository_user(
        repository,
        "Anas",
    )

    with pytest.raises(
        UserAlreadyExistsError,
        match="Username is already registered",
    ):
        create_repository_user(
            repository,
            " ANAS ",
        )

    assert repository.count() == 1


def test_repository_returns_none_for_unknown_user() -> None:
    repository = InMemoryUserRepository()

    assert repository.get_by_username(
        "unknown-user"
    ) is None


def test_repository_rejects_empty_hash() -> None:
    repository = InMemoryUserRepository()

    with pytest.raises(
        ValueError,
        match="Hashed password cannot be empty",
    ):
        repository.create_user(
            username="anas",
            hashed_password="   ",
        )


def test_repository_updates_password_hash() -> None:
    repository = InMemoryUserRepository()

    original_user = create_repository_user(
        repository
    )

    replacement_hash = hash_password(
        "another-secure-password"
    )

    updated_user = repository.update_password_hash(
        username="ANAS",
        hashed_password=replacement_hash,
    )

    assert (
        updated_user.hashed_password
        == replacement_hash
    )
    assert updated_user.id == original_user.id

    assert (
        repository.get_by_username(
            "anas"
        )
        == updated_user
    )


def test_repository_rejects_update_for_unknown_user() -> None:
    repository = InMemoryUserRepository()

    with pytest.raises(
        UserNotFoundError,
        match="User not found",
    ):
        repository.update_password_hash(
            username="unknown-user",
            hashed_password=hash_password(
                VALID_PASSWORD
            ),
        )


def test_public_user_does_not_expose_password_hash() -> None:
    repository = InMemoryUserRepository()

    stored_user = create_repository_user(
        repository
    )

    public_user = to_public_user(
        stored_user
    )

    serialized_user = public_user.model_dump()

    assert public_user.id == stored_user.id
    assert public_user.username == "anas"
    assert "hashed_password" not in serialized_user
    assert "password" not in serialized_user


def test_stored_user_is_immutable() -> None:
    repository = InMemoryUserRepository()

    stored_user = create_repository_user(
        repository
    )

    with pytest.raises(FrozenInstanceError):
        stored_user.username = "modified"


def test_repository_generates_unique_user_ids() -> None:
    repository = InMemoryUserRepository()

    first_user = create_repository_user(
        repository,
        "first-user",
    )

    second_user = create_repository_user(
        repository,
        "second-user",
    )

    assert first_user.id != second_user.id
    assert repository.count() == 2
