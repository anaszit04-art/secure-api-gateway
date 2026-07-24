from typing import Final

from gateway.app.auth.config import AuthSettings
from gateway.app.auth.models import (
    StoredUser,
    UserPublic,
    UserRegistration,
    UsernamePolicyError,
    to_public_user,
)
from gateway.app.auth.passwords import (
    hash_password,
    verify_and_update_password,
    verify_password,
)
from gateway.app.auth.repository import (
    InMemoryUserRepository,
)
from gateway.app.auth.tokens import (
    create_access_token,
)


INVALID_CREDENTIALS_MESSAGE: Final[str] = (
    "Invalid username or password."
)

DUMMY_PASSWORD_HASH: Final[str] = hash_password(
    "dummy-authentication-password-2026"
)


class AuthenticationError(ValueError):
    """
    Raised when authentication cannot be completed.

    The message remains intentionally generic to avoid
    revealing whether a username exists.
    """


class AuthenticationService:
    """
    Coordinate user registration, password verification
    and JWT access-token creation.
    """

    def __init__(
        self,
        *,
        repository: InMemoryUserRepository,
        settings: AuthSettings,
    ) -> None:
        self._repository = repository
        self._settings = settings

    def register_user(
        self,
        registration: UserRegistration,
    ) -> UserPublic:
        """
        Hash and store a new user.

        Only the safe public representation is returned.
        """
        hashed_password = hash_password(
            registration.password
        )

        stored_user = self._repository.create_user(
            username=registration.username,
            hashed_password=hashed_password,
        )

        return to_public_user(stored_user)

    def authenticate_user(
        self,
        *,
        username: str,
        password: str,
    ) -> StoredUser:
        """
        Verify credentials and return the stored user.

        Unknown usernames and incorrect passwords produce
        the same public error.
        """
        try:
            stored_user = (
                self._repository.get_by_username(
                    username
                )
            )
        except UsernamePolicyError:
            stored_user = None

        if stored_user is None:
            # Perform a real Argon2 verification even when
            # the user is absent to reduce timing differences.
            verify_password(
                password,
                DUMMY_PASSWORD_HASH,
            )

            raise AuthenticationError(
                INVALID_CREDENTIALS_MESSAGE
            )

        is_valid, replacement_hash = (
            verify_and_update_password(
                password,
                stored_user.hashed_password,
            )
        )

        if not is_valid or not stored_user.is_active:
            raise AuthenticationError(
                INVALID_CREDENTIALS_MESSAGE
            )

        if replacement_hash is not None:
            stored_user = (
                self._repository.update_password_hash(
                    username=stored_user.username,
                    hashed_password=replacement_hash,
                )
            )

        return stored_user

    def authenticate_and_create_token(
        self,
        *,
        username: str,
        password: str,
    ) -> str:
        """
        Authenticate credentials and issue an access token.
        """
        stored_user = self.authenticate_user(
            username=username,
            password=password,
        )

        return create_access_token(
            subject=stored_user.username,
            settings=self._settings,
        )
