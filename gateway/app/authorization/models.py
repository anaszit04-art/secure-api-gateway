from __future__ import annotations

import re
import unicodedata

from dataclasses import dataclass
from typing import Final
from uuid import UUID


MAXIMUM_ROLE_NAME_LENGTH: Final[int] = 64
MAXIMUM_PERMISSION_CODE_LENGTH: Final[int] = 128


ROLE_NAME_PATTERN: Final[
    re.Pattern[str]
] = re.compile(
    r"^[a-z][a-z0-9_-]*$"
)


PERMISSION_CODE_PATTERN: Final[
    re.Pattern[str]
] = re.compile(
    r"^[a-z][a-z0-9-]*"
    r"(?:\:[a-z][a-z0-9-]*){2}$"
)


class RoleNamePolicyError(ValueError):
    """
    Raised when a role name violates the
    authorization naming policy.
    """


class PermissionCodePolicyError(ValueError):
    """
    Raised when a permission code violates the
    authorization naming policy.
    """


def normalize_role_name(
    role_name: str,
) -> str:
    """
    Normalize and validate a role name.

    Examples:
        user
        operator
        admin
    """

    if not isinstance(
        role_name,
        str,
    ):
        raise RoleNamePolicyError(
            "Role name must be a string."
        )

    normalized = unicodedata.normalize(
        "NFKC",
        role_name,
    ).strip().casefold()

    if not normalized:
        raise RoleNamePolicyError(
            "Role name cannot be empty."
        )

    if (
        len(normalized)
        > MAXIMUM_ROLE_NAME_LENGTH
    ):
        raise RoleNamePolicyError(
            "Role name is too long."
        )

    if (
        ROLE_NAME_PATTERN.fullmatch(
            normalized
        )
        is None
    ):
        raise RoleNamePolicyError(
            "Role name contains invalid "
            "characters."
        )

    return normalized


def normalize_permission_code(
    permission_code: str,
) -> str:
    """
    Normalize and validate a permission code.

    Permission codes use three segments:

        resource:target:action

    Example:

        proxy:service-a:read
    """

    if not isinstance(
        permission_code,
        str,
    ):
        raise PermissionCodePolicyError(
            "Permission code must be a string."
        )

    normalized = unicodedata.normalize(
        "NFKC",
        permission_code,
    ).strip().casefold()

    if not normalized:
        raise PermissionCodePolicyError(
            "Permission code cannot be empty."
        )

    if (
        len(normalized)
        > MAXIMUM_PERMISSION_CODE_LENGTH
    ):
        raise PermissionCodePolicyError(
            "Permission code is too long."
        )

    if (
        PERMISSION_CODE_PATTERN.fullmatch(
            normalized
        )
        is None
    ):
        raise PermissionCodePolicyError(
            "Permission code must contain "
            "exactly three valid segments."
        )

    return normalized


@dataclass(
    frozen=True,
    slots=True,
)
class StoredRole:
    """
    Authorization-domain representation
    of a role.
    """

    id: UUID
    name: str
    description: str
    is_system: bool


@dataclass(
    frozen=True,
    slots=True,
)
class StoredPermission:
    """
    Authorization-domain representation
    of a permission.
    """

    id: UUID
    code: str
    description: str
