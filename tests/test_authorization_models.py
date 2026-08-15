import pytest

from gateway.app.authorization.models import (
    PermissionCodePolicyError,
    RoleNamePolicyError,
    normalize_permission_code,
    normalize_role_name,
)


@pytest.mark.parametrize(
    (
        "raw",
        "expected",
    ),
    [
        (
            "USER",
            "user",
        ),
        (
            " operator ",
            "operator",
        ),
        (
            "security_admin",
            "security_admin",
        ),
    ],
)
def test_normalize_role_name(
    raw: str,
    expected: str,
) -> None:
    assert (
        normalize_role_name(
            raw
        )
        == expected
    )


@pytest.mark.parametrize(
    "invalid",
    [
        "",
        " ",
        "Admin Role",
        "admin!",
        "-admin",
        "a" * 65,
    ],
)
def test_invalid_role_name_is_rejected(
    invalid: str,
) -> None:
    with pytest.raises(
        RoleNamePolicyError
    ):
        normalize_role_name(
            invalid
        )


@pytest.mark.parametrize(
    (
        "raw",
        "expected",
    ),
    [
        (
            "PROXY:SERVICE-A:READ",
            "proxy:service-a:read",
        ),
        (
            " proxy:service-b:write ",
            "proxy:service-b:write",
        ),
        (
            "authorization:roles:manage",
            "authorization:roles:manage",
        ),
    ],
)
def test_normalize_permission_code(
    raw: str,
    expected: str,
) -> None:
    assert (
        normalize_permission_code(
            raw
        )
        == expected
    )


@pytest.mark.parametrize(
    "invalid",
    [
        "",
        "proxy",
        "proxy:read",
        "proxy:service-a:read:extra",
        "proxy:Service A:read",
        ":service-a:read",
        "proxy::read",
        "x" * 129,
    ],
)
def test_invalid_permission_code_is_rejected(
    invalid: str,
) -> None:
    with pytest.raises(
        PermissionCodePolicyError
    ):
        normalize_permission_code(
            invalid
        )
