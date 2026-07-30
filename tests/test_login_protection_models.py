import pytest

from gateway.app.rate_limit.login import (
    LoginProtectionDecision,
    LoginProtectionPolicy,
    LoginProtectionPolicyError,
    canonicalize_login_identifier,
)


def test_login_policy_accepts_valid_values() -> None:
    policy = LoginProtectionPolicy(
        name="account-login",
        failure_threshold=5,
        failure_window_seconds=900,
        lockout_seconds=300,
    )

    assert policy.name == "account-login"
    assert policy.failure_threshold == 5
    assert policy.failure_window_seconds == 900
    assert policy.lockout_seconds == 300


@pytest.mark.parametrize(
    "name",
    [
        "",
        " Account",
        ":account",
        "x" * 65,
    ],
)
def test_login_policy_rejects_invalid_names(
    name: str,
) -> None:
    with pytest.raises(
        LoginProtectionPolicyError
    ):
        LoginProtectionPolicy(
            name=name,
            failure_threshold=5,
            failure_window_seconds=900,
            lockout_seconds=300,
        )


@pytest.mark.parametrize(
    "threshold",
    [
        0,
        -1,
        101,
        True,
        1.5,
    ],
)
def test_login_policy_rejects_invalid_threshold(
    threshold: object,
) -> None:
    with pytest.raises(
        LoginProtectionPolicyError
    ):
        LoginProtectionPolicy(
            name="account-login",
            failure_threshold=(
                threshold  # type: ignore[arg-type]
            ),
            failure_window_seconds=900,
            lockout_seconds=300,
        )


@pytest.mark.parametrize(
    "window",
    [
        0,
        -1,
        86_401,
        True,
    ],
)
def test_login_policy_rejects_invalid_failure_window(
    window: object,
) -> None:
    with pytest.raises(
        LoginProtectionPolicyError
    ):
        LoginProtectionPolicy(
            name="account-login",
            failure_threshold=5,
            failure_window_seconds=(
                window  # type: ignore[arg-type]
            ),
            lockout_seconds=300,
        )


@pytest.mark.parametrize(
    "duration",
    [
        0,
        -1,
        86_401,
        True,
    ],
)
def test_login_policy_rejects_invalid_lockout_duration(
    duration: object,
) -> None:
    with pytest.raises(
        LoginProtectionPolicyError
    ):
        LoginProtectionPolicy(
            name="account-login",
            failure_threshold=5,
            failure_window_seconds=900,
            lockout_seconds=(
                duration  # type: ignore[arg-type]
            ),
        )


def test_login_identifier_is_canonicalized() -> None:
    assert canonicalize_login_identifier(
        "  ANAS  "
    ) == "anas"


def test_empty_login_identifier_uses_stable_sentinel() -> None:
    assert canonicalize_login_identifier(
        "   "
    ) == "<empty-login-identifier>"


def test_login_decision_accepts_valid_values() -> None:
    decision = LoginProtectionDecision(
        locked=True,
        failures=5,
        retry_after_seconds=300,
    )

    assert decision.locked is True
    assert decision.failures == 5
    assert decision.retry_after_seconds == 300
