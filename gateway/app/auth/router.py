from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.security import OAuth2PasswordRequestForm

from gateway.app.audit.dependencies import (
    AuditServiceDependency,
    record_request_security_event,
)
from gateway.app.audit.models import (
    AuditEventType,
    AuditOutcome,
)
from gateway.app.auth.dependencies import (
    authentication_database_unavailable,
    get_authentication_service,
    get_current_user,
)
from gateway.app.auth.models import (
    TokenResponse,
    UserPublic,
    UserRegistration,
)
from gateway.app.auth.repository import (
    UserAlreadyExistsError,
    UserRepositoryBackendError,
)
from gateway.app.auth.service import (
    INVALID_CREDENTIALS_MESSAGE,
    AuthenticationError,
    AuthenticationService,
)
from gateway.app.rate_limit.dependencies import (
    build_rate_limit_headers,
)
from gateway.app.rate_limit.login import (
    LoginProtectionBackendError,
    LoginProtectionPolicy,
    RedisLoginProtection,
)
from gateway.app.rate_limit.login_dependencies import (
    authentication_protection_unavailable,
    enforce_login_ip_rate_limit,
    get_account_login_policy,
    get_login_protection,
    too_many_authentication_attempts,
)
from gateway.app.rate_limit.models import (
    RateLimitDecision,
)


router = APIRouter(
    prefix="/auth",
    tags=[
        "authentication",
    ],
)


@router.post(
    "/register",
    response_model=UserPublic,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    registration: UserRegistration,
    request: Request,
    service: Annotated[
        AuthenticationService,
        Depends(get_authentication_service),
    ],
    audit_service: AuditServiceDependency,
) -> UserPublic:
    """
    Register a new local user.
    """

    try:
        user = await service.register_user(
            registration
        )

    except UserAlreadyExistsError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Username is already registered."
            ),
        ) from exc

    except UserRepositoryBackendError as exc:
        await record_request_security_event(
            request=request,
            audit_service=audit_service,
            event_type=(
                AuditEventType
                .AUTHENTICATION_BACKEND_UNAVAILABLE
            ),
            outcome=AuditOutcome.UNAVAILABLE,
            method=request.method,
            status_code=503,
            reason_code=(
                "registration_repository_unavailable"
            ),
        )

        raise (
            authentication_database_unavailable()
        ) from exc

    await record_request_security_event(
        request=request,
        audit_service=audit_service,
        event_type=(
            AuditEventType.USER_REGISTERED
        ),
        outcome=AuditOutcome.SUCCESS,
        target_user_id=user.id,
        method=request.method,
        status_code=201,
        reason_code="registration_completed",
    )

    return user


@router.post(
    "/token",
    response_model=TokenResponse,
)
async def issue_access_token(
    request: Request,
    response: Response,
    form_data: Annotated[
        OAuth2PasswordRequestForm,
        Depends(),
    ],
    service: Annotated[
        AuthenticationService,
        Depends(get_authentication_service),
    ],
    ip_decision: Annotated[
        RateLimitDecision,
        Depends(enforce_login_ip_rate_limit),
    ],
    login_protection: Annotated[
        RedisLoginProtection,
        Depends(get_login_protection),
    ],
    account_policy: Annotated[
        LoginProtectionPolicy,
        Depends(get_account_login_policy),
    ],
    audit_service: AuditServiceDependency,
) -> TokenResponse:
    """
    Authenticate credentials and issue a Bearer token.

    Protection is applied in this order:

    1. rate limit the direct client address;
    2. check the temporary account lock;
    3. authenticate the submitted credentials;
    4. record failures or clear state after success.
    """

    try:
        lock_decision = (
            await login_protection.check_lock(
                identifier=form_data.username,
                policy=account_policy,
            )
        )

    except LoginProtectionBackendError as exc:
        await record_request_security_event(
            request=request,
            audit_service=audit_service,
            event_type=(
                AuditEventType
                .RATE_LIMIT_BACKEND_UNAVAILABLE
            ),
            outcome=AuditOutcome.UNAVAILABLE,
            method=request.method,
            status_code=503,
            reason_code=(
                "login_lock_check_unavailable"
            ),
        )

        raise (
            authentication_protection_unavailable()
        ) from exc

    if lock_decision.locked:
        await record_request_security_event(
            request=request,
            audit_service=audit_service,
            event_type=(
                AuditEventType.ACCOUNT_LOCKED
            ),
            outcome=AuditOutcome.DENIED,
            method=request.method,
            status_code=429,
            reason_code="account_already_locked",
        )

        raise too_many_authentication_attempts(
            retry_after_seconds=(
                lock_decision.retry_after_seconds
            )
        )

    try:
        authentication_result = (
            await service
            .authenticate_and_create_result(
                username=form_data.username,
                password=form_data.password,
            )
        )

    except UserRepositoryBackendError as exc:
        await record_request_security_event(
            request=request,
            audit_service=audit_service,
            event_type=(
                AuditEventType
                .AUTHENTICATION_BACKEND_UNAVAILABLE
            ),
            outcome=AuditOutcome.UNAVAILABLE,
            method=request.method,
            status_code=503,
            reason_code=(
                "authentication_repository_unavailable"
            ),
        )

        raise (
            authentication_database_unavailable()
        ) from exc

    except AuthenticationError as exc:
        await record_request_security_event(
            request=request,
            audit_service=audit_service,
            event_type=(
                AuditEventType.LOGIN_FAILED
            ),
            outcome=AuditOutcome.FAILURE,
            method=request.method,
            status_code=401,
            reason_code="invalid_credentials",
        )

        try:
            failure_decision = (
                await login_protection.record_failure(
                    identifier=(
                        form_data.username
                    ),
                    policy=account_policy,
                )
            )

        except LoginProtectionBackendError as backend_exc:
            await record_request_security_event(
                request=request,
                audit_service=audit_service,
                event_type=(
                    AuditEventType
                    .RATE_LIMIT_BACKEND_UNAVAILABLE
                ),
                outcome=AuditOutcome.UNAVAILABLE,
                method=request.method,
                status_code=503,
                reason_code=(
                    "login_failure_tracking_unavailable"
                ),
            )

            raise (
                authentication_protection_unavailable()
            ) from backend_exc

        if failure_decision.locked:
            await record_request_security_event(
                request=request,
                audit_service=audit_service,
                event_type=(
                    AuditEventType.ACCOUNT_LOCKED
                ),
                outcome=AuditOutcome.DENIED,
                method=request.method,
                status_code=429,
                reason_code=(
                    "failure_threshold_reached"
                ),
            )

            raise too_many_authentication_attempts(
                retry_after_seconds=(
                    failure_decision
                    .retry_after_seconds
                )
            ) from exc

        error_headers = {
            "WWW-Authenticate": "Bearer",
        }

        error_headers.update(
            build_rate_limit_headers(
                ip_decision
            )
        )

        raise HTTPException(
            status_code=(
                status.HTTP_401_UNAUTHORIZED
            ),
            detail=INVALID_CREDENTIALS_MESSAGE,
            headers=error_headers,
        ) from exc

    try:
        await login_protection.reset(
            identifier=form_data.username,
            policy=account_policy,
        )

    except LoginProtectionBackendError as exc:
        await record_request_security_event(
            request=request,
            audit_service=audit_service,
            event_type=(
                AuditEventType
                .RATE_LIMIT_BACKEND_UNAVAILABLE
            ),
            outcome=AuditOutcome.UNAVAILABLE,
            method=request.method,
            status_code=503,
            reason_code=(
                "login_state_reset_unavailable"
            ),
        )

        raise (
            authentication_protection_unavailable()
        ) from exc

    for header_name, header_value in (
        build_rate_limit_headers(
            ip_decision
        ).items()
    ):
        response.headers[
            header_name
        ] = header_value

    await record_request_security_event(
        request=request,
        audit_service=audit_service,
        event_type=(
            AuditEventType.LOGIN_SUCCEEDED
        ),
        outcome=AuditOutcome.SUCCESS,
        actor_user_id=(
            authentication_result.user.id
        ),
        method=request.method,
        status_code=200,
        reason_code="credentials_verified",
    )

    return TokenResponse(
        access_token=(
            authentication_result
            .access_token
        ),
    )


@router.get(
    "/me",
    response_model=UserPublic,
)
def read_current_user(
    current_user: Annotated[
        UserPublic,
        Depends(get_current_user),
    ],
) -> UserPublic:
    """
    Return the authenticated user's public profile.
    """

    return current_user
