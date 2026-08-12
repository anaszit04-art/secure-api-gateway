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

from gateway.app.auth.dependencies import (
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
    service: Annotated[
        AuthenticationService,
        Depends(get_authentication_service),
    ],
) -> UserPublic:
    """
    Register a new local user.
    """

    try:
        return await service.register_user(
            registration
        )
    except UserAlreadyExistsError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Username is already registered."
            ),
        ) from exc


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
) -> TokenResponse:
    """
    Authenticate credentials and issue a Bearer token.

    Protection is applied in this order:

    1. rate limit the direct client address;
    2. check the temporary account lock;
    3. authenticate the submitted credentials;
    4. record failures or clear state after success.
    """

    del request

    try:
        lock_decision = (
            await login_protection.check_lock(
                identifier=form_data.username,
                policy=account_policy,
            )
        )
    except LoginProtectionBackendError as exc:
        raise (
            authentication_protection_unavailable()
        ) from exc

    if lock_decision.locked:
        raise too_many_authentication_attempts(
            retry_after_seconds=(
                lock_decision.retry_after_seconds
            )
        )

    try:
        access_token = (
            await service.authenticate_and_create_token(
                username=form_data.username,
                password=form_data.password,
            )
        )
    except AuthenticationError as exc:
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
            raise (
                authentication_protection_unavailable()
            ) from backend_exc

        if failure_decision.locked:
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

    return TokenResponse(
        access_token=access_token,
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
