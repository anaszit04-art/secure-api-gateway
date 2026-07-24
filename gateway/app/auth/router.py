from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
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
def register_user(
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
        return service.register_user(
            registration
        )
    except UserAlreadyExistsError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username is already registered.",
        ) from exc


@router.post(
    "/token",
    response_model=TokenResponse,
)
def issue_access_token(
    form_data: Annotated[
        OAuth2PasswordRequestForm,
        Depends(),
    ],
    service: Annotated[
        AuthenticationService,
        Depends(get_authentication_service),
    ],
) -> TokenResponse:
    """
    Authenticate credentials and issue a Bearer token.
    """
    try:
        access_token = (
            service.authenticate_and_create_token(
                username=form_data.username,
                password=form_data.password,
            )
        )
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=INVALID_CREDENTIALS_MESSAGE,
            headers={
                "WWW-Authenticate": "Bearer",
            },
        ) from exc

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
