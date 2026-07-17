from fastapi import APIRouter, Cookie, Depends, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.dependencies import enforce_csrf, get_client_ip, get_current_user
from app.models import User
from app.schemas import LoginRequest, LoginResponse, RefreshResponse, UserOut
from app.services import AuthService

router = APIRouter(prefix="/auth", tags=["auth"])
settings = get_settings()


def _set_auth_cookies(response: Response, access_token: str, refresh_token: str) -> None:
    """Устанавливает access и refresh cookie в ответ."""
    response.set_cookie(
        "access_token",
        access_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=settings.jwt_access_token_expire_minutes * 60,
        path="/",
    )
    response.set_cookie(
        "refresh_token",
        refresh_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=settings.jwt_refresh_token_expire_days * 24 * 60 * 60,
        path="/api/v1/auth/refresh",
    )


def _clear_auth_cookies(response: Response) -> None:
    """Очищает auth-cookie в браузере."""
    response.set_cookie("access_token", "", httponly=True, secure=settings.cookie_secure, samesite=settings.cookie_samesite, max_age=0, path="/")
    response.set_cookie(
        "refresh_token",
        "",
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=0,
        path="/api/v1/auth/refresh",
    )


@router.post("/login", response_model=LoginResponse, status_code=status.HTTP_200_OK)
async def login(
    payload: LoginRequest,
    response: Response,
    request: Request,
    _: None = Depends(enforce_csrf),
    db: AsyncSession = Depends(get_db),
) -> LoginResponse:
    """Выполняет логин и устанавливает cookie-токены."""
    service = AuthService(db)
    access_token, refresh_token, user = await service.login(payload.username, payload.password, get_client_ip(request))
    _set_auth_cookies(response, access_token, refresh_token)
    response.status_code = status.HTTP_200_OK
    return LoginResponse(id=user.id, username=user.username, role=user.role)


@router.post("/refresh", response_model=RefreshResponse, status_code=status.HTTP_200_OK)
async def refresh(
    response: Response,
    request: Request,
    _: None = Depends(enforce_csrf),
    refresh_token: str | None = Cookie(default=None),
    db: AsyncSession = Depends(get_db),
) -> RefreshResponse:
    """Обновляет пару cookie-токенов с ротацией refresh-токена."""
    service = AuthService(db)
    new_access, new_refresh = await service.refresh(refresh_token, get_client_ip(request))
    _set_auth_cookies(response, new_access, new_refresh)
    response.status_code = status.HTTP_200_OK
    return RefreshResponse(ok=True)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    response: Response,
    request: Request,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Отзывает токены и очищает cookie в браузере."""
    await AuthService(db).logout(current_user.id, get_client_ip(request))
    _clear_auth_cookies(response)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response
