from uuid import UUID

from fastapi import APIRouter, Depends, File as FastAPIFile, Query, Request, UploadFile, status
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.dependencies import enforce_csrf, get_client_ip, get_current_user, require_admin
from app.models import User
from app.pagination import PageParams, to_paginated_response
from app.schemas import OwnPasswordChangeRequest, PasswordResetOut, UserCreate, UserOut, UserProfileUpdate, UserUpdate
from app.services import UserService

router = APIRouter(prefix="/users", tags=["users"])
settings = get_settings()


@router.get("/me", response_model=UserOut)
async def me(current_user: User = Depends(get_current_user)) -> User:
    """Возвращает профиль текущего пользователя."""
    return current_user


@router.get("/me/profile", response_model=UserOut)
async def my_profile(current_user: User = Depends(get_current_user)) -> User:
    """Возвращает расширенный профиль текущего пользователя."""
    return current_user


@router.patch("/me", response_model=UserOut)
async def update_my_profile(
    payload: UserProfileUpdate,
    request: Request,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    """Обновляет профиль текущего пользователя."""
    user = await UserService(db).update_own_profile(current_user.id, payload.model_dump(exclude_unset=True), get_client_ip(request))
    return UserOut.model_validate(user)


@router.patch("/me/password", response_model=UserOut)
async def change_my_password(
    payload: OwnPasswordChangeRequest,
    request: Request,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    """Меняет пароль текущего пользователя."""
    user = await UserService(db).change_own_password(
        current_user.id,
        current_password=payload.current_password,
        new_password=payload.new_password,
        ip_address=get_client_ip(request),
    )
    return UserOut.model_validate(user)


@router.post("/me/avatar", response_model=UserOut)
async def upload_my_avatar(
    request: Request,
    avatar: UploadFile = FastAPIFile(...),
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    """Загружает новый аватар текущего пользователя."""
    user = await UserService(db).upload_avatar(current_user.id, avatar, get_client_ip(request))
    return UserOut.model_validate(user)


@router.get("", response_model=dict)
async def list_users(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=200),
    _admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Возвращает список пользователей для администратора."""
    items, total = await UserService(db).list_users(page, size)
    return to_paginated_response([UserOut.model_validate(it) for it in items], total, PageParams(page=page, size=size)).model_dump()


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserCreate,
    request: Request,
    _: None = Depends(enforce_csrf),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    """Создаёт нового пользователя."""
    user = await UserService(db).create_user(payload.model_dump(), admin.id, get_client_ip(request))
    return UserOut.model_validate(user)


@router.get("/{user_id}", response_model=UserOut)
async def get_user(
    user_id: UUID,
    _admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    """Возвращает пользователя по ID."""
    user = await UserService(db).get_user(user_id)
    return UserOut.model_validate(user)


@router.get("/{user_id}/avatar")
async def get_user_avatar(
    user_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Возвращает аватар пользователя."""
    service = UserService(db)
    service.ensure_can_view_avatar(current_user, user_id)
    user, content = await service.download_avatar(user_id)
    return Response(content=content, media_type=user.avatar_content_type or "application/octet-stream")


@router.put("/{user_id}", response_model=UserOut)
async def update_user(
    user_id: UUID,
    payload: UserUpdate,
    request: Request,
    _: None = Depends(enforce_csrf),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    """Обновляет пользователя."""
    user = await UserService(db).update_user(user_id, payload.model_dump(exclude_unset=True), admin.id, get_client_ip(request))
    return UserOut.model_validate(user)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: UUID,
    request: Request,
    _: None = Depends(enforce_csrf),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Удаляет пользователя."""
    await UserService(db).delete_user(user_id, admin.id, get_client_ip(request))


@router.patch("/{user_id}/password", response_model=PasswordResetOut, status_code=status.HTTP_200_OK)
async def reset_password(
    user_id: UUID,
    request: Request,
    _: None = Depends(enforce_csrf),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> PasswordResetOut:
    """Сбрасывает пароль пользователя."""
    user = await UserService(db).reset_password(user_id, admin.id, get_client_ip(request))
    preview_url = settings.mail_preview_url if settings.smtp_host == "mailpit" else None
    return PasswordResetOut(email_sent_to=user.email, must_change_password=True, mail_preview_url=preview_url)
