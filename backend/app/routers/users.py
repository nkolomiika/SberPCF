from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import enforce_csrf, get_client_ip, get_current_user, require_admin
from app.models import User
from app.pagination import PageParams, to_paginated_response
from app.schemas import PasswordResetRequest, UserCreate, UserOut, UserUpdate
from app.services import UserService

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserOut)
async def me(current_user: User = Depends(get_current_user)) -> User:
    """Возвращает профиль текущего пользователя."""
    return current_user


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


@router.patch("/{user_id}/password", status_code=status.HTTP_204_NO_CONTENT)
async def reset_password(
    user_id: UUID,
    payload: PasswordResetRequest,
    request: Request,
    _: None = Depends(enforce_csrf),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Сбрасывает пароль пользователя."""
    await UserService(db).reset_password(user_id, payload.new_password, admin.id, get_client_ip(request))
