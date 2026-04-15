from collections.abc import Iterable
from uuid import UUID

from fastapi import Cookie, Depends, Header, Request
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.enums import UserRole
from app.exceptions import ForbiddenError, UnauthorizedError
from app.models import Project, ProjectMember, User
from app.security import decode_token

settings = get_settings()
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def get_client_ip(request: Request) -> str | None:
    """Возвращает IP клиента из запроса."""
    if request.client:
        return request.client.host
    return None


async def enforce_csrf(request: Request, origin: str | None = Header(default=None, alias="Origin")) -> None:
    """Проверяет Origin для state-changing запросов."""
    if request.method.upper() not in MUTATING_METHODS:
        return
    if not origin:
        raise ForbiddenError("Отсутствует заголовок Origin")
    if origin not in settings.csrf_origins:
        raise ForbiddenError("Недопустимый Origin")


async def get_current_user(
    db: AsyncSession = Depends(get_db),
    access_token: str | None = Cookie(default=None),
) -> User:
    """Извлекает текущего пользователя из access cookie."""
    if not access_token:
        raise UnauthorizedError("Требуется авторизация")
    user_id = decode_token(access_token, expected_type="access")
    user = await db.scalar(select(User).where(User.id == user_id))
    if not user or not user.is_active:
        raise UnauthorizedError("Пользователь не найден или деактивирован")
    return user


async def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Проверяет, что текущий пользователь является администратором."""
    if current_user.role != UserRole.ADMIN:
        raise ForbiddenError("Недостаточно прав")
    return current_user


async def require_project_access(
    project_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Project:
    """Проверяет, что пользователь имеет доступ к проекту."""
    project = await db.scalar(select(Project).where(Project.id == project_id))
    if not project:
        raise ForbiddenError("Проект не найден или недоступен")
    if current_user.role == UserRole.ADMIN:
        return project
    membership = await db.scalar(
        select(ProjectMember).where(
            and_(
                ProjectMember.project_id == project_id,
                ProjectMember.user_id == current_user.id,
            )
        )
    )
    if not membership:
        raise ForbiddenError("Нет доступа к проекту")
    return project


def role_in(user: User, allowed: Iterable[UserRole]) -> bool:
    """Проверяет принадлежность роли пользователя допустимому набору."""
    return user.role in allowed
