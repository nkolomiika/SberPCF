from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import enforce_csrf, get_client_ip, get_current_user, require_admin, require_project_access
from app.models import User
from app.pagination import PageParams, to_paginated_response
from app.schemas import (
    ProjectCreate,
    ProjectMemberCreate,
    ProjectMemberOut,
    ProjectOut,
    ProjectUpdate,
)
from app.services import ProjectService

router = APIRouter(prefix="/projects", tags=["projects"])


@router.get("", response_model=dict)
async def list_projects(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=200),
    status_filter: str | None = Query(None, alias="status"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Возвращает список проектов с учётом прав доступа."""
    items, total = await ProjectService(db).list_projects(current_user, page, size, status_filter)
    return to_paginated_response([ProjectOut.model_validate(it) for it in items], total, PageParams(page=page, size=size)).model_dump()


@router.post("", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
async def create_project(
    payload: ProjectCreate,
    request: Request,
    _: None = Depends(enforce_csrf),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> ProjectOut:
    """Создаёт проект."""
    project = await ProjectService(db).create_project(payload.model_dump(), admin.id, get_client_ip(request))
    return ProjectOut.model_validate(project)


@router.get("/{project_id}", response_model=ProjectOut)
async def get_project(
    project_id: UUID,
    _project = Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> ProjectOut:
    """Возвращает проект по ID."""
    project = await ProjectService(db).get_project(project_id)
    return ProjectOut.model_validate(project)


@router.put("/{project_id}", response_model=ProjectOut)
async def update_project(
    project_id: UUID,
    payload: ProjectUpdate,
    request: Request,
    _: None = Depends(enforce_csrf),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> ProjectOut:
    """Обновляет проект."""
    project = await ProjectService(db).update_project(project_id, payload.model_dump(exclude_unset=True), admin.id, get_client_ip(request))
    return ProjectOut.model_validate(project)


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(
    project_id: UUID,
    request: Request,
    _: None = Depends(enforce_csrf),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Удаляет проект."""
    await ProjectService(db).delete_project(project_id, admin.id, get_client_ip(request))


@router.get("/{project_id}/members", response_model=list[ProjectMemberOut])
async def list_members(
    project_id: UUID,
    _project = Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> list[ProjectMemberOut]:
    """Возвращает участников проекта."""
    items = await ProjectService(db).list_members(project_id)
    return [ProjectMemberOut.model_validate(row) for row in items]


@router.post("/{project_id}/members", status_code=status.HTTP_201_CREATED)
async def add_member(
    project_id: UUID,
    payload: ProjectMemberCreate,
    request: Request,
    _: None = Depends(enforce_csrf),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Добавляет участника в проект."""
    return await ProjectService(db).add_member(project_id, payload.user_id, admin.id, get_client_ip(request))


@router.delete("/{project_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(
    project_id: UUID,
    user_id: UUID,
    request: Request,
    _: None = Depends(enforce_csrf),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Удаляет участника из проекта."""
    await ProjectService(db).remove_member(project_id, user_id, admin.id, get_client_ip(request))
