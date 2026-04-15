from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import require_admin
from app.models import AuditLog, User
from app.pagination import PageParams, to_paginated_response
from app.schemas import AuditLogOut

router = APIRouter(prefix="/audit-logs", tags=["audit"])


@router.get("", response_model=dict)
async def list_audit_logs(
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    user_id: UUID | None = None,
    action: str | None = None,
    entity_type: str | None = None,
    _admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Возвращает журнал действий с фильтрацией."""
    query = select(AuditLog)
    conditions = []
    if user_id:
        conditions.append(AuditLog.user_id == user_id)
    if action:
        conditions.append(AuditLog.action == action)
    if entity_type:
        conditions.append(AuditLog.entity_type == entity_type)
    if conditions:
        query = query.where(and_(*conditions))
    total = await db.scalar(select(func.count()).select_from(query.subquery()))
    items = (
        await db.scalars(query.order_by(AuditLog.created_at.desc()).offset((page - 1) * size).limit(size))
    ).all()
    total_count = total if isinstance(total, int) else 0
    return to_paginated_response([AuditLogOut.model_validate(item) for item in items], total_count, PageParams(page=page, size=size)).model_dump()
