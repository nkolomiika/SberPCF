from types import SimpleNamespace
from uuid import uuid4

import pytest
from app.models import UserRole
from app.services import ProjectService
from unittest.mock import AsyncMock, MagicMock


def _make_scalars_result(items: list[object]) -> MagicMock:
    result = MagicMock()
    result.all.return_value = items
    return result


@pytest.mark.asyncio
async def test_list_projects_applies_status_filter_for_admin() -> None:
    db = AsyncMock()
    project_item = SimpleNamespace(id=uuid4(), name="Project A")
    db.scalar = AsyncMock(return_value=1)
    db.scalars = AsyncMock(return_value=_make_scalars_result([project_item]))
    service = ProjectService(db)
    current_user = SimpleNamespace(id=uuid4(), role=UserRole.ADMIN)

    items, total = await service.list_projects(current_user=current_user, page=1, size=20, status="active")

    assert items == [project_item]
    assert total == 1
    statement = db.scalars.await_args.args[0]
    sql = str(statement)
    assert "projects.status" in sql
    assert "project_members" not in sql


@pytest.mark.asyncio
async def test_list_projects_limits_to_membership_for_pentester() -> None:
    db = AsyncMock()
    project_item = SimpleNamespace(id=uuid4(), name="Project B")
    db.scalar = AsyncMock(return_value=1)
    db.scalars = AsyncMock(return_value=_make_scalars_result([project_item]))
    service = ProjectService(db)
    current_user = SimpleNamespace(id=uuid4(), role=UserRole.PENTESTER)

    items, total = await service.list_projects(current_user=current_user, page=2, size=10, status=None)

    assert items == [project_item]
    assert total == 1
    statement = db.scalars.await_args.args[0]
    sql = str(statement)
    assert "JOIN project_members" in sql
    assert "project_members.user_id" in sql


@pytest.mark.asyncio
async def test_delete_project_removes_entity_and_writes_audit() -> None:
    db = AsyncMock()
    service = ProjectService(db)
    project_id = uuid4()
    actor_id = uuid4()
    project = SimpleNamespace(id=project_id)
    service.get_project = AsyncMock(return_value=project)  # type: ignore[method-assign]
    service.audit.log = AsyncMock()  # type: ignore[method-assign]

    await service.delete_project(project_id=project_id, actor_id=actor_id, ip_address="127.0.0.1")

    db.delete.assert_awaited_once_with(project)
    db.commit.assert_awaited_once()
    service.audit.log.assert_awaited_once_with(
        "DELETE",
        user_id=actor_id,
        entity_type="project",
        entity_id=project_id,
        ip_address="127.0.0.1",
    )
