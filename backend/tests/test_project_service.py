from types import SimpleNamespace
from uuid import uuid4

import pytest
from app.enums import ProjectStatus
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


@pytest.mark.asyncio
async def test_update_project_freezes_timeline_on_first_non_active_status() -> None:
    db = AsyncMock()
    service = ProjectService(db)
    project_id = uuid4()
    actor_id = uuid4()
    project = SimpleNamespace(
        id=project_id,
        start_date=None,
        end_date=None,
        folder="",
        status=ProjectStatus.ACTIVE,
        timeline_frozen_at=None,
    )
    service.get_project = AsyncMock(return_value=project)  # type: ignore[method-assign]
    service.audit.log = AsyncMock()  # type: ignore[method-assign]

    updated = await service.update_project(
        project_id=project_id,
        payload={"status": ProjectStatus.HANDOVER_TO_DEVELOPMENT},
        actor_id=actor_id,
        ip_address="127.0.0.1",
    )

    assert updated.status == ProjectStatus.HANDOVER_TO_DEVELOPMENT
    assert updated.timeline_frozen_at is not None
    db.commit.assert_awaited()


@pytest.mark.asyncio
async def test_update_project_keeps_existing_frozen_timestamp_for_non_active_transitions() -> None:
    db = AsyncMock()
    service = ProjectService(db)
    project_id = uuid4()
    actor_id = uuid4()
    frozen_at = object()
    project = SimpleNamespace(
        id=project_id,
        start_date=None,
        end_date=None,
        folder="",
        status=ProjectStatus.HANDOVER_TO_DEVELOPMENT,
        timeline_frozen_at=frozen_at,
    )
    service.get_project = AsyncMock(return_value=project)  # type: ignore[method-assign]
    service.audit.log = AsyncMock()  # type: ignore[method-assign]

    updated = await service.update_project(
        project_id=project_id,
        payload={"status": ProjectStatus.VULNERABILITY_RECHECK},
        actor_id=actor_id,
        ip_address="127.0.0.1",
    )

    assert updated.status == ProjectStatus.VULNERABILITY_RECHECK
    assert updated.timeline_frozen_at is frozen_at


@pytest.mark.asyncio
async def test_update_project_unfreezes_timeline_when_reactivated() -> None:
    db = AsyncMock()
    service = ProjectService(db)
    project_id = uuid4()
    actor_id = uuid4()
    project = SimpleNamespace(
        id=project_id,
        start_date=None,
        end_date=None,
        folder="",
        status=ProjectStatus.VULNERABILITY_RECHECK,
        timeline_frozen_at=object(),
    )
    service.get_project = AsyncMock(return_value=project)  # type: ignore[method-assign]
    service.audit.log = AsyncMock()  # type: ignore[method-assign]

    updated = await service.update_project(
        project_id=project_id,
        payload={"status": ProjectStatus.ACTIVE},
        actor_id=actor_id,
        ip_address="127.0.0.1",
    )

    assert updated.status == ProjectStatus.ACTIVE
    assert updated.timeline_frozen_at is None
