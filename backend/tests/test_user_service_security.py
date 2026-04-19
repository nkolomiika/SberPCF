from types import SimpleNamespace
from uuid import uuid4

import pytest
from unittest.mock import AsyncMock

from app.enums import UserRole
from app.exceptions import ForbiddenError, ValidationError
from app.services import UserService


@pytest.mark.asyncio
async def test_force_change_password_rejects_when_flag_not_set() -> None:
    db = AsyncMock()
    service = UserService(db)
    user = SimpleNamespace(id=uuid4(), must_change_password=False)
    service.get_user = AsyncMock(return_value=user)  # type: ignore[method-assign]

    with pytest.raises(ForbiddenError, match="не требуется"):
        await service.force_change_password(user.id, new_password="StrongPassword123!")


@pytest.mark.asyncio
async def test_admin_cannot_change_other_user_email() -> None:
    db = AsyncMock()
    service = UserService(db)
    user = SimpleNamespace(id=uuid4(), username="alice", email="alice@example.com")
    service.get_user = AsyncMock(return_value=user)  # type: ignore[method-assign]

    with pytest.raises(ValidationError, match="не может менять email"):
        await service.update_user(user.id, {"email": "new@example.com"}, actor_id=uuid4())


def test_avatar_download_forbidden_for_other_non_admin_users() -> None:
    requester = SimpleNamespace(id=uuid4(), role=UserRole.PENTESTER)
    target_user_id = uuid4()

    with pytest.raises(ForbiddenError, match="чужого аватара"):
        UserService.ensure_can_view_avatar(requester, target_user_id)
