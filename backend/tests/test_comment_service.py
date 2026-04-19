from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.enums import UserRole
from app.exceptions import ForbiddenError
from app.models import CommentMention, Notification
from app.services import CommentService


@pytest.mark.asyncio
async def test_admin_cannot_update_foreign_comment() -> None:
    comment = SimpleNamespace(id=uuid4(), vulnerability_id=uuid4(), user_id=uuid4())
    actor = SimpleNamespace(id=uuid4(), role=UserRole.ADMIN)
    db = MagicMock()
    db.scalar = AsyncMock(return_value=comment)
    service = CommentService(db)
    service._ensure_vuln = AsyncMock()

    with pytest.raises(ForbiddenError, match="только свой комментарий"):
        await service.update(uuid4(), comment.vulnerability_id, comment.id, "updated", actor)


@pytest.mark.asyncio
async def test_admin_cannot_delete_foreign_comment() -> None:
    comment = SimpleNamespace(id=uuid4(), vulnerability_id=uuid4(), user_id=uuid4())
    actor = SimpleNamespace(id=uuid4(), role=UserRole.ADMIN)
    db = MagicMock()
    db.scalar = AsyncMock(return_value=comment)
    service = CommentService(db)
    service._ensure_vuln = AsyncMock()

    with pytest.raises(ForbiddenError, match="только свой комментарий"):
        await service.delete(uuid4(), comment.vulnerability_id, comment.id, actor)


@pytest.mark.asyncio
async def test_update_comment_mentions_do_not_create_notifications(monkeypatch: pytest.MonkeyPatch) -> None:
    project_id = uuid4()
    vuln_id = uuid4()
    comment = SimpleNamespace(
        id=uuid4(),
        vulnerability_id=vuln_id,
        user_id=uuid4(),
        content="old",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    actor = SimpleNamespace(id=comment.user_id, role=UserRole.PENTESTER, username="author", avatar_url=None)
    mentioned_user = SimpleNamespace(id=uuid4(), username="target")
    db = MagicMock()
    db.scalar = AsyncMock(return_value=comment)
    db.execute = AsyncMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    ws_manager = SimpleNamespace(broadcast=AsyncMock(), notify_user=AsyncMock())
    monkeypatch.setattr("app.services.ws_manager", ws_manager)

    service = CommentService(db)
    service._ensure_vuln = AsyncMock()
    service._extract_mentions = AsyncMock(return_value=[mentioned_user])
    service.audit.log = AsyncMock()

    result = await service.update(project_id, vuln_id, comment.id, "updated @target", actor)

    added_models = [call.args[0] for call in db.add.call_args_list]
    assert any(isinstance(model, CommentMention) for model in added_models)
    assert not any(isinstance(model, Notification) for model in added_models)
    ws_manager.notify_user.assert_not_awaited()
    ws_manager.broadcast.assert_awaited_once()
    assert result.mentions[0].username == "target"
