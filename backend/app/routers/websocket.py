from uuid import UUID

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from jose import JWTError, jwt
from sqlalchemy import and_, select

from app.config import get_settings
from app.database import SessionLocal
from app.enums import UserRole
from app.models import ProjectMember, User
from app.ws_manager import ws_manager

router = APIRouter(tags=["websocket"])
settings = get_settings()


@router.websocket("/ws/projects/{project_id}")
async def project_ws(websocket: WebSocket, project_id: UUID) -> None:
    """WebSocket-канал проекта с авторизацией по access cookie."""
    access_token = websocket.cookies.get("access_token")
    if not access_token:
        await websocket.close(code=4401)
        return
    try:
        payload = jwt.decode(access_token, settings.jwt_secret_key, algorithms=["HS256"])
        if payload.get("type") != "access":
            await websocket.close(code=4401)
            return
        user_id = payload.get("sub")
        if not user_id:
            await websocket.close(code=4401)
            return
    except JWTError:
        await websocket.close(code=4401)
        return

    async with SessionLocal() as db:
        user = await db.scalar(select(User).where(User.id == user_id))
        if not user or not user.is_active:
            await websocket.close(code=4403)
            return
        if user.role != UserRole.ADMIN:
            membership = await db.scalar(
                select(ProjectMember).where(and_(ProjectMember.project_id == project_id, ProjectMember.user_id == user.id))
            )
            if not membership:
                await websocket.close(code=4403)
                return

    setattr(websocket.state, "user_id", user_id)
    await ws_manager.connect(project_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(project_id, websocket)
