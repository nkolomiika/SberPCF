from collections import defaultdict
from uuid import UUID

from fastapi import WebSocket


class ConnectionManager:
    """Менеджер WebSocket-подключений по комнатам проекта."""

    def __init__(self) -> None:
        self.rooms: dict[UUID, set[WebSocket]] = defaultdict(set)

    async def connect(self, project_id: UUID, websocket: WebSocket) -> None:
        """Принимает соединение и регистрирует его в комнате проекта."""
        await websocket.accept()
        self.rooms[project_id].add(websocket)

    def disconnect(self, project_id: UUID, websocket: WebSocket) -> None:
        """Удаляет соединение из комнаты проекта."""
        self.rooms[project_id].discard(websocket)
        if not self.rooms[project_id]:
            self.rooms.pop(project_id, None)

    async def broadcast(self, project_id: UUID, payload: dict) -> None:
        """Рассылает событие всем активным подключениям комнаты."""
        stale: list[WebSocket] = []
        for ws in self.rooms.get(project_id, set()):
            try:
                await ws.send_json(payload)
            except Exception:
                stale.append(ws)

        for ws in stale:
            self.disconnect(project_id, ws)

    async def notify_user(self, user_id: UUID, payload: dict) -> None:
        """Рассылает персональное уведомление по всем комнатам пользователя."""
        for room_id, sockets in list(self.rooms.items()):
            stale: list[WebSocket] = []
            for ws in sockets:
                if getattr(ws.state, "user_id", None) == user_id:
                    try:
                        await ws.send_json(payload)
                    except Exception:
                        stale.append(ws)
            for ws in stale:
                self.disconnect(room_id, ws)


ws_manager = ConnectionManager()
