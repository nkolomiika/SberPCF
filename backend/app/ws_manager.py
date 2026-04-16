from collections import defaultdict
from uuid import UUID

from fastapi import WebSocket


class ConnectionManager:
    """Менеджер WebSocket-подключений по комнатам проекта."""

    def __init__(self) -> None:
        self.rooms: dict[UUID, set[WebSocket]] = defaultdict(set)
        self.projects_index_sockets: set[WebSocket] = set()

    async def connect(self, project_id: UUID, websocket: WebSocket) -> None:
        """Принимает соединение и регистрирует его в комнате проекта."""
        await websocket.accept()
        self.rooms[project_id].add(websocket)

    def disconnect(self, project_id: UUID, websocket: WebSocket) -> None:
        """Удаляет соединение из комнаты проекта."""
        self.rooms[project_id].discard(websocket)
        if not self.rooms[project_id]:
            self.rooms.pop(project_id, None)

    async def connect_projects_index(self, websocket: WebSocket) -> None:
        """Подключает сокет к общему каналу списка проектов."""
        await websocket.accept()
        self.projects_index_sockets.add(websocket)

    def disconnect_projects_index(self, websocket: WebSocket) -> None:
        """Удаляет сокет из общего канала списка проектов."""
        self.projects_index_sockets.discard(websocket)

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

    async def broadcast_projects_index(self, payload: dict) -> None:
        """Рассылает событие всем открытым страницам списка проектов."""
        stale: list[WebSocket] = []
        for ws in set(self.projects_index_sockets):
            try:
                await ws.send_json(payload)
            except Exception:
                stale.append(ws)
        for ws in stale:
            self.disconnect_projects_index(ws)


ws_manager = ConnectionManager()
