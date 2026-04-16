from __future__ import annotations

import asyncio
import json
import re
from datetime import UTC, date, datetime, timedelta
from io import BytesIO
from uuid import UUID

import magic
from docx import Document
from fastapi import UploadFile
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from sqlalchemy import Select, and_, delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.enums import AssetType, NotificationType, UserRole
from app.exceptions import ConflictError, ForbiddenError, NotFoundError, UnauthorizedError, ValidationError
from app.models import (
    AuditLog,
    Comment,
    CommentMention,
    Endpoint,
    File,
    Host,
    Notification,
    Port,
    Project,
    ProjectFolder,
    ProjectMember,
    RefreshToken,
    Service,
    User,
    Vulnerability,
    VulnerabilityAsset,
)
from app.schemas import (
    CommentOut,
    ImportResult,
    MentionOut,
    NotificationContext,
    NotificationOut,
)
from app.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    hash_refresh_token,
    verify_password,
)
from app.storage.minio_client import MinioStorage
from app.ws_manager import ws_manager

settings = get_settings()
MENTION_RE = re.compile(r"@([a-zA-Z0-9_.-]{1,100})")
MAX_FILE_SIZE = 50 * 1024 * 1024
ALLOWED_MIME_TYPES = {
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "text/plain",
    "application/pdf",
    "application/xml",
    "application/json",
    "application/zip",
    "application/x-tar",
    "application/gzip",
}


class AuditService:
    """Сервис записи журнала действий."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def log(
        self,
        action: str,
        *,
        user_id: UUID | None = None,
        entity_type: str | None = None,
        entity_id: UUID | None = None,
        details: dict | None = None,
        ip_address: str | None = None,
    ) -> None:
        """Создаёт запись аудита."""
        self.db.add(
            AuditLog(
                user_id=user_id,
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                details=details,
                ip_address=ip_address,
            )
        )
        await self.db.commit()


class AuthService:
    """Сервис аутентификации и управления JWT-cookie."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.audit = AuditService(db)

    async def login(self, username: str, password: str, ip_address: str | None = None) -> tuple[str, str, User]:
        """Проверяет учётные данные и создаёт пару токенов."""
        user = await self.db.scalar(select(User).where(User.username == username))
        if not user or not verify_password(password, user.password_hash):
            await self.audit.log("LOGIN_FAILED", details={"username": username}, ip_address=ip_address)
            raise UnauthorizedError("Неверный логин или пароль")
        if not user.is_active:
            raise UnauthorizedError("Пользователь деактивирован")

        access_token = create_access_token(user.id)
        refresh_token = create_refresh_token(user.id)
        refresh_hash = hash_refresh_token(refresh_token)
        expires_at = datetime.now(UTC) + timedelta(days=settings.jwt_refresh_token_expire_days)
        self.db.add(RefreshToken(user_id=user.id, token_hash=refresh_hash, expires_at=expires_at))
        await self.db.commit()

        await self.audit.log("LOGIN", user_id=user.id, ip_address=ip_address)
        return access_token, refresh_token, user

    async def refresh(self, refresh_token: str | None, ip_address: str | None = None) -> str:
        """Обновляет access-токен по валидному refresh-cookie."""
        if not refresh_token:
            raise UnauthorizedError("Refresh token отсутствует")
        user_id = decode_token(refresh_token, expected_type="refresh")
        token_hash = hash_refresh_token(refresh_token)
        token_entry = await self.db.scalar(
            select(RefreshToken).where(
                and_(
                    RefreshToken.token_hash == token_hash,
                    RefreshToken.user_id == user_id,
                    RefreshToken.revoked_at.is_(None),
                    RefreshToken.expires_at > datetime.now(UTC),
                )
            )
        )
        if not token_entry:
            raise UnauthorizedError("Refresh token недействителен")
        await self.audit.log("LOGIN", user_id=user_id, details={"source": "refresh"}, ip_address=ip_address)
        return create_access_token(user_id)

    async def logout(self, user_id: UUID, ip_address: str | None = None) -> None:
        """Отзывает все активные refresh-токены пользователя."""
        await self.db.execute(
            update(RefreshToken)
            .where(and_(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None)))
            .values(revoked_at=datetime.now(UTC))
        )
        await self.db.commit()
        await self.audit.log("LOGOUT", user_id=user_id, ip_address=ip_address)


class UserService:
    """Сервис управления пользователями."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.audit = AuditService(db)

    @staticmethod
    def _normalized_admin_email() -> str:
        configured_email = settings.initial_admin_email
        if "@" in configured_email and "." in configured_email.split("@", 1)[1]:
            return configured_email
        return "admin@example.com"

    async def bootstrap_admin(self) -> None:
        """Создаёт стартового администратора при пустой таблице users."""
        normalized_email = self._normalized_admin_email()
        total_users = await self.db.scalar(select(func.count()).select_from(User))
        if total_users and total_users > 0:
            admin_user = await self.db.scalar(select(User).where(User.username == settings.initial_admin_username))
            if admin_user and ("@" not in admin_user.email or "." not in admin_user.email.split("@", 1)[1]):
                admin_user.email = normalized_email
                await self.db.commit()
            return
        admin = User(
            username=settings.initial_admin_username,
            email=normalized_email,
            password_hash=hash_password(settings.initial_admin_password),
            role=UserRole.ADMIN,
            is_active=True,
        )
        self.db.add(admin)
        await self.db.commit()

    async def list_users(self, page: int, size: int) -> tuple[list[User], int]:
        """Возвращает список пользователей с пагинацией."""
        total = await self.db.scalar(select(func.count()).select_from(User)) or 0
        items = (
            await self.db.scalars(select(User).order_by(User.created_at.desc()).offset((page - 1) * size).limit(size))
        ).all()
        return list(items), total

    async def get_user(self, user_id: UUID) -> User:
        """Возвращает пользователя по идентификатору."""
        user = await self.db.scalar(select(User).where(User.id == user_id))
        if not user:
            raise NotFoundError("Пользователь не найден")
        return user

    async def create_user(self, payload: dict, actor_id: UUID, ip_address: str | None = None) -> User:
        """Создаёт нового пользователя."""
        exists = await self.db.scalar(
            select(User).where(or_(User.username == payload["username"], User.email == payload["email"]))
        )
        if exists:
            raise ConflictError("username или email уже заняты")
        user = User(
            username=payload["username"],
            email=payload["email"],
            password_hash=hash_password(payload["password"]),
            role=payload.get("role", UserRole.PENTESTER),
            is_active=True,
        )
        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)
        await self.audit.log("CREATE", user_id=actor_id, entity_type="user", entity_id=user.id, ip_address=ip_address)
        return user

    async def update_user(self, user_id: UUID, payload: dict, actor_id: UUID, ip_address: str | None = None) -> User:
        """Обновляет данные пользователя."""
        user = await self.get_user(user_id)
        for key, value in payload.items():
            if value is not None:
                setattr(user, key, value)
        await self.db.commit()
        await self.db.refresh(user)
        await self.audit.log("UPDATE", user_id=actor_id, entity_type="user", entity_id=user.id, ip_address=ip_address)
        return user

    async def delete_user(self, user_id: UUID, actor_id: UUID, ip_address: str | None = None) -> None:
        """Удаляет пользователя."""
        if user_id == actor_id:
            raise ValidationError("Нельзя удалить самого себя")
        user = await self.get_user(user_id)
        await self.db.delete(user)
        await self.db.commit()
        await self.audit.log("DELETE", user_id=actor_id, entity_type="user", entity_id=user_id, ip_address=ip_address)

    async def reset_password(self, user_id: UUID, new_password: str, actor_id: UUID, ip_address: str | None = None) -> None:
        """Сбрасывает пароль пользователя и отзывает его refresh-токены."""
        user = await self.get_user(user_id)
        user.password_hash = hash_password(new_password)
        await self.db.execute(
            update(RefreshToken)
            .where(and_(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None)))
            .values(revoked_at=datetime.now(UTC))
        )
        await self.db.commit()
        await self.audit.log("UPDATE", user_id=actor_id, entity_type="user", entity_id=user_id, ip_address=ip_address)


class ProjectService:
    """Сервис управления проектами и участниками."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.audit = AuditService(db)

    @staticmethod
    def _validate_project_dates(start_date: date | None, end_date: date | None) -> None:
        if start_date and end_date and end_date < start_date:
            raise ValidationError("Дата окончания проекта не может быть раньше даты начала")

    @staticmethod
    def _normalize_project_folder(folder: str | None) -> str:
        normalized = (folder or "").strip()
        return normalized or "Без папки"

    @staticmethod
    def _normalize_folder_segment(name: str) -> str:
        normalized = name.strip().strip("/")
        if not normalized:
            raise ValidationError("Название папки не может быть пустым")
        if "/" in normalized:
            raise ValidationError("Название папки не должно содержать '/'")
        return normalized

    async def list_projects(self, current_user: User, page: int, size: int, status: str | None = None) -> tuple[list[Project], int]:
        """Возвращает список проектов с учётом доступа."""
        query: Select = select(Project)
        if status:
            query = query.where(Project.status == status)
        if current_user.role != UserRole.ADMIN:
            query = query.join(ProjectMember, ProjectMember.project_id == Project.id).where(ProjectMember.user_id == current_user.id)
        count_query = select(func.count()).select_from(query.subquery())
        total = await self.db.scalar(count_query) or 0
        items = (await self.db.scalars(query.order_by(Project.created_at.desc()).offset((page - 1) * size).limit(size))).all()
        return list(items), total

    async def get_project(self, project_id: UUID) -> Project:
        """Возвращает проект по ID."""
        project = await self.db.scalar(select(Project).where(Project.id == project_id))
        if not project:
            raise NotFoundError("Проект не найден")
        return project

    async def create_project(self, payload: dict, actor_id: UUID, ip_address: str | None = None) -> Project:
        """Создаёт новый проект."""
        self._validate_project_dates(payload.get("start_date"), payload.get("end_date"))
        payload["folder"] = self._normalize_project_folder(payload.get("folder"))
        project = Project(**payload, created_by=actor_id)
        self.db.add(project)
        await self.db.commit()
        await self.db.refresh(project)
        await self.audit.log("CREATE", user_id=actor_id, entity_type="project", entity_id=project.id, ip_address=ip_address)
        await ws_manager.broadcast_projects_index(
            {"event": "created", "entity": "project", "project_id": str(project.id), "data": {"id": str(project.id)}}
        )
        return project

    async def update_project(self, project_id: UUID, payload: dict, actor_id: UUID, ip_address: str | None = None) -> Project:
        """Обновляет проект."""
        project = await self.get_project(project_id)
        if "folder" in payload:
            payload["folder"] = self._normalize_project_folder(payload.get("folder"))
        next_start_date = payload.get("start_date", project.start_date)
        next_end_date = payload.get("end_date", project.end_date)
        self._validate_project_dates(next_start_date, next_end_date)
        old_status = project.status
        for key, value in payload.items():
            if value is not None:
                setattr(project, key, value)
        await self.db.commit()
        await self.db.refresh(project)
        await self.audit.log("UPDATE", user_id=actor_id, entity_type="project", entity_id=project.id, ip_address=ip_address)
        await ws_manager.broadcast(project.id, {"event": "updated", "entity": "project", "project_id": str(project.id), "data": {"id": str(project.id)}})
        await ws_manager.broadcast_projects_index(
            {"event": "updated", "entity": "project", "project_id": str(project.id), "data": {"id": str(project.id)}}
        )
        if payload.get("status") and payload["status"] != old_status:
            await self.audit.log(
                "STATUS_CHANGE",
                user_id=actor_id,
                entity_type="project",
                entity_id=project.id,
                details={"old_status": old_status.value, "new_status": project.status.value},
                ip_address=ip_address,
            )
        return project

    async def delete_project(self, project_id: UUID, actor_id: UUID, ip_address: str | None = None) -> None:
        """Удаляет проект и связанные сущности."""
        project = await self.get_project(project_id)
        await self.db.delete(project)
        await self.db.commit()
        await self.audit.log("DELETE", user_id=actor_id, entity_type="project", entity_id=project_id, ip_address=ip_address)
        await ws_manager.broadcast(project_id, {"event": "deleted", "entity": "project", "project_id": str(project_id), "data": {"id": str(project_id)}})
        await ws_manager.broadcast_projects_index(
            {"event": "deleted", "entity": "project", "project_id": str(project_id), "data": {"id": str(project_id)}}
        )

    async def list_members(self, project_id: UUID) -> list[dict]:
        """Возвращает список участников проекта."""
        rows = (
            await self.db.execute(
                select(ProjectMember, User)
                .join(User, User.id == ProjectMember.user_id)
                .where(ProjectMember.project_id == project_id)
                .order_by(ProjectMember.added_at.desc())
            )
        ).all()
        return [
            {
                "user_id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role,
                "added_at": member.added_at,
            }
            for member, user in rows
        ]

    async def add_member(self, project_id: UUID, user_id: UUID, actor_id: UUID, ip_address: str | None = None) -> dict:
        """Добавляет пользователя в участники проекта."""
        await self.get_project(project_id)
        user = await self.db.scalar(select(User).where(User.id == user_id))
        if not user:
            raise NotFoundError("Пользователь не найден")
        exists = await self.db.scalar(
            select(ProjectMember).where(and_(ProjectMember.project_id == project_id, ProjectMember.user_id == user_id))
        )
        if exists:
            raise ConflictError("Пользователь уже участник проекта")
        member = ProjectMember(project_id=project_id, user_id=user_id)
        self.db.add(member)
        await self.db.commit()
        await self.db.refresh(member)
        await self.audit.log("CREATE", user_id=actor_id, entity_type="project_member", entity_id=member.id, ip_address=ip_address)
        return {"user_id": user.id, "username": user.username, "added_at": member.added_at}

    async def remove_member(self, project_id: UUID, user_id: UUID, actor_id: UUID, ip_address: str | None = None) -> None:
        """Удаляет пользователя из участников проекта."""
        member = await self.db.scalar(
            select(ProjectMember).where(and_(ProjectMember.project_id == project_id, ProjectMember.user_id == user_id))
        )
        if not member:
            raise NotFoundError("Участник не найден")
        await self.db.delete(member)
        await self.db.commit()
        await self.audit.log("DELETE", user_id=actor_id, entity_type="project_member", entity_id=member.id, ip_address=ip_address)

    async def list_folders(self) -> list[ProjectFolder]:
        """Возвращает список папок проектов."""
        rows = await self.db.scalars(select(ProjectFolder).order_by(ProjectFolder.path.asc()))
        return list(rows.all())

    async def create_folder(self, name: str, parent_id: UUID | None, actor_id: UUID, ip_address: str | None = None) -> ProjectFolder:
        """Создаёт новую папку проекта (в т.ч. вложенную)."""
        segment = self._normalize_folder_segment(name)
        parent: ProjectFolder | None = None
        if parent_id:
            parent = await self.db.scalar(select(ProjectFolder).where(ProjectFolder.id == parent_id))
            if not parent:
                raise NotFoundError("Родительская папка не найдена")
        path = f"{parent.path}/{segment}" if parent else segment
        duplicate = await self.db.scalar(select(ProjectFolder).where(ProjectFolder.path == path))
        if duplicate:
            raise ConflictError("Папка с таким путём уже существует")
        folder = ProjectFolder(name=segment, path=path, parent_id=parent_id, created_by=actor_id)
        self.db.add(folder)
        await self.db.commit()
        await self.db.refresh(folder)
        await self.audit.log("CREATE", user_id=actor_id, entity_type="project_folder", entity_id=folder.id, ip_address=ip_address)
        await ws_manager.broadcast_projects_index(
            {"event": "created", "entity": "project_folder", "data": {"id": str(folder.id), "path": folder.path}}
        )
        return folder

    async def move_folder(
        self, folder_id: UUID, new_parent_id: UUID | None, actor_id: UUID, ip_address: str | None = None
    ) -> ProjectFolder:
        """Перемещает папку и пересчитывает пути дочерних папок и проектов."""
        folder = await self.db.scalar(select(ProjectFolder).where(ProjectFolder.id == folder_id))
        if not folder:
            raise NotFoundError("Папка не найдена")
        if new_parent_id == folder.id:
            raise ValidationError("Нельзя переместить папку в саму себя")

        new_parent: ProjectFolder | None = None
        if new_parent_id:
            new_parent = await self.db.scalar(select(ProjectFolder).where(ProjectFolder.id == new_parent_id))
            if not new_parent:
                raise NotFoundError("Родительская папка не найдена")
            if new_parent.path == folder.path or new_parent.path.startswith(f"{folder.path}/"):
                raise ValidationError("Нельзя переместить папку в её дочернюю папку")

        duplicate = await self.db.scalar(
            select(ProjectFolder).where(
                and_(
                    ProjectFolder.id != folder.id,
                    ProjectFolder.parent_id == new_parent_id,
                    ProjectFolder.name == folder.name,
                )
            )
        )
        if duplicate:
            raise ConflictError("В целевой папке уже есть папка с таким именем")

        old_path = folder.path
        new_path = f"{new_parent.path}/{folder.name}" if new_parent else folder.name
        if new_path == old_path and folder.parent_id == new_parent_id:
            return folder

        subtree_folders = (
            await self.db.scalars(
                select(ProjectFolder).where(or_(ProjectFolder.path == old_path, ProjectFolder.path.like(f"{old_path}/%")))
            )
        ).all()
        subtree_projects = (
            await self.db.scalars(select(Project).where(or_(Project.folder == old_path, Project.folder.like(f"{old_path}/%"))))
        ).all()

        for subtree_folder in subtree_folders:
            suffix = subtree_folder.path[len(old_path) :]
            subtree_folder.path = f"{new_path}{suffix}"
            if subtree_folder.id == folder.id:
                subtree_folder.parent_id = new_parent_id

        for project in subtree_projects:
            suffix = project.folder[len(old_path) :]
            project.folder = f"{new_path}{suffix}"

        await self.db.commit()
        await self.db.refresh(folder)
        await self.audit.log(
            "UPDATE",
            user_id=actor_id,
            entity_type="project_folder",
            entity_id=folder.id,
            details={"from": old_path, "to": new_path},
            ip_address=ip_address,
        )
        await ws_manager.broadcast_projects_index(
            {
                "event": "updated",
                "entity": "project_folder",
                "data": {"id": str(folder.id), "from": old_path, "to": new_path},
            }
        )
        return folder


class AssetService:
    """Сервис CRUD для host/port/service/endpoint."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.audit = AuditService(db)

    @staticmethod
    def _apply_raw_request_payload(payload: dict) -> dict:
        request_raw = payload.get("request_raw")
        if not request_raw:
            return payload
        lines = [line.strip() for line in str(request_raw).replace("\r", "").split("\n") if line.strip()]
        if not lines:
            raise ValidationError("request_raw пустой")
        request_line = lines[0].split()
        if len(request_line) < 3:
            raise ValidationError("request_raw должен содержать request line вида 'METHOD /path HTTP/1.1'")
        method, path_value, http_part = request_line[0].upper(), request_line[1], request_line[2].upper()
        allowed_methods = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
        if method not in allowed_methods:
            raise ValidationError("request_raw содержит неподдерживаемый HTTP-метод")
        if not http_part.startswith("HTTP/"):
            raise ValidationError("request_raw должен содержать HTTP-версию в request line")
        payload["method"] = method
        payload["path"] = path_value
        if not payload.get("description"):
            payload["description"] = str(request_raw).strip()
        payload.pop("request_raw", None)
        return payload

    async def _get_host(self, project_id: UUID, host_id: UUID) -> Host:
        host = await self.db.scalar(select(Host).where(and_(Host.id == host_id, Host.project_id == project_id)))
        if not host:
            raise NotFoundError("Хост не найден")
        return host

    async def _get_port(self, host_id: UUID, port_id: UUID) -> Port:
        port = await self.db.scalar(select(Port).where(and_(Port.id == port_id, Port.host_id == host_id)))
        if not port:
            raise NotFoundError("Порт не найден")
        return port

    async def list_hosts(self, project_id: UUID, page: int, size: int, status: str | None) -> tuple[list[Host], int]:
        query = select(Host).where(Host.project_id == project_id)
        if status:
            query = query.where(Host.status == status)
        total = await self.db.scalar(select(func.count()).select_from(query.subquery())) or 0
        items = (await self.db.scalars(query.order_by(Host.created_at.desc()).offset((page - 1) * size).limit(size))).all()
        return list(items), total

    async def create_host(self, project_id: UUID, payload: dict, actor_id: UUID) -> Host:
        host = Host(project_id=project_id, **payload)
        self.db.add(host)
        await self.db.commit()
        await self.db.refresh(host)
        await self.audit.log("CREATE", user_id=actor_id, entity_type="host", entity_id=host.id)
        await ws_manager.broadcast(project_id, {"event": "created", "entity": "host", "project_id": str(project_id), "data": {"id": str(host.id)}})
        return host

    async def get_host(self, project_id: UUID, host_id: UUID) -> dict:
        host = await self._get_host(project_id, host_id)
        ports = (await self.db.scalars(select(Port).where(Port.host_id == host.id))).all()
        endpoints = (await self.db.scalars(select(Endpoint).where(Endpoint.host_id == host.id))).all()
        return {
            "id": host.id,
            "project_id": host.project_id,
            "ip_address": host.ip_address,
            "hostname": host.hostname,
            "status": host.status,
            "notes": host.notes,
            "created_at": host.created_at,
            "updated_at": host.updated_at,
            "ports": [
                {
                    "id": port.id,
                    "host_id": port.host_id,
                    "port_number": port.port_number,
                    "protocol": port.protocol,
                    "state": port.state,
                    "created_at": port.created_at,
                    "updated_at": port.updated_at,
                }
                for port in ports
            ],
            "endpoints": [
                {
                    "id": endpoint.id,
                    "host_id": endpoint.host_id,
                    "path": endpoint.path,
                    "method": endpoint.method,
                    "description": endpoint.description,
                    "created_at": endpoint.created_at,
                    "updated_at": endpoint.updated_at,
                }
                for endpoint in endpoints
            ],
        }

    async def update_host(self, project_id: UUID, host_id: UUID, payload: dict, actor_id: UUID) -> Host:
        host = await self._get_host(project_id, host_id)
        for key, value in payload.items():
            if value is not None:
                setattr(host, key, value)
        await self.db.commit()
        await self.db.refresh(host)
        await self.audit.log("UPDATE", user_id=actor_id, entity_type="host", entity_id=host.id)
        await ws_manager.broadcast(project_id, {"event": "updated", "entity": "host", "project_id": str(project_id), "data": {"id": str(host.id)}})
        return host

    async def delete_host(self, project_id: UUID, host_id: UUID, actor_id: UUID) -> None:
        host = await self._get_host(project_id, host_id)
        await self.db.delete(host)
        await self.db.commit()
        await self.audit.log("DELETE", user_id=actor_id, entity_type="host", entity_id=host.id)
        await ws_manager.broadcast(project_id, {"event": "deleted", "entity": "host", "project_id": str(project_id), "data": {"id": str(host.id)}})

    async def list_ports(self, host_id: UUID) -> list[Port]:
        return list((await self.db.scalars(select(Port).where(Port.host_id == host_id).order_by(Port.port_number))).all())

    async def create_port(self, project_id: UUID, host_id: UUID, payload: dict, actor_id: UUID) -> Port:
        await self._get_host(project_id, host_id)
        duplicate = await self.db.scalar(
            select(Port).where(
                and_(
                    Port.host_id == host_id,
                    Port.port_number == payload["port_number"],
                    Port.protocol == payload["protocol"],
                )
            )
        )
        if duplicate:
            raise ConflictError("Порт с таким номером и протоколом уже существует")
        port = Port(host_id=host_id, **payload)
        self.db.add(port)
        await self.db.commit()
        await self.db.refresh(port)
        await self.audit.log("CREATE", user_id=actor_id, entity_type="port", entity_id=port.id)
        await ws_manager.broadcast(project_id, {"event": "created", "entity": "port", "project_id": str(project_id), "data": {"id": str(port.id)}})
        return port

    async def get_port(self, host_id: UUID, port_id: UUID) -> Port:
        return await self._get_port(host_id, port_id)

    async def update_port(self, project_id: UUID, host_id: UUID, port_id: UUID, payload: dict, actor_id: UUID) -> Port:
        port = await self._get_port(host_id, port_id)
        next_port_number = payload.get("port_number", port.port_number)
        next_protocol = payload.get("protocol", port.protocol)
        duplicate = await self.db.scalar(
            select(Port).where(
                and_(
                    Port.host_id == host_id,
                    Port.id != port.id,
                    Port.port_number == next_port_number,
                    Port.protocol == next_protocol,
                )
            )
        )
        if duplicate:
            raise ConflictError("Порт с таким номером и протоколом уже существует")
        for key, value in payload.items():
            if value is not None:
                setattr(port, key, value)
        await self.db.commit()
        await self.db.refresh(port)
        await self.audit.log("UPDATE", user_id=actor_id, entity_type="port", entity_id=port.id)
        await ws_manager.broadcast(project_id, {"event": "updated", "entity": "port", "project_id": str(project_id), "data": {"id": str(port.id)}})
        return port

    async def delete_port(self, project_id: UUID, host_id: UUID, port_id: UUID, actor_id: UUID) -> None:
        port = await self._get_port(host_id, port_id)
        await self.db.delete(port)
        await self.db.commit()
        await self.audit.log("DELETE", user_id=actor_id, entity_type="port", entity_id=port.id)
        await ws_manager.broadcast(project_id, {"event": "deleted", "entity": "port", "project_id": str(project_id), "data": {"id": str(port.id)}})

    async def list_services(self, port_id: UUID) -> list[Service]:
        return list((await self.db.scalars(select(Service).where(Service.port_id == port_id).order_by(Service.created_at.desc()))).all())

    async def create_service(self, project_id: UUID, host_id: UUID, port_id: UUID, payload: dict, actor_id: UUID) -> Service:
        await self._get_host(project_id, host_id)
        await self._get_port(host_id, port_id)
        service = Service(port_id=port_id, **payload)
        self.db.add(service)
        await self.db.commit()
        await self.db.refresh(service)
        await self.audit.log("CREATE", user_id=actor_id, entity_type="service", entity_id=service.id)
        await ws_manager.broadcast(project_id, {"event": "created", "entity": "service", "project_id": str(project_id), "data": {"id": str(service.id)}})
        return service

    async def update_service(
        self, project_id: UUID, host_id: UUID, port_id: UUID, service_id: UUID, payload: dict, actor_id: UUID
    ) -> Service:
        await self._get_host(project_id, host_id)
        await self._get_port(host_id, port_id)
        service = await self.db.scalar(select(Service).where(and_(Service.id == service_id, Service.port_id == port_id)))
        if not service:
            raise NotFoundError("Сервис не найден")
        for key, value in payload.items():
            if value is not None:
                setattr(service, key, value)
        await self.db.commit()
        await self.db.refresh(service)
        await self.audit.log("UPDATE", user_id=actor_id, entity_type="service", entity_id=service.id)
        await ws_manager.broadcast(project_id, {"event": "updated", "entity": "service", "project_id": str(project_id), "data": {"id": str(service.id)}})
        return service

    async def delete_service(self, project_id: UUID, port_id: UUID, service_id: UUID, actor_id: UUID) -> None:
        service = await self.db.scalar(select(Service).where(and_(Service.id == service_id, Service.port_id == port_id)))
        if not service:
            raise NotFoundError("Сервис не найден")
        await self.db.delete(service)
        await self.db.commit()
        await self.audit.log("DELETE", user_id=actor_id, entity_type="service", entity_id=service.id)
        await ws_manager.broadcast(project_id, {"event": "deleted", "entity": "service", "project_id": str(project_id), "data": {"id": str(service.id)}})

    async def list_endpoints(self, host_id: UUID) -> list[Endpoint]:
        return list((await self.db.scalars(select(Endpoint).where(Endpoint.host_id == host_id).order_by(Endpoint.created_at.desc()))).all())

    async def create_endpoint(self, project_id: UUID, host_id: UUID, payload: dict, actor_id: UUID) -> Endpoint:
        await self._get_host(project_id, host_id)
        payload = self._apply_raw_request_payload(dict(payload))
        endpoint = Endpoint(host_id=host_id, **payload)
        self.db.add(endpoint)
        await self.db.commit()
        await self.db.refresh(endpoint)
        await self.audit.log("CREATE", user_id=actor_id, entity_type="endpoint", entity_id=endpoint.id)
        await ws_manager.broadcast(project_id, {"event": "created", "entity": "endpoint", "project_id": str(project_id), "data": {"id": str(endpoint.id)}})
        return endpoint

    async def update_endpoint(self, project_id: UUID, host_id: UUID, endpoint_id: UUID, payload: dict, actor_id: UUID) -> Endpoint:
        await self._get_host(project_id, host_id)
        payload = self._apply_raw_request_payload(dict(payload))
        endpoint = await self.db.scalar(select(Endpoint).where(and_(Endpoint.id == endpoint_id, Endpoint.host_id == host_id)))
        if not endpoint:
            raise NotFoundError("Endpoint не найден")
        for key, value in payload.items():
            if value is not None:
                setattr(endpoint, key, value)
        await self.db.commit()
        await self.db.refresh(endpoint)
        await self.audit.log("UPDATE", user_id=actor_id, entity_type="endpoint", entity_id=endpoint.id)
        await ws_manager.broadcast(project_id, {"event": "updated", "entity": "endpoint", "project_id": str(project_id), "data": {"id": str(endpoint.id)}})
        return endpoint

    async def delete_endpoint(self, project_id: UUID, host_id: UUID, endpoint_id: UUID, actor_id: UUID) -> None:
        endpoint = await self.db.scalar(select(Endpoint).where(and_(Endpoint.id == endpoint_id, Endpoint.host_id == host_id)))
        if not endpoint:
            raise NotFoundError("Endpoint не найден")
        await self.db.delete(endpoint)
        await self.db.commit()
        await self.audit.log("DELETE", user_id=actor_id, entity_type="endpoint", entity_id=endpoint.id)
        await ws_manager.broadcast(project_id, {"event": "deleted", "entity": "endpoint", "project_id": str(project_id), "data": {"id": str(endpoint.id)}})


class VulnerabilityService:
    """Сервис управления уязвимостями и привязками активов."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.audit = AuditService(db)

    async def _get_vuln(self, project_id: UUID, vuln_id: UUID) -> Vulnerability:
        vuln = await self.db.scalar(select(Vulnerability).where(and_(Vulnerability.id == vuln_id, Vulnerability.project_id == project_id)))
        if not vuln:
            raise NotFoundError("Уязвимость не найдена")
        return vuln

    async def list(self, project_id: UUID, page: int, size: int, severity: str | None, status: str | None) -> tuple[list[Vulnerability], int]:
        query = select(Vulnerability).where(Vulnerability.project_id == project_id)
        if severity:
            query = query.where(Vulnerability.severity == severity)
        if status:
            query = query.where(Vulnerability.status == status)
        total = await self.db.scalar(select(func.count()).select_from(query.subquery())) or 0
        items = (await self.db.scalars(query.order_by(Vulnerability.created_at.desc()).offset((page - 1) * size).limit(size))).all()
        return list(items), total

    async def list_for_host(
        self, project_id: UUID, host_id: UUID, page: int, size: int, severity: str | None, status: str | None
    ) -> tuple[list[Vulnerability], int]:
        host_exists = await self.db.scalar(select(Host.id).where(and_(Host.id == host_id, Host.project_id == project_id)))
        if not host_exists:
            raise NotFoundError("Хост не найден")

        query = (
            select(Vulnerability)
            .join(VulnerabilityAsset, VulnerabilityAsset.vulnerability_id == Vulnerability.id)
            .where(
                and_(
                    Vulnerability.project_id == project_id,
                    VulnerabilityAsset.asset_type == AssetType.HOST,
                    VulnerabilityAsset.asset_id == host_id,
                )
            )
            .distinct()
        )
        if severity:
            query = query.where(Vulnerability.severity == severity)
        if status:
            query = query.where(Vulnerability.status == status)
        total = await self.db.scalar(select(func.count()).select_from(query.subquery())) or 0
        items = (await self.db.scalars(query.order_by(Vulnerability.created_at.desc()).offset((page - 1) * size).limit(size))).all()
        return list(items), total

    async def create(self, project_id: UUID, payload: dict, actor_id: UUID) -> Vulnerability:
        vuln = Vulnerability(project_id=project_id, created_by=actor_id, **payload)
        self.db.add(vuln)
        await self.db.commit()
        await self.db.refresh(vuln)
        await self.audit.log("CREATE", user_id=actor_id, entity_type="vulnerability", entity_id=vuln.id)
        await ws_manager.broadcast(project_id, {"event": "created", "entity": "vulnerability", "project_id": str(project_id), "data": {"id": str(vuln.id)}})
        return vuln

    async def get(self, project_id: UUID, vuln_id: UUID) -> dict:
        vuln = await self._get_vuln(project_id, vuln_id)
        links = (await self.db.scalars(select(VulnerabilityAsset).where(VulnerabilityAsset.vulnerability_id == vuln.id))).all()
        files = (await self.db.scalars(select(File).where(File.vulnerability_id == vuln.id))).all()
        comments_count = await self.db.scalar(select(func.count()).select_from(Comment).where(Comment.vulnerability_id == vuln.id)) or 0
        return {"vulnerability": vuln, "assets": list(links), "files": list(files), "comments_count": comments_count}

    async def update(self, project_id: UUID, vuln_id: UUID, payload: dict, actor_id: UUID) -> Vulnerability:
        vuln = await self._get_vuln(project_id, vuln_id)
        for key, value in payload.items():
            if value is not None:
                setattr(vuln, key, value)
        await self.db.commit()
        await self.db.refresh(vuln)
        await self.audit.log("UPDATE", user_id=actor_id, entity_type="vulnerability", entity_id=vuln.id)
        await ws_manager.broadcast(project_id, {"event": "updated", "entity": "vulnerability", "project_id": str(project_id), "data": {"id": str(vuln.id)}})
        return vuln

    async def patch_status(self, project_id: UUID, vuln_id: UUID, status: str, actor_id: UUID) -> Vulnerability:
        vuln = await self._get_vuln(project_id, vuln_id)
        old_status = vuln.status
        vuln.status = status
        await self.db.commit()
        await self.db.refresh(vuln)
        await self.audit.log(
            "STATUS_CHANGE",
            user_id=actor_id,
            entity_type="vulnerability",
            entity_id=vuln.id,
            details={"old_status": old_status.value, "new_status": vuln.status.value},
        )
        await ws_manager.broadcast(project_id, {"event": "updated", "entity": "vulnerability", "project_id": str(project_id), "data": {"id": str(vuln.id)}})
        return vuln

    async def delete(self, project_id: UUID, vuln_id: UUID, actor_id: UUID) -> None:
        vuln = await self._get_vuln(project_id, vuln_id)
        await self.db.delete(vuln)
        await self.db.commit()
        await self.audit.log("DELETE", user_id=actor_id, entity_type="vulnerability", entity_id=vuln_id)
        await ws_manager.broadcast(project_id, {"event": "deleted", "entity": "vulnerability", "project_id": str(project_id), "data": {"id": str(vuln_id)}})

    async def list_assets(self, project_id: UUID, vuln_id: UUID) -> list[VulnerabilityAsset]:
        await self._get_vuln(project_id, vuln_id)
        return list((await self.db.scalars(select(VulnerabilityAsset).where(VulnerabilityAsset.vulnerability_id == vuln_id))).all())

    async def _assert_asset_in_project(self, project_id: UUID, asset_type: AssetType, asset_id: UUID) -> None:
        if asset_type == AssetType.HOST:
            found = await self.db.scalar(select(Host.id).where(and_(Host.id == asset_id, Host.project_id == project_id)))
        elif asset_type == AssetType.PORT:
            found = await self.db.scalar(
                select(Port.id).join(Host, Port.host_id == Host.id).where(and_(Port.id == asset_id, Host.project_id == project_id))
            )
        elif asset_type == AssetType.SERVICE:
            found = await self.db.scalar(
                select(Service.id)
                .join(Port, Service.port_id == Port.id)
                .join(Host, Port.host_id == Host.id)
                .where(and_(Service.id == asset_id, Host.project_id == project_id))
            )
        else:
            found = await self.db.scalar(
                select(Endpoint.id).join(Host, Endpoint.host_id == Host.id).where(and_(Endpoint.id == asset_id, Host.project_id == project_id))
            )
        if not found:
            raise ValidationError("Актив не найден или принадлежит другому проекту")

    async def add_asset(self, project_id: UUID, vuln_id: UUID, asset_type: AssetType, asset_id: UUID, actor_id: UUID) -> VulnerabilityAsset:
        await self._get_vuln(project_id, vuln_id)
        await self._assert_asset_in_project(project_id, asset_type, asset_id)
        duplicate = await self.db.scalar(
            select(VulnerabilityAsset).where(
                and_(
                    VulnerabilityAsset.vulnerability_id == vuln_id,
                    VulnerabilityAsset.asset_type == asset_type,
                    VulnerabilityAsset.asset_id == asset_id,
                )
            )
        )
        if duplicate:
            raise ConflictError("Связь уже существует")
        link = VulnerabilityAsset(vulnerability_id=vuln_id, asset_type=asset_type, asset_id=asset_id)
        self.db.add(link)
        await self.db.commit()
        await self.db.refresh(link)
        await self.audit.log("CREATE", user_id=actor_id, entity_type="vulnerability_asset", entity_id=link.id)
        return link

    async def delete_asset(self, project_id: UUID, vuln_id: UUID, link_id: UUID, actor_id: UUID) -> None:
        await self._get_vuln(project_id, vuln_id)
        link = await self.db.scalar(
            select(VulnerabilityAsset).where(and_(VulnerabilityAsset.id == link_id, VulnerabilityAsset.vulnerability_id == vuln_id))
        )
        if not link:
            raise NotFoundError("Связь не найдена")
        await self.db.delete(link)
        await self.db.commit()
        await self.audit.log("DELETE", user_id=actor_id, entity_type="vulnerability_asset", entity_id=link_id)


class FileService:
    """Сервис загрузки и выдачи файлов уязвимостей."""

    def __init__(self, db: AsyncSession, storage: MinioStorage | None = None) -> None:
        self.db = db
        self.audit = AuditService(db)
        self.storage = storage or MinioStorage()
        self.storage.ensure_bucket()

    async def _ensure_vuln(self, project_id: UUID, vuln_id: UUID) -> Vulnerability:
        vuln = await self.db.scalar(select(Vulnerability).where(and_(Vulnerability.id == vuln_id, Vulnerability.project_id == project_id)))
        if not vuln:
            raise NotFoundError("Уязвимость не найдена")
        return vuln

    async def list(self, project_id: UUID, vuln_id: UUID) -> list[File]:
        await self._ensure_vuln(project_id, vuln_id)
        return list((await self.db.scalars(select(File).where(File.vulnerability_id == vuln_id).order_by(File.uploaded_at.desc()))).all())

    async def upload(self, project_id: UUID, vuln_id: UUID, upload: UploadFile, actor_id: UUID) -> File:
        await self._ensure_vuln(project_id, vuln_id)
        content = await upload.read()
        if len(content) > MAX_FILE_SIZE:
            raise ValidationError("Размер файла превышает 50 МБ")
        mime_type = magic.from_buffer(content, mime=True)
        if mime_type not in ALLOWED_MIME_TYPES:
            raise ValidationError("Неподдерживаемый тип файла")
        object_key = await asyncio.to_thread(self.storage.upload_bytes, content, mime_type, upload.filename or "file.bin")
        file_meta = File(
            vulnerability_id=vuln_id,
            original_name=upload.filename or "file.bin",
            content_type=mime_type,
            size_bytes=len(content),
            minio_bucket=settings.minio_bucket_name,
            minio_key=object_key,
            uploaded_by=actor_id,
        )
        self.db.add(file_meta)
        await self.db.commit()
        await self.db.refresh(file_meta)
        await self.audit.log("FILE_UPLOAD", user_id=actor_id, entity_type="file", entity_id=file_meta.id)
        await ws_manager.broadcast(project_id, {"event": "created", "entity": "file", "project_id": str(project_id), "data": {"id": str(file_meta.id)}})
        return file_meta

    async def download(self, file_id: UUID, current_user: User) -> tuple[File, bytes]:
        file_meta = await self.db.scalar(select(File).where(File.id == file_id))
        if not file_meta:
            raise NotFoundError("Файл не найден")
        vuln = await self.db.scalar(select(Vulnerability).where(Vulnerability.id == file_meta.vulnerability_id))
        if not vuln:
            raise NotFoundError("Уязвимость не найдена")
        if current_user.role != UserRole.ADMIN:
            membership = await self.db.scalar(
                select(ProjectMember).where(
                    and_(ProjectMember.project_id == vuln.project_id, ProjectMember.user_id == current_user.id)
                )
            )
            if not membership:
                raise ForbiddenError("Нет доступа к файлу")
        blob = await asyncio.to_thread(self.storage.download_bytes, file_meta.minio_key)
        return file_meta, blob

    async def delete(self, project_id: UUID, vuln_id: UUID, file_id: UUID, actor_id: UUID) -> None:
        await self._ensure_vuln(project_id, vuln_id)
        file_meta = await self.db.scalar(
            select(File).where(and_(File.id == file_id, File.vulnerability_id == vuln_id))
        )
        if not file_meta:
            raise NotFoundError("Файл не найден")
        await self.db.delete(file_meta)
        await self.db.commit()
        await asyncio.to_thread(self.storage.delete, file_meta.minio_key)
        await self.audit.log("FILE_DELETE", user_id=actor_id, entity_type="file", entity_id=file_id)
        await ws_manager.broadcast(project_id, {"event": "deleted", "entity": "file", "project_id": str(project_id), "data": {"id": str(file_id)}})


class CommentService:
    """Сервис комментариев и @упоминаний."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.audit = AuditService(db)

    async def _ensure_vuln(self, project_id: UUID, vuln_id: UUID) -> Vulnerability:
        vuln = await self.db.scalar(select(Vulnerability).where(and_(Vulnerability.id == vuln_id, Vulnerability.project_id == project_id)))
        if not vuln:
            raise NotFoundError("Уязвимость не найдена")
        return vuln

    async def _extract_mentions(self, content: str) -> list[User]:
        usernames = set(MENTION_RE.findall(content))
        if not usernames:
            return []
        rows = (await self.db.scalars(select(User).where(User.username.in_(list(usernames))))).all()
        return list(rows)

    async def list(self, vuln_id: UUID, page: int, size: int) -> tuple[list[CommentOut], int]:
        total = await self.db.scalar(select(func.count()).select_from(Comment).where(Comment.vulnerability_id == vuln_id)) or 0
        rows = (
            await self.db.execute(
                select(Comment, User)
                .join(User, User.id == Comment.user_id)
                .where(Comment.vulnerability_id == vuln_id)
                .order_by(Comment.created_at.asc())
                .offset((page - 1) * size)
                .limit(size)
            )
        ).all()
        result: list[CommentOut] = []
        for comment, user in rows:
            mention_rows = (
                await self.db.execute(
                    select(CommentMention, User)
                    .join(User, User.id == CommentMention.user_id)
                    .where(CommentMention.comment_id == comment.id)
                )
            ).all()
            mentions = [MentionOut(user_id=u.id, username=u.username) for _, u in mention_rows]
            result.append(
                CommentOut(
                    id=comment.id,
                    vulnerability_id=comment.vulnerability_id,
                    user_id=comment.user_id,
                    username=user.username,
                    content=comment.content,
                    mentions=mentions,
                    created_at=comment.created_at,
                    updated_at=comment.updated_at,
                )
            )
        return result, total

    async def create(self, project_id: UUID, vuln_id: UUID, content: str, actor: User) -> CommentOut:
        vuln = await self._ensure_vuln(project_id, vuln_id)
        comment = Comment(vulnerability_id=vuln.id, user_id=actor.id, content=content)
        self.db.add(comment)
        await self.db.flush()
        mentioned_users = await self._extract_mentions(content)
        mention_models: list[MentionOut] = []
        for user in mentioned_users:
            self.db.add(CommentMention(comment_id=comment.id, user_id=user.id))
            notification = Notification(user_id=user.id, type=NotificationType.MENTION, comment_id=comment.id, is_read=False)
            self.db.add(notification)
            mention_models.append(MentionOut(user_id=user.id, username=user.username))
        await self.db.commit()
        await self.db.refresh(comment)
        await self.audit.log("CREATE", user_id=actor.id, entity_type="comment", entity_id=comment.id)
        await ws_manager.broadcast(project_id, {"event": "created", "entity": "comment", "project_id": str(project_id), "data": {"id": str(comment.id)}})
        return CommentOut(
            id=comment.id,
            vulnerability_id=comment.vulnerability_id,
            user_id=comment.user_id,
            username=actor.username,
            content=comment.content,
            mentions=mention_models,
            created_at=comment.created_at,
            updated_at=comment.updated_at,
        )

    async def update(self, project_id: UUID, vuln_id: UUID, comment_id: UUID, content: str, actor: User) -> CommentOut:
        await self._ensure_vuln(project_id, vuln_id)
        comment = await self.db.scalar(
            select(Comment).where(and_(Comment.id == comment_id, Comment.vulnerability_id == vuln_id))
        )
        if not comment:
            raise NotFoundError("Комментарий не найден")
        if actor.role != UserRole.ADMIN and comment.user_id != actor.id:
            raise ForbiddenError("Можно редактировать только свой комментарий")
        comment.content = content
        await self.db.execute(delete(CommentMention).where(CommentMention.comment_id == comment.id))
        mentioned_users = await self._extract_mentions(content)
        mention_models: list[MentionOut] = []
        for user in mentioned_users:
            self.db.add(CommentMention(comment_id=comment.id, user_id=user.id))
            self.db.add(Notification(user_id=user.id, type=NotificationType.MENTION, comment_id=comment.id, is_read=False))
            mention_models.append(MentionOut(user_id=user.id, username=user.username))
        await self.db.commit()
        await self.db.refresh(comment)
        await self.audit.log("UPDATE", user_id=actor.id, entity_type="comment", entity_id=comment.id)
        await ws_manager.broadcast(project_id, {"event": "updated", "entity": "comment", "project_id": str(project_id), "data": {"id": str(comment.id)}})
        return CommentOut(
            id=comment.id,
            vulnerability_id=comment.vulnerability_id,
            user_id=comment.user_id,
            username=actor.username,
            content=comment.content,
            mentions=mention_models,
            created_at=comment.created_at,
            updated_at=comment.updated_at,
        )

    async def delete(self, project_id: UUID, vuln_id: UUID, comment_id: UUID, actor: User) -> None:
        await self._ensure_vuln(project_id, vuln_id)
        comment = await self.db.scalar(
            select(Comment).where(and_(Comment.id == comment_id, Comment.vulnerability_id == vuln_id))
        )
        if not comment:
            raise NotFoundError("Комментарий не найден")
        if actor.role != UserRole.ADMIN and comment.user_id != actor.id:
            raise ForbiddenError("Можно удалить только свой комментарий")
        await self.db.delete(comment)
        await self.db.commit()
        await self.audit.log("DELETE", user_id=actor.id, entity_type="comment", entity_id=comment.id)
        await ws_manager.broadcast(project_id, {"event": "deleted", "entity": "comment", "project_id": str(project_id), "data": {"id": str(comment.id)}})


class NotificationService:
    """Сервис уведомлений пользователя."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def list(self, user_id: UUID, page: int, size: int, is_read: bool | None) -> tuple[list[NotificationOut], int]:
        query = select(Notification).where(Notification.user_id == user_id)
        if is_read is not None:
            query = query.where(Notification.is_read == is_read)
        total = await self.db.scalar(select(func.count()).select_from(query.subquery())) or 0
        notifications = (
            await self.db.scalars(query.order_by(Notification.created_at.desc()).offset((page - 1) * size).limit(size))
        ).all()
        result: list[NotificationOut] = []
        for item in notifications:
            context = None
            if item.comment_id:
                row = await self.db.execute(
                    select(Comment, Vulnerability, User)
                    .join(Vulnerability, Vulnerability.id == Comment.vulnerability_id)
                    .join(User, User.id == Comment.user_id)
                    .where(Comment.id == item.comment_id)
                )
                data = row.first()
                if data:
                    comment, vuln, commenter = data
                    context = NotificationContext(
                        vulnerability_id=vuln.id,
                        vulnerability_title=vuln.title,
                        project_id=vuln.project_id,
                        commenter_username=commenter.username,
                    )
            result.append(
                NotificationOut(
                    id=item.id,
                    type=item.type.value,
                    comment_id=item.comment_id,
                    is_read=item.is_read,
                    created_at=item.created_at,
                    context=context,
                )
            )
        return result, total

    async def unread_count(self, user_id: UUID) -> int:
        return await self.db.scalar(
            select(func.count()).select_from(Notification).where(and_(Notification.user_id == user_id, Notification.is_read.is_(False)))
        ) or 0

    async def mark_read(self, notification_id: UUID, user_id: UUID) -> Notification:
        notification = await self.db.scalar(
            select(Notification).where(and_(Notification.id == notification_id, Notification.user_id == user_id))
        )
        if not notification:
            raise NotFoundError("Уведомление не найдено")
        notification.is_read = True
        await self.db.commit()
        await self.db.refresh(notification)
        return notification

    async def mark_all_read(self, user_id: UUID) -> None:
        await self.db.execute(update(Notification).where(Notification.user_id == user_id).values(is_read=True))
        await self.db.commit()


class ImportService:
    """Сервис импорта инфраструктуры из JSON-формата PCF."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def import_json(self, project_id: UUID, payload: bytes, actor_id: UUID) -> ImportResult:
        """Импортирует данные атомарно: при ошибке откатывает всё."""
        try:
            parsed = json.loads(payload.decode("utf-8"))
        except Exception as exc:
            raise ValidationError("Невалидный JSON-файл") from exc
        if not isinstance(parsed, dict) or "hosts" not in parsed or not isinstance(parsed["hosts"], list):
            raise ValidationError("JSON должен содержать массив hosts")

        result = ImportResult(hosts_created=0, ports_created=0, services_created=0, endpoints_created=0, errors=[])
        try:
            for host_data in parsed["hosts"]:
                host = Host(
                    project_id=project_id,
                    ip_address=host_data.get("ip_address"),
                    hostname=host_data.get("hostname"),
                    status=host_data.get("status", "unknown"),
                    notes=host_data.get("notes"),
                )
                self.db.add(host)
                await self.db.flush()
                result.hosts_created += 1

                for port_data in host_data.get("ports", []):
                    duplicate = await self.db.scalar(
                        select(Port).where(
                            and_(
                                Port.host_id == host.id,
                                Port.port_number == port_data["port_number"],
                                Port.protocol == port_data.get("protocol", "tcp"),
                            )
                        )
                    )
                    if duplicate:
                        raise ValidationError(
                            f"Дубликат порта {port_data['port_number']}/{port_data.get('protocol', 'tcp')} для host {host.id}"
                        )
                    port = Port(
                        host_id=host.id,
                        port_number=port_data["port_number"],
                        protocol=port_data.get("protocol", "tcp"),
                        state=port_data.get("state", "open"),
                    )
                    self.db.add(port)
                    await self.db.flush()
                    result.ports_created += 1

                    for service_data in port_data.get("services", []):
                        self.db.add(
                            Service(
                                port_id=port.id,
                                name=service_data["name"],
                                version=service_data.get("version"),
                                banner=service_data.get("banner"),
                            )
                        )
                        result.services_created += 1

                for endpoint_data in host_data.get("endpoints", []):
                    endpoint_payload = {
                        "path": endpoint_data.get("path"),
                        "method": endpoint_data.get("method"),
                        "description": endpoint_data.get("description"),
                        "request_raw": endpoint_data.get("request_raw") or endpoint_data.get("raw_request") or endpoint_data.get("request"),
                    }
                    endpoint_payload = AssetService._apply_raw_request_payload(endpoint_payload)
                    if not endpoint_payload.get("path"):
                        raise ValidationError("Каждый endpoint должен содержать path или request_raw")
                    self.db.add(
                        Endpoint(
                            host_id=host.id,
                            path=endpoint_payload["path"],
                            method=endpoint_payload.get("method"),
                            description=endpoint_payload.get("description"),
                        )
                    )
                    result.endpoints_created += 1

            await self.db.commit()
        except Exception:
            await self.db.rollback()
            raise

        await AuditService(self.db).log("CREATE", user_id=actor_id, entity_type="import", details=result.model_dump())
        await ws_manager.broadcast(project_id, {"event": "updated", "entity": "host", "project_id": str(project_id), "data": {"imported": True}})
        return result


class ReportService:
    """Сервис генерации отчётов в форматах md/pdf/docx."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def _collect_project_data(self, project_id: UUID) -> dict:
        project = await self.db.scalar(select(Project).where(Project.id == project_id))
        if not project:
            raise NotFoundError("Проект не найден")
        members = (
            await self.db.execute(
                select(User.username)
                .join(ProjectMember, ProjectMember.user_id == User.id)
                .where(ProjectMember.project_id == project_id)
            )
        ).all()
        vulnerabilities = (await self.db.scalars(select(Vulnerability).where(Vulnerability.project_id == project_id))).all()
        hosts = (await self.db.scalars(select(Host).where(Host.project_id == project_id))).all()
        ports = (
            await self.db.scalars(select(Port).join(Host, Port.host_id == Host.id).where(Host.project_id == project_id))
        ).all()
        return {
            "project": project,
            "members": [m[0] for m in members],
            "vulnerabilities": list(vulnerabilities),
            "hosts": list(hosts),
            "ports": list(ports),
        }

    async def generate_markdown(self, project_id: UUID) -> bytes:
        """Генерирует Markdown-отчёт."""
        data = await self._collect_project_data(project_id)
        project: Project = data["project"]
        vulnerabilities: list[Vulnerability] = data["vulnerabilities"]
        severity_stats: dict[str, int] = {}
        status_stats: dict[str, int] = {}
        for vuln in vulnerabilities:
            severity_stats[vuln.severity.value] = severity_stats.get(vuln.severity.value, 0) + 1
            status_stats[vuln.status.value] = status_stats.get(vuln.status.value, 0) + 1

        lines = [
            f"# Отчёт по проекту {project.name}",
            "",
            "## Общая информация",
            f"- Статус: {project.status.value}",
            f"- Даты: {project.start_date} - {project.end_date}",
            f"- Участники: {', '.join(data['members']) if data['members'] else 'нет'}",
            "",
            "## Статистика уязвимостей по критичности",
        ]
        for key, value in severity_stats.items():
            lines.append(f"- {key}: {value}")
        lines += ["", "## Статистика уязвимостей по статусу"]
        for key, value in status_stats.items():
            lines.append(f"- {key}: {value}")
        lines += ["", "## Активы", f"- Хосты: {len(data['hosts'])}", f"- Порты: {len(data['ports'])}", "", "## Уязвимости"]
        for vuln in vulnerabilities:
            lines += [
                f"### {vuln.title}",
                f"- Severity: {vuln.severity.value}",
                f"- Status: {vuln.status.value}",
                f"- CVSS: {vuln.cvss_version.value if vuln.cvss_version else '-'} {vuln.cvss_score if vuln.cvss_score else '-'}",
                f"- CWE: {vuln.cwe_id or '-'}",
                "",
                "**Описание**",
                vuln.description or "-",
                "",
                "**Шаги воспроизведения**",
                vuln.steps_to_reproduce or "-",
                "",
                "**Влияние**",
                vuln.impact or "-",
                "",
                "**Рекомендации**",
                vuln.recommendations or "-",
                "",
            ]
        return "\n".join(lines).encode("utf-8")

    @staticmethod
    def _build_pdf(markdown_text: str) -> bytes:
        """Синхронная генерация PDF-версии отчёта."""
        buffer = BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=A4)
        width, height = A4
        y = height - 40
        for line in markdown_text.splitlines():
            if y < 40:
                pdf.showPage()
                y = height - 40
            pdf.drawString(40, y, line[:120])
            y -= 14
        pdf.save()
        return buffer.getvalue()

    @staticmethod
    def _build_docx(markdown_text: str) -> bytes:
        """Синхронная генерация DOCX-версии отчёта."""
        doc = Document()
        for line in markdown_text.splitlines():
            doc.add_paragraph(line)
        buffer = BytesIO()
        doc.save(buffer)
        return buffer.getvalue()

    async def generate(self, project_id: UUID, output_format: str) -> bytes:
        """Генерирует отчёт в запрошенном формате."""
        markdown_bytes = await self.generate_markdown(project_id)
        if output_format == "md":
            return markdown_bytes
        if output_format == "pdf":
            return await asyncio.to_thread(self._build_pdf, markdown_bytes.decode("utf-8"))
        if output_format == "docx":
            return await asyncio.to_thread(self._build_docx, markdown_bytes.decode("utf-8"))
        raise ValidationError("Неподдерживаемый формат отчёта")
