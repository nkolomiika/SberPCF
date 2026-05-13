"""Сброс демо-данных и пересид БД (пользователей сохраняет).

Запуск из каталога backend:
    PYTHONPATH=/app python scripts/reset_and_seed.py   # Docker
    python scripts/reset_and_seed.py                   # локально, если backend в PYTHONPATH
"""
import asyncio
import base64
import sys
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

# Позволяет выполнять файл напрямую без предварительного export PYTHONPATH=/app
_backend_root = Path(__file__).resolve().parent.parent
if str(_backend_root) not in sys.path:
    sys.path.insert(0, str(_backend_root))

from sqlalchemy import text, select

from app.audit_store import audit_store
from app.config import get_settings
from app.database import Base, SessionLocal, engine
from app.enums import (
    AssetType,
    CvssVersion,
    HostStatus,
    HttpMethod,
    NotificationType,
    PortState,
    ProjectStatus,
    Protocol,
    Severity,
    UserRole,
    VulnerabilityStatus,
)
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
    Service,
    User,
    Vulnerability,
    VulnerabilityAsset,
)
from app.security import hash_password
from app.services import UserService
from app.storage.minio_client import MinioStorage

DEMO_PNG_BYTES = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Wn0K6sAAAAASUVORK5CYII="
)


async def ensure_schema() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


def reset_minio(minio_keys: list[str]) -> None:
    if not minio_keys:
        return
    storage = MinioStorage()
    storage.ensure_bucket()
    for object_key in minio_keys:
        try:
            storage.client.remove_object(storage.bucket, object_key)
        except Exception:
            # Объект может отсутствовать в MinIO (например, был удалён вручную).
            pass


async def reset_clickhouse() -> None:
    await audit_store.ensure_table()
    if not audit_store.enabled:
        return
    try:
        client = audit_store._get_client()
        client.command(f"CREATE DATABASE IF NOT EXISTS {get_settings().clickhouse_database}")
        client.command("TRUNCATE TABLE audit_logs")
    except Exception:
        pass


async def create_users() -> dict[str, User]:
    settings = get_settings()
    users: dict[str, User] = {}
    async with SessionLocal() as db:
        await UserService(db).bootstrap_admin()
        admin = await db.scalar(select(User).where(User.username == settings.initial_admin_username))
        if not admin:
            raise RuntimeError("Admin user was not created")
        users["admin"] = admin

        demo_users = [
            ("alice", "alice@example.com", UserRole.PENTESTER),
            ("bob", "bob@example.com", UserRole.PENTESTER),
            ("charlie", "charlie@example.com", UserRole.PENTESTER),
            ("diana", "diana@example.com", UserRole.DEVELOPER),
            ("eve", "eve@example.com", UserRole.DEVELOPER),
        ]
        for username, email, role in demo_users:
            user = await db.scalar(select(User).where(User.username == username))
            if not user:
                user = await db.scalar(select(User).where(User.email == email))
            if not user:
                user = User(
                    username=username,
                    email=email,
                    password_hash=hash_password("admin"),
                    role=role,
                    is_active=True,
                )
                db.add(user)
                await db.flush()
            users[username] = user
        await db.commit()
    return users


async def clear_domain_data_preserve_users() -> list[str]:
    async with SessionLocal() as db:
        minio_keys = list((await db.scalars(select(File.minio_key).where(File.minio_key.is_not(None)))).all())
        await db.execute(
            text(
                """
                TRUNCATE TABLE
                    comment_mentions,
                    notifications,
                    comments,
                    vulnerability_assets,
                    files,
                    vulnerabilities,
                    services,
                    ports,
                    endpoints,
                    hosts,
                    project_members,
                    projects,
                    project_folders,
                    mail_jobs,
                    audit_logs
                RESTART IDENTITY CASCADE
                """
            )
        )
        await db.commit()
    return minio_keys


async def seed_demo_data() -> None:
    users = await create_users()
    storage = MinioStorage()
    storage.ensure_bucket()
    now = datetime.now(UTC)
    today = date.today()
    severity_cycle = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    status_cycle = [
        VulnerabilityStatus.OPEN,
        VulnerabilityStatus.IN_PROGRESS,
        VulnerabilityStatus.FIXED,
        VulnerabilityStatus.ACCEPTED_RISK,
    ]
    project_statuses = [ProjectStatus.ACTIVE, ProjectStatus.ACTIVE, ProjectStatus.COMPLETED, ProjectStatus.ARCHIVED]
    folder_specs = [
        ("External Audits", None),
        ("Internal", None),
        ("Red Team", None),
        ("Phase 1", "Red Team"),
        ("Phase 2", "Red Team"),
        ("Mobile", "External Audits"),
        ("API", "External Audits"),
        ("Infrastructure", "Internal"),
    ]

    async with SessionLocal() as db:
        admin = await db.scalar(select(User).where(User.username == "admin"))
        if not admin:
            raise RuntimeError("Admin user is missing")

        folders_by_path: dict[str, ProjectFolder] = {}
        for folder_name, parent_path in folder_specs:
            path = f"{parent_path}/{folder_name}" if parent_path else folder_name
            parent = folders_by_path.get(parent_path) if parent_path else None
            folder = ProjectFolder(
                name=folder_name,
                path=path,
                parent_id=parent.id if parent else None,
                created_by=admin.id,
            )
            db.add(folder)
            await db.flush()
            folders_by_path[path] = folder

        project_specs = [
            ("Acme External API", "External Audits/API", ProjectStatus.ACTIVE, [users["alice"], users["bob"], users["diana"]]),
            ("Contoso Mobile", "External Audits/Mobile", ProjectStatus.ACTIVE, [users["alice"], users["eve"]]),
            ("Intranet Review", "Internal/Infrastructure", ProjectStatus.ACTIVE, [users["bob"], users["charlie"]]),
            ("Red Team Alpha", "Red Team/Phase 1", ProjectStatus.ACTIVE, [users["alice"], users["charlie"], users["diana"]]),
            ("Red Team Bravo", "Red Team/Phase 2", ProjectStatus.COMPLETED, [users["bob"], users["eve"]]),
            ("Partner Portal", "", ProjectStatus.ACTIVE, [users["alice"], users["bob"]]),
            ("Legacy ERP", "", ProjectStatus.ARCHIVED, [users["charlie"], users["diana"]]),
            ("Corporate SSO", "Internal", ProjectStatus.COMPLETED, [users["alice"], users["eve"]]),
        ]

        audit_rows: list[dict] = []
        file_counter = 0

        for project_index, (project_name, folder_path, project_status, members) in enumerate(project_specs, start=1):
            project = Project(
                name=project_name,
                folder=folder_path,
                description=f"Тестовый проект '{project_name}' с набором активов, уязвимостей и совместной работы.",
                start_date=today - timedelta(days=14 + project_index),
                end_date=today + timedelta(days=14 - project_index if project_status == ProjectStatus.ACTIVE else -project_index),
                status=project_statuses[(project_index - 1) % len(project_statuses)] if project_status is None else project_status,
                created_by=admin.id,
            )
            db.add(project)
            await db.flush()

            db.add(ProjectMember(project_id=project.id, user_id=admin.id))
            for member in members:
                db.add(ProjectMember(project_id=project.id, user_id=member.id))
            await db.flush()

            audit_rows.append(
                {
                    "user_id": admin.id,
                    "username": admin.username,
                    "action": "CREATE",
                    "entity_type": "project",
                    "entity_id": project.id,
                    "details": {"project": project.name, "folder": folder_path or "root"},
                    "ip_address": "127.0.0.1",
                    "created_at": now - timedelta(days=project_index),
                }
            )

            for host_index in range(1, 4):
                host = Host(
                    project_id=project.id,
                    ip_address=f"10.{project_index}.{host_index}.10",
                    hostname=f"{project_name.lower().replace(' ', '-')}-host-{host_index}.demo.local",
                    status=HostStatus.UP if host_index != 2 else HostStatus.UNKNOWN,
                    notes=f"Описание тестового хоста {host_index} для проекта {project_name}.",
                )
                db.add(host)
                await db.flush()

                ports_for_host: list[Port] = []
                for port_number, protocol, state, service_name, version in [
                    (22, Protocol.TCP, PortState.OPEN, "ssh", "OpenSSH_9.6"),
                    (80, Protocol.TCP, PortState.OPEN, "http", "nginx/1.25"),
                    (443, Protocol.TCP, PortState.OPEN, "https", "nginx/1.25"),
                    (8080, Protocol.TCP, PortState.FILTERED if host_index == 3 else PortState.OPEN, "tomcat", "10.1"),
                ]:
                    port = Port(host_id=host.id, port_number=port_number, protocol=protocol, state=state)
                    db.add(port)
                    await db.flush()
                    ports_for_host.append(port)
                    db.add(
                        Service(
                            port_id=port.id,
                            name=service_name,
                            version=version,
                            banner=f"{service_name} banner for {project_name}",
                        )
                    )

                endpoints: list[Endpoint] = []
                for method, path_suffix, description in [
                    (HttpMethod.GET, "/api/health", "Проверка состояния сервиса"),
                    (HttpMethod.POST, "/api/login", "Точка входа пользователей"),
                    (HttpMethod.GET, "/api/users", "Получение списка пользователей"),
                ]:
                    endpoint = Endpoint(
                        host_id=host.id,
                        path=path_suffix,
                        method=method,
                        description=f"{description} ({project_name})",
                    )
                    db.add(endpoint)
                    await db.flush()
                    endpoints.append(endpoint)

                for vuln_index in range(1, 3):
                    vuln = Vulnerability(
                        project_id=project.id,
                        title=f"{project_name} / Host {host_index} / Finding {vuln_index}",
                        description="Тестовая уязвимость для проверки host-centric сценариев.",
                        severity=severity_cycle[(project_index + host_index + vuln_index) % len(severity_cycle)],
                        cvss_version=CvssVersion.V40,
                        cvss_score=8.7 if vuln_index % 2 else 9.3,
                        cvss_vector=(
                            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
                            if vuln_index % 2
                            else "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L"
                        ),
                        cwe_id="CWE-79" if vuln_index % 2 else "CWE-89",
                        status=status_cycle[(project_index + vuln_index) % len(status_cycle)],
                        steps_to_reproduce="1. Выполнить запрос\n2. Получить некорректный ответ\n3. Зафиксировать результат",
                        impact="Компрометация конфиденциальности и/или целостности данных.",
                        recommendations="Ограничить доступ, валидировать входные данные и усилить аутентификацию.",
                        created_by=members[0].id if members else admin.id,
                    )
                    db.add(vuln)
                    await db.flush()

                    db.add(VulnerabilityAsset(vulnerability_id=vuln.id, asset_type=AssetType.HOST, asset_id=host.id))
                    if ports_for_host:
                        db.add(VulnerabilityAsset(vulnerability_id=vuln.id, asset_type=AssetType.PORT, asset_id=ports_for_host[0].id))
                    if endpoints:
                        db.add(VulnerabilityAsset(vulnerability_id=vuln.id, asset_type=AssetType.ENDPOINT, asset_id=endpoints[0].id))

                    file_counter += 1
                    png_bytes = DEMO_PNG_BYTES
                    png_key = storage.upload_bytes(png_bytes, "image/png", f"evidence-{project_index}-{host_index}-{vuln_index}.png")
                    db.add(
                        File(
                            vulnerability_id=vuln.id,
                            original_name=f"evidence-{project_index}-{host_index}-{vuln_index}.png",
                            content_type="image/png",
                            size_bytes=len(png_bytes),
                            minio_bucket=storage.bucket,
                            minio_key=png_key,
                            uploaded_by=members[0].id if members else admin.id,
                        )
                    )

                    report_bytes = f"Demo evidence for {project_name} host {host_index} vuln {vuln_index}".encode("utf-8")
                    report_key = storage.upload_bytes(report_bytes, "text/plain", f"notes-{project_index}-{host_index}-{vuln_index}.txt")
                    db.add(
                        File(
                            vulnerability_id=vuln.id,
                            original_name=f"notes-{project_index}-{host_index}-{vuln_index}.txt",
                            content_type="text/plain",
                            size_bytes=len(report_bytes),
                            minio_bucket=storage.bucket,
                            minio_key=report_key,
                            uploaded_by=admin.id,
                        )
                    )

                    author = members[0] if members else admin
                    mentioned = members[-1] if len(members) > 1 else admin
                    comment = Comment(
                        vulnerability_id=vuln.id,
                        user_id=author.id,
                        content=f"Проверено автором @{mentioned.username}. Нужно перепроверить доступ к {host.hostname}.",
                    )
                    db.add(comment)
                    await db.flush()
                    db.add(CommentMention(comment_id=comment.id, user_id=mentioned.id))
                    db.add(Notification(user_id=mentioned.id, type=NotificationType.MENTION, comment_id=comment.id, is_read=False))

                    audit_rows.append(
                        {
                            "user_id": author.id,
                            "username": author.username,
                            "action": "CREATE",
                            "entity_type": "vulnerability",
                            "entity_id": vuln.id,
                            "details": {"project": project.name, "host": host.hostname, "severity": vuln.severity.value},
                            "ip_address": f"10.255.{project_index}.{host_index}",
                            "created_at": now - timedelta(hours=project_index * host_index * vuln_index),
                        }
                    )

        for row in audit_rows:
            db.add(
                AuditLog(
                    user_id=row["user_id"],
                    action=row["action"],
                    entity_type=row["entity_type"],
                    entity_id=row["entity_id"],
                    details=row["details"],
                    ip_address=row["ip_address"],
                    created_at=row["created_at"],
                )
            )

        await db.commit()

    for row in audit_rows:
        await audit_store.insert(
            user_id=row["user_id"],
            username=row["username"],
            action=row["action"],
            entity_type=row["entity_type"],
            entity_id=row["entity_id"],
            details=row["details"],
            ip_address=row["ip_address"],
            created_at=row["created_at"],
        )


async def main() -> None:
    await ensure_schema()
    minio_keys = await clear_domain_data_preserve_users()
    reset_minio(minio_keys)
    await reset_clickhouse()
    await seed_demo_data()
    print("Database reseed complete. Existing users were preserved; demo data for projects/assets/vulnerabilities was refreshed.")


if __name__ == "__main__":
    asyncio.run(main())
