from datetime import date, datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    Enum,
    ForeignKey,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
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


class TimestampMixin:
    """Добавляет поля created_at/updated_at."""

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class User(Base, TimestampMixin):
    """Пользователь системы."""

    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole, name="user_role"), nullable=False, default=UserRole.PENTESTER)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class RefreshToken(Base):
    """Хранилище активных refresh-токенов (в виде хэшей)."""

    __tablename__ = "refresh_tokens"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Project(Base, TimestampMixin):
    """Пентест-проект."""

    __tablename__ = "projects"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    start_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    end_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    status: Mapped[ProjectStatus] = mapped_column(
        Enum(ProjectStatus, name="project_status"), nullable=False, default=ProjectStatus.ACTIVE
    )
    created_by: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)


class ProjectMember(Base):
    """Связь участника с проектом."""

    __tablename__ = "project_members"
    __table_args__ = (UniqueConstraint("project_id", "user_id", name="uq_project_member"),)

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Host(Base, TimestampMixin):
    """Хост инфраструктуры проекта."""

    __tablename__ = "hosts"
    __table_args__ = (
        CheckConstraint("ip_address IS NOT NULL OR hostname IS NOT NULL", name="ck_host_ip_or_hostname"),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[HostStatus] = mapped_column(Enum(HostStatus, name="host_status"), nullable=False, default=HostStatus.UNKNOWN)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class Port(Base, TimestampMixin):
    """Порт, обнаруженный на хосте."""

    __tablename__ = "ports"
    __table_args__ = (
        UniqueConstraint("host_id", "port_number", "protocol", name="uq_port_host_number_protocol"),
        CheckConstraint("port_number >= 1 AND port_number <= 65535", name="ck_port_number_range"),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    host_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    port_number: Mapped[int] = mapped_column(nullable=False)
    protocol: Mapped[Protocol] = mapped_column(Enum(Protocol, name="port_protocol"), nullable=False, default=Protocol.TCP)
    state: Mapped[PortState] = mapped_column(Enum(PortState, name="port_state"), nullable=False, default=PortState.OPEN)


class Service(Base, TimestampMixin):
    """Сервис, работающий на порту."""

    __tablename__ = "services"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    port_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("ports.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    banner: Mapped[str | None] = mapped_column(Text, nullable=True)


class Endpoint(Base, TimestampMixin):
    """HTTP endpoint, связанный с хостом."""

    __tablename__ = "endpoints"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    host_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False, index=True)
    path: Mapped[str] = mapped_column(Text, nullable=False)
    method: Mapped[HttpMethod | None] = mapped_column(Enum(HttpMethod, name="http_method"), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)


class Vulnerability(Base, TimestampMixin):
    """Найденная уязвимость."""

    __tablename__ = "vulnerabilities"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[Severity] = mapped_column(Enum(Severity, name="vuln_severity"), nullable=False)
    cvss_version: Mapped[CvssVersion | None] = mapped_column(Enum(CvssVersion, name="cvss_version"), nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Numeric(4, 1), nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cwe_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
    status: Mapped[VulnerabilityStatus] = mapped_column(
        Enum(VulnerabilityStatus, name="vuln_status"), nullable=False, default=VulnerabilityStatus.OPEN, index=True
    )
    steps_to_reproduce: Mapped[str | None] = mapped_column(Text, nullable=True)
    impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendations: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)


class VulnerabilityAsset(Base):
    """Полиморфная привязка уязвимости к активу."""

    __tablename__ = "vulnerability_assets"
    __table_args__ = (UniqueConstraint("vulnerability_id", "asset_type", "asset_id", name="uq_vuln_asset"),)

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    vulnerability_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
    )
    asset_type: Mapped[AssetType] = mapped_column(Enum(AssetType, name="asset_type"), nullable=False)
    asset_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)


class File(Base):
    """Метаданные загруженного файла."""

    __tablename__ = "files"
    __table_args__ = (CheckConstraint("size_bytes <= 52428800", name="ck_file_max_size"),)

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    vulnerability_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    original_name: Mapped[str] = mapped_column(String(500), nullable=False)
    content_type: Mapped[str] = mapped_column(String(127), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    minio_bucket: Mapped[str] = mapped_column(String(63), nullable=False)
    minio_key: Mapped[str] = mapped_column(Text, nullable=False)
    uploaded_by: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Comment(Base, TimestampMixin):
    """Комментарий к уязвимости."""

    __tablename__ = "comments"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    vulnerability_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)


class CommentMention(Base):
    """Упоминание пользователя в комментарии."""

    __tablename__ = "comment_mentions"
    __table_args__ = (UniqueConstraint("comment_id", "user_id", name="uq_comment_mention"),)

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    comment_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("comments.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)


class Notification(Base):
    """In-app уведомление."""

    __tablename__ = "notifications"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    type: Mapped[NotificationType] = mapped_column(
        Enum(NotificationType, name="notification_type"),
        nullable=False,
        default=NotificationType.MENTION,
    )
    comment_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("comments.id", ondelete="SET NULL"), nullable=True)
    is_read: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AuditLog(Base):
    """Запись журнала действий."""

    __tablename__ = "audit_logs"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    user_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    entity_type: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    entity_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True, index=True)
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
