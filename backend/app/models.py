from datetime import date, datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.enums import (
    AssetType,
    CvssVersion,
    HostStatus,
    HttpMethod,
    NotificationType,
    OsType,
    PortState,
    ProjectRole,
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

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    full_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    avatar_minio_bucket: Mapped[str | None] = mapped_column(String(63), nullable=True)
    avatar_minio_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    avatar_content_type: Mapped[str | None] = mapped_column(String(127), nullable=True)
    avatar_uploaded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole, name="user_role"), nullable=False, default=UserRole.PENTESTER)
    # Проектная роль — глобальная, настраивается в /members. Лид = обычный юзер,
    # которому открыты доп. возможности в проектах, где он участник.
    project_role: Mapped[ProjectRole] = mapped_column(
        Enum(ProjectRole, name="project_role"),
        nullable=False,
        default=ProjectRole.PENTESTER,
        server_default=ProjectRole.PENTESTER.name,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    @property
    def avatar_url(self) -> str | None:
        if not self.avatar_minio_key:
            return None
        version = int(self.avatar_uploaded_at.timestamp()) if self.avatar_uploaded_at else 0
        return f"/api/v1/users/{self.id}/avatar?v={version}"


class RefreshToken(Base):
    """Хранилище активных refresh-токенов (в виде хэшей)."""

    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AgentApiToken(Base, TimestampMixin):
    """Bearer-токен для машинного `/api/v2` доступа AI-агентов."""

    __tablename__ = "agent_api_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # name — TEXT без ограничения длины: бывают токены с длинными описательными
    # именами ("Jenkins CI / nightly scan for project X / scope: vulns+notes"),
    # не хотим ловить отказ на UI.
    name: Mapped[str] = mapped_column(Text, nullable=False)
    token_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    token_prefix: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    scopes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    all_projects: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    created_by: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AgentApiTokenProjectGrant(Base):
    """Разрешение agent token на конкретный проект."""

    __tablename__ = "agent_api_token_project_grants"
    __table_args__ = (UniqueConstraint("token_id", "project_id", name="uq_agent_api_token_project"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    token_id: Mapped[int] = mapped_column(Integer, ForeignKey("agent_api_tokens.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id: Mapped[int] = mapped_column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class MailJob(Base, TimestampMixin):
    """Задание на отправку письма пользователю."""

    __tablename__ = "mail_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_by: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    recipient_email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    template: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", server_default="pending", index=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)


class Project(Base, TimestampMixin):
    """Пентест-проект."""

    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    folder: Mapped[str] = mapped_column(String(255), nullable=False, default="", server_default="")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    start_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    end_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    timeline_frozen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[ProjectStatus] = mapped_column(
        Enum(ProjectStatus, name="project_status"), nullable=False, default=ProjectStatus.ACTIVE
    )
    created_by: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)


class ProjectFolder(Base, TimestampMixin):
    """Папка проектов с поддержкой иерархии."""

    __tablename__ = "project_folders"
    __table_args__ = (
        UniqueConstraint("parent_id", "name", name="uq_project_folder_parent_name"),
        UniqueConstraint("path", name="uq_project_folder_path"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    path: Mapped[str] = mapped_column(String(1024), nullable=False)
    parent_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("project_folders.id", ondelete="CASCADE"),
        nullable=True,
    )
    created_by: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)


class ProjectMember(Base):
    """Связь участника с проектом."""

    __tablename__ = "project_members"
    __table_args__ = (UniqueConstraint("project_id", "user_id", name="uq_project_member"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class JiraInstance(Base, TimestampMixin):
    """Глобальная конфигурация Jira для backend-only интеграции."""

    __tablename__ = "jira_instances"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="default", server_default="default")
    base_url: Mapped[str] = mapped_column(String(1024), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    api_token_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    default_issue_type: Mapped[str] = mapped_column(String(100), nullable=False, default="Task", server_default="Task")
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")
    created_by: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)


class ProjectJiraLink(Base, TimestampMixin):
    """Привязка проекта PCF к Jira project key."""

    __tablename__ = "project_jira_links"
    __table_args__ = (UniqueConstraint("project_id", name="uq_project_jira_link_project"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    jira_project_key: Mapped[str] = mapped_column(String(32), nullable=False)
    created_by: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)


class ProjectNote(Base, TimestampMixin):
    """Вложенная заметка проекта (Confluence-like)."""

    __tablename__ = "project_notes"
    __table_args__ = (UniqueConstraint("project_id", "parent_id", "title", name="uq_project_note_sibling_title"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    parent_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("project_notes.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    content: Mapped[str | None] = mapped_column(Text, nullable=True)
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    created_by: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    updated_by: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)

    # Автор нужен в выдаче по имени: список пользователей доступен только админу,
    # поэтому имя резолвим на бэке, а не на фронте. Два FK на users → foreign_keys
    # обязателен, иначе связь неоднозначна.
    creator: Mapped["User"] = relationship("User", foreign_keys=[created_by], lazy="selectin")

    @property
    def created_by_username(self) -> str | None:
        """Имя автора заметки для ProjectNoteOut."""
        return self.creator.username if self.creator else None


class ProjectNoteComment(Base, TimestampMixin):
    """Комментарий к странице заметки проекта."""

    __tablename__ = "project_note_comments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    note_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("project_notes.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    content: Mapped[str] = mapped_column(Text, nullable=False)


class Host(Base, TimestampMixin):
    """Хост инфраструктуры проекта.

    Поле ``ip_address`` сохранено для обратной совместимости и хранит «основной»
    IP-адрес (тот же, что и ``HostIpAddress.is_primary == True``). Полный список
    IP-адресов хоста ведётся в отдельной таблице :class:`HostIpAddress`.
    """

    __tablename__ = "hosts"
    __table_args__ = (
        CheckConstraint("ip_address IS NOT NULL OR hostname IS NOT NULL", name="ck_host_ip_or_hostname"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[HostStatus] = mapped_column(Enum(HostStatus, name="host_status"), nullable=False, default=HostStatus.UNKNOWN)
    os_type: Mapped[OsType] = mapped_column(
        Enum(OsType, name="host_os_type"),
        nullable=False,
        default=OsType.UNKNOWN,
        server_default=OsType.UNKNOWN.name,
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    ip_addresses: Mapped[list["HostIpAddress"]] = relationship(
        "HostIpAddress",
        back_populates="host",
        cascade="all, delete-orphan",
        order_by="HostIpAddress.created_at",
    )


class HostIpAddress(Base, TimestampMixin):
    """Один IP-адрес хоста — у одного хоста их может быть несколько."""

    __tablename__ = "host_ip_addresses"
    __table_args__ = (
        UniqueConstraint("host_id", "ip_address", name="uq_host_ip_address"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("hosts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    label: Mapped[str | None] = mapped_column(String(100), nullable=True)
    is_primary: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")

    host: Mapped[Host] = relationship("Host", back_populates="ip_addresses")
    ports: Mapped[list["Port"]] = relationship(
        "Port",
        back_populates="ip_address",
        cascade="all, delete-orphan",
        order_by="Port.port_number",
    )


class Port(Base, TimestampMixin):
    """Порт, обнаруженный на хосте."""

    __tablename__ = "ports"
    __table_args__ = (
        UniqueConstraint("ip_address_id", "port_number", "protocol", name="uq_port_ip_number_protocol"),
        CheckConstraint("port_number >= 1 AND port_number <= 65535", name="ck_port_number_range"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_id: Mapped[int] = mapped_column(Integer, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    ip_address_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("host_ip_addresses.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    port_number: Mapped[int] = mapped_column(nullable=False)
    protocol: Mapped[Protocol] = mapped_column(Enum(Protocol, name="port_protocol"), nullable=False, default=Protocol.TCP)
    state: Mapped[PortState] = mapped_column(Enum(PortState, name="port_state"), nullable=False, default=PortState.OPEN)

    ip_address: Mapped["HostIpAddress"] = relationship("HostIpAddress", back_populates="ports")
    # Сервисы порта — нужны, чтобы отдавать имя сервиса вместе с портом одним
    # запросом (FK services.port_id уже есть, миграция не требуется).
    services: Mapped[list["Service"]] = relationship(
        "Service",
        cascade="all, delete-orphan",
        order_by="Service.name",
    )


class Service(Base, TimestampMixin):
    """Сервис, работающий на порту."""

    __tablename__ = "services"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    port_id: Mapped[int] = mapped_column(Integer, ForeignKey("ports.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    banner: Mapped[str | None] = mapped_column(Text, nullable=True)


class Endpoint(Base, TimestampMixin):
    """HTTP endpoint, связанный с хостом."""

    __tablename__ = "endpoints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_id: Mapped[int] = mapped_column(Integer, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False, index=True)
    path: Mapped[str] = mapped_column(Text, nullable=False)
    method: Mapped[HttpMethod | None] = mapped_column(Enum(HttpMethod, name="http_method"), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    query_params: Mapped[list[dict] | None] = mapped_column(JSON, nullable=True)
    request_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_content_type: Mapped[str | None] = mapped_column(String(127), nullable=True)
    request_headers: Mapped[list[dict] | None] = mapped_column(JSON, nullable=True)


class Vulnerability(Base, TimestampMixin):
    """Найденная уязвимость."""

    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
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
    workflow_steps: Mapped[list[dict] | None] = mapped_column(JSON, nullable=True)
    steps_to_reproduce: Mapped[str | None] = mapped_column(Text, nullable=True)
    impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendations: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)

    # Имя автора отдаём вместе с находкой: /users доступен только админу, а
    # «Reported by» видят все участники проекта.
    creator: Mapped["User"] = relationship("User", foreign_keys=[created_by], lazy="selectin")

    @property
    def created_by_username(self) -> str | None:
        """Имя автора находки для VulnerabilityOut."""
        return self.creator.username if self.creator else None


class VulnerabilityAsset(Base):
    """Полиморфная привязка уязвимости к активу."""

    __tablename__ = "vulnerability_assets"
    __table_args__ = (UniqueConstraint("vulnerability_id", "asset_type", "asset_id", name="uq_vuln_asset"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
    )
    asset_type: Mapped[AssetType] = mapped_column(Enum(AssetType, name="asset_type"), nullable=False)
    asset_id: Mapped[int] = mapped_column(Integer, nullable=False)


class JiraIssueLink(Base, TimestampMixin):
    """Связь уязвимости PCF с issue в Jira."""

    __tablename__ = "jira_issue_links"
    __table_args__ = (UniqueConstraint("vulnerability_id", name="uq_jira_issue_link_vulnerability"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    jira_issue_key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    jira_issue_url: Mapped[str] = mapped_column(String(1024), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="linked", server_default="linked")
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)


class File(Base):
    """Метаданные загруженного файла."""

    __tablename__ = "files"
    __table_args__ = (CheckConstraint("size_bytes <= 52428800", name="ck_file_max_size"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    original_name: Mapped[str] = mapped_column(String(500), nullable=False)
    content_type: Mapped[str] = mapped_column(String(127), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    minio_bucket: Mapped[str] = mapped_column(String(63), nullable=False)
    minio_key: Mapped[str] = mapped_column(Text, nullable=False)
    uploaded_by: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Comment(Base, TimestampMixin):
    """Комментарий к уязвимости."""

    __tablename__ = "comments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)


class CommentMention(Base):
    """Упоминание пользователя в комментарии."""

    __tablename__ = "comment_mentions"
    __table_args__ = (UniqueConstraint("comment_id", "user_id", name="uq_comment_mention"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    comment_id: Mapped[int] = mapped_column(Integer, ForeignKey("comments.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)


class Notification(Base):
    """In-app уведомление."""

    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    type: Mapped[NotificationType] = mapped_column(
        Enum(NotificationType, name="notification_type"),
        nullable=False,
        default=NotificationType.MENTION,
    )
    comment_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("comments.id", ondelete="SET NULL"), nullable=True)
    # FK на комментарий заметки — для упоминаний (@username) в обсуждениях заметок.
    # Заполнен ровно у одного из двух (comment_id ИЛИ note_comment_id), не у обоих.
    note_comment_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("project_note_comments.id", ondelete="SET NULL"),
        nullable=True,
    )
    # Предмет уведомления для не-mention поводов: добавление в проект и смена
    # статуса проекта ссылаются на project_id, смена статуса находки — на
    # vulnerability_id. У упоминаний оба пустые: их предмет — комментарий выше.
    project_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=True)
    vulnerability_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=True)
    # Кто инициировал событие и какой статус выставлен — чтобы не доставать из
    # аудита: уведомление должно быть самодостаточным даже после правок объекта.
    actor_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    status: Mapped[str | None] = mapped_column(String(50), nullable=True)
    is_read: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AuditLog(Base):
    """Запись журнала действий."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    entity_type: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    entity_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
