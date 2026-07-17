from datetime import date, datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, ValidationInfo, field_validator, model_validator

from app.enums import (
    AssetType,
    CvssVersion,
    HostStatus,
    HttpMethod,
    OsType,
    PortState,
    ProjectRole,
    ProjectStatus,
    Protocol,
    Severity,
    UserRole,
    VulnerabilityStatus,
)


class ORMBase(BaseModel):
    """Базовая схема для работы с ORM-объектами."""

    model_config = ConfigDict(from_attributes=True)


class InputBaseModel(BaseModel):
    """Базовая схема входных данных с нормализацией строк."""

    @field_validator("*", mode="before")
    @classmethod
    def normalize_strings(cls, value: object, info: ValidationInfo) -> object:
        if isinstance(value, str):
            stripped = value.strip()
            field = cls.model_fields.get(info.field_name)
            if stripped == "" and field is not None and not field.is_required():
                return None
            return stripped
        if isinstance(value, list) and all(isinstance(item, str) for item in value):
            return [item.strip() for item in value if item.strip()]
        return value


class LoginRequest(InputBaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=128)


class LoginResponse(BaseModel):
    id: int
    username: str
    role: UserRole


class RefreshResponse(BaseModel):
    ok: bool = True


class AgentTokenCreate(InputBaseModel):
    # Длину названия не ограничиваем — колонка в БД переведена в TEXT, юзеры
    # часто описывают токен длинным расшифровывающим именем (для какого скрипта/CI/команды).
    name: str = Field(min_length=1)
    scopes: list[str] = Field(default_factory=list)
    project_ids: list[int] = Field(default_factory=list)
    all_projects: bool = False
    expires_at: datetime | None = None


class AgentTokenOut(ORMBase):
    id: int
    name: str
    token_prefix: str
    scopes: list[str] = Field(default_factory=list)
    all_projects: bool
    created_by: int
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    last_used_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    project_ids: list[int] = Field(default_factory=list)


class AgentTokenCreateResponse(AgentTokenOut):
    token: str


class UserCreate(InputBaseModel):
    username: str = Field(min_length=1, max_length=100)
    email: EmailStr
    full_name: str | None = Field(default=None, max_length=255)
    password: str | None = Field(default=None, min_length=8, max_length=128)
    role: UserRole = UserRole.PENTESTER
    project_role: ProjectRole = ProjectRole.PENTESTER
    send_invite_email: bool = False


class UserUpdate(InputBaseModel):
    username: str | None = Field(default=None, min_length=1, max_length=100)
    email: EmailStr | None = None
    full_name: str | None = Field(default=None, max_length=255)
    role: UserRole | None = None
    project_role: ProjectRole | None = None
    is_active: bool | None = None


class UserProfileUpdate(InputBaseModel):
    username: str | None = Field(default=None, min_length=1, max_length=100)
    email: EmailStr | None = None
    full_name: str | None = Field(default=None, max_length=255)


class OwnPasswordChangeRequest(InputBaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)


class PasswordResetOut(BaseModel):
    ok: bool = True
    email_sent_to: EmailStr
    mail_preview_url: str | None = None


class UserOut(ORMBase):
    id: int
    username: str
    email: EmailStr
    full_name: str | None = None
    avatar_url: str | None = None
    role: UserRole
    is_active: bool
    # Проектная роль (глобальная, настраивается в /members): lead открывает
    # доп. возможности в проектах, где пользователь участник.
    project_role: ProjectRole = ProjectRole.PENTESTER
    password_changed_at: datetime | None = None
    created_at: datetime


class ProjectCreate(InputBaseModel):
    name: str = Field(min_length=1, max_length=255)
    folder: str = Field(default="", max_length=255)
    description: str | None = None
    start_date: date | None = None
    end_date: date | None = None

    @model_validator(mode="after")
    def validate_dates(self) -> "ProjectCreate":
        if self.start_date and self.end_date and self.end_date < self.start_date:
            raise ValueError("Дата окончания проекта не может быть раньше даты начала")
        return self


class ProjectUpdate(InputBaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    folder: str | None = Field(default=None, max_length=255)
    description: str | None = None
    start_date: date | None = None
    end_date: date | None = None
    status: ProjectStatus | None = None

    @model_validator(mode="after")
    def validate_dates(self) -> "ProjectUpdate":
        if self.start_date and self.end_date and self.end_date < self.start_date:
            raise ValueError("Дата окончания проекта не может быть раньше даты начала")
        return self


class ProjectOut(ORMBase):
    id: int
    name: str
    folder: str
    description: str | None
    start_date: date | None
    end_date: date | None
    timeline_frozen_at: datetime | None
    status: ProjectStatus
    created_by: int
    created_at: datetime
    updated_at: datetime


class ProjectFolderCreate(InputBaseModel):
    name: str = Field(min_length=1, max_length=255)
    parent_id: int | None = None


class ProjectFolderMove(InputBaseModel):
    parent_id: int | None = None


class ProjectFolderOut(ORMBase):
    id: int
    name: str
    path: str
    parent_id: int | None
    created_by: int
    created_at: datetime
    updated_at: datetime


class ProjectMemberCreate(InputBaseModel):
    user_id: int


class ProjectMemberOut(BaseModel):
    user_id: int
    username: str
    email: EmailStr
    # Обе роли — глобальные пользовательские: аккаунтная и проектная.
    role: UserRole
    project_role: ProjectRole = ProjectRole.PENTESTER
    added_at: datetime


class JiraConfigUpsert(InputBaseModel):
    name: str = Field(default="default", min_length=1, max_length=255)
    base_url: str = Field(min_length=1, max_length=1024)
    email: EmailStr
    api_token: str | None = Field(default=None, min_length=1)
    default_issue_type: str = Field(default="Task", min_length=1, max_length=100)
    is_enabled: bool = True


class JiraConfigOut(ORMBase):
    id: int
    name: str
    base_url: str
    email: EmailStr
    default_issue_type: str
    is_enabled: bool
    created_by: int
    created_at: datetime
    updated_at: datetime


class ProjectJiraLinkUpsert(InputBaseModel):
    jira_project_key: str = Field(min_length=1, max_length=32)


class ProjectJiraLinkOut(ORMBase):
    id: int
    project_id: int
    jira_project_key: str
    created_by: int
    created_at: datetime
    updated_at: datetime


class JiraIssueLinkOut(ORMBase):
    id: int
    vulnerability_id: int
    jira_issue_key: str
    jira_issue_url: str
    status: str
    last_error: str | None
    created_at: datetime
    updated_at: datetime


class ProjectNoteCreate(InputBaseModel):
    title: str = Field(min_length=1, max_length=255)
    parent_id: int | None = None
    content: str | None = None


class ProjectNoteUpdate(InputBaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=255)
    content: str | None = None


class ProjectNoteMove(InputBaseModel):
    parent_id: int | None = None


class ProjectNoteReorderItem(InputBaseModel):
    id: int
    sort_order: int = Field(ge=0, le=100000)


class ProjectNoteReorder(InputBaseModel):
    parent_id: int | None = None
    items: list[ProjectNoteReorderItem] = Field(default_factory=list, min_length=1)


class ProjectNoteOut(ORMBase):
    id: int
    project_id: int
    parent_id: int | None
    title: str
    content: str | None
    sort_order: int
    created_by: int
    # Имя автора: /users только для админа, поэтому резолвим на бэке.
    created_by_username: str | None = None
    updated_by: int | None
    created_at: datetime
    updated_at: datetime


class HostIpAddressCreate(InputBaseModel):
    ip_address: str = Field(min_length=1, max_length=45)
    label: str | None = Field(default=None, max_length=100)
    is_primary: bool = False


class HostIpAddressUpdate(InputBaseModel):
    ip_address: str | None = Field(default=None, min_length=1, max_length=45)
    label: str | None = Field(default=None, max_length=100)
    is_primary: bool | None = None


class HostIpAddressOut(ORMBase):
    id: int
    host_id: int
    ip_address: str
    label: str | None
    is_primary: bool
    ports: list["PortOut"] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class HostCreate(InputBaseModel):
    ip_address: str | None = Field(default=None, max_length=45)
    """Алиас для обратной совместимости — попадает в primary IP при создании."""
    ip_addresses: list[str] = Field(default_factory=list)
    """Полный список IP-адресов хоста; первый помечается как primary."""
    hostname: str | None = Field(default=None, max_length=255)
    status: HostStatus = HostStatus.UNKNOWN
    os_type: OsType = OsType.UNKNOWN
    notes: str | None = None

    @model_validator(mode="after")
    def validate_target_defined(self) -> "HostCreate":
        # Унифицируем ip_address и ip_addresses в один список без дублей и пустот.
        merged: list[str] = []
        for raw in [self.ip_address, *self.ip_addresses]:
            if not raw:
                continue
            value = raw.strip()
            if value and value not in merged:
                merged.append(value)
        self.ip_addresses = merged
        if merged:
            self.ip_address = merged[0]
        if not self.ip_addresses and not self.hostname:
            raise ValueError("Нужно указать хотя бы один ip_address или hostname")
        return self


class HostUpdate(InputBaseModel):
    ip_address: str | None = Field(default=None, max_length=45)
    ip_addresses: list[HostIpAddressCreate] | None = None
    hostname: str | None = Field(default=None, max_length=255)
    status: HostStatus | None = None
    os_type: OsType | None = None
    notes: str | None = None


class HostOut(ORMBase):
    id: int
    project_id: int
    ip_address: str | None
    """Primary IP — синоним для is_primary=true записи в ip_addresses."""
    ip_addresses: list[HostIpAddressOut] = Field(default_factory=list)
    hostname: str | None
    status: HostStatus
    os_type: OsType = OsType.UNKNOWN
    notes: str | None
    created_at: datetime
    updated_at: datetime


class PortCreate(InputBaseModel):
    ip_address_id: int
    port_number: int = Field(ge=1, le=65535)
    protocol: Protocol = Protocol.TCP
    state: PortState = PortState.OPEN


class PortUpdate(InputBaseModel):
    ip_address_id: int | None = None
    port_number: int | None = Field(default=None, ge=1, le=65535)
    protocol: Protocol | None = None
    state: PortState | None = None


class PortOut(ORMBase):
    id: int
    host_id: int
    ip_address_id: int
    port_number: int
    protocol: Protocol
    state: PortState
    services: list["ServiceOut"] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class ServiceCreate(InputBaseModel):
    name: str = Field(min_length=1, max_length=100)
    version: str | None = Field(default=None, max_length=100)
    banner: str | None = None


class ServiceUpdate(InputBaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    version: str | None = Field(default=None, max_length=100)
    banner: str | None = None


class ServiceOut(ORMBase):
    id: int
    port_id: int
    name: str
    version: str | None
    banner: str | None
    created_at: datetime
    updated_at: datetime


PortOut.model_rebuild()
HostIpAddressOut.model_rebuild()


class EndpointQueryParam(InputBaseModel):
    # Длину имени параметра не ограничиваем — у некоторых API названия параметров
    # довольно длинные (полные имена флагов/фич). Минимум 1 — нужен непустой ключ.
    name: str = Field(min_length=1)
    value: str | None = None
    required: bool = False
    description: str | None = None


class EndpointRequestHeader(InputBaseModel):
    name: str = Field(min_length=1)
    value: str = ""


class EndpointCreate(InputBaseModel):
    path: str | None = Field(default=None, min_length=1)
    method: HttpMethod | None = None
    description: str | None = None
    request_raw: str | None = None
    query_params: list[EndpointQueryParam] = Field(default_factory=list)
    request_body: str | None = None
    request_content_type: str | None = Field(default=None, max_length=127)
    request_headers: list[EndpointRequestHeader] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_endpoint_target_defined(self) -> "EndpointCreate":
        if not self.path and not self.request_raw:
            raise ValueError("Нужно указать path или request_raw")
        return self


class EndpointUpdate(InputBaseModel):
    path: str | None = Field(default=None, min_length=1)
    method: HttpMethod | None = None
    description: str | None = None
    request_raw: str | None = None
    query_params: list[EndpointQueryParam] | None = None
    request_body: str | None = None
    request_content_type: str | None = Field(default=None, max_length=127)
    request_headers: list[EndpointRequestHeader] | None = None


class EndpointOut(ORMBase):
    id: int
    host_id: int
    path: str
    method: HttpMethod | None
    description: str | None
    query_params: list[EndpointQueryParam] = Field(default_factory=list)
    request_body: str | None
    request_content_type: str | None
    request_headers: list[EndpointRequestHeader] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime

    @field_validator("request_headers", "query_params", mode="before")
    @classmethod
    def _coerce_optional_list(cls, value: object) -> object:
        return value if value is not None else []


class VulnerabilityWorkflowStep(InputBaseModel):
    id: str = Field(min_length=1, max_length=100)
    description: str | None = None
    image_file_ids: list[int] = Field(default_factory=list)
    endpoint_id: int | None = None
    endpoint_request_raw: str | None = None


class VulnerabilityCreate(InputBaseModel):
    host_id: int
    title: str = Field(min_length=1, max_length=500)
    description: str | None = None
    severity: Severity
    cvss_version: CvssVersion | None = None
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: str | None = Field(default=None, max_length=255)
    cwe_id: str | None = Field(default=None, max_length=20)
    status: VulnerabilityStatus = VulnerabilityStatus.OPEN
    workflow_steps: list["VulnerabilityWorkflowStep"] = Field(default_factory=list)
    steps_to_reproduce: str | None = None
    impact: str | None = None
    recommendations: str | None = None

    @field_validator("cvss_version")
    @classmethod
    def validate_cvss_version(cls, value: CvssVersion | None) -> CvssVersion | None:
        if value is not None and value != CvssVersion.V40:
            raise ValueError("Поддерживается только CVSS 4.0")
        return value


class VulnerabilityUpdate(InputBaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=500)
    description: str | None = None
    severity: Severity | None = None
    cvss_version: CvssVersion | None = None
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: str | None = Field(default=None, max_length=255)
    cwe_id: str | None = Field(default=None, max_length=20)
    status: VulnerabilityStatus | None = None
    workflow_steps: list["VulnerabilityWorkflowStep"] | None = None
    steps_to_reproduce: str | None = None
    impact: str | None = None
    recommendations: str | None = None

    @field_validator("cvss_version")
    @classmethod
    def validate_cvss_version(cls, value: CvssVersion | None) -> CvssVersion | None:
        if value is not None and value != CvssVersion.V40:
            raise ValueError("Поддерживается только CVSS 4.0")
        return value


class VulnerabilityStatusPatch(InputBaseModel):
    status: VulnerabilityStatus


class VulnerabilityOut(ORMBase):
    id: int
    project_id: int
    title: str
    description: str | None
    severity: Severity
    cvss_version: CvssVersion | None
    cvss_score: float | None
    cvss_vector: str | None
    cwe_id: str | None
    status: VulnerabilityStatus
    workflow_steps: list["VulnerabilityWorkflowStep"] = Field(default_factory=list)
    steps_to_reproduce: str | None
    impact: str | None
    recommendations: str | None
    created_by: int
    # Имя автора: /users только для админа, поэтому резолвим на бэке.
    created_by_username: str | None = None
    created_at: datetime
    updated_at: datetime


class VulnerabilityAssetCreate(InputBaseModel):
    asset_type: AssetType
    asset_id: int


class VulnerabilityAssetOut(ORMBase):
    id: int
    vulnerability_id: int
    asset_type: AssetType
    asset_id: int


class FileOut(ORMBase):
    id: int
    original_name: str
    content_type: str
    size_bytes: int
    uploaded_by: int
    uploaded_at: datetime


class CommentCreate(InputBaseModel):
    content: str = Field(min_length=1)


class CommentUpdate(InputBaseModel):
    content: str = Field(min_length=1)


class MentionOut(BaseModel):
    user_id: int
    username: str


class CommentOut(ORMBase):
    id: int
    vulnerability_id: int
    user_id: int
    username: str
    avatar_url: str | None = None
    content: str
    mentions: list[MentionOut]
    created_at: datetime
    updated_at: datetime


class ProjectNoteCommentCreate(InputBaseModel):
    content: str = Field(min_length=1)


class ProjectNoteCommentUpdate(InputBaseModel):
    content: str = Field(min_length=1)


class ProjectNoteCommentOut(ORMBase):
    id: int
    project_id: int
    note_id: int
    user_id: int
    username: str
    avatar_url: str | None = None
    content: str
    created_at: datetime
    updated_at: datetime


class NotificationContext(BaseModel):
    vulnerability_id: int | None = None
    vulnerability_title: str | None = None
    # Поля для упоминаний в комментариях заметок (вместо уязвимостей).
    note_id: int | None = None
    note_title: str | None = None
    project_id: int | None = None
    project_name: str | None = None
    host_id: int | None = None
    # Кто инициировал событие: автор комментария либо тот, кто сменил статус.
    commenter_username: str | None = None
    # Выставленный статус — для уведомлений о смене статуса находки/проекта.
    status: str | None = None


class NotificationOut(ORMBase):
    id: int
    type: str
    comment_id: int | None
    # ID комментария заметки — для упоминаний в обсуждениях заметок.
    note_comment_id: int | None = None
    is_read: bool
    created_at: datetime
    context: NotificationContext | None = None


class UnreadCountOut(BaseModel):
    count: int


class ImportResult(BaseModel):
    hosts_created: int
    ports_created: int
    services_created: int
    endpoints_created: int
    errors: list[str]


class OpenApiImportResult(BaseModel):
    host_id: int
    spec_host: str | None = None
    endpoints_created: int
    endpoints_skipped: int
    errors: list[str] = Field(default_factory=list)


class PcfImportService(InputBaseModel):
    name: str = Field(min_length=1, max_length=255)
    version: str | None = Field(default=None, max_length=100)
    banner: str | None = None


class PcfImportPort(InputBaseModel):
    port_number: int = Field(ge=1, le=65535)
    protocol: Protocol = Protocol.TCP
    state: PortState = PortState.OPEN
    services: list[PcfImportService] = Field(default_factory=list)


class PcfImportEndpoint(InputBaseModel):
    path: str | None = Field(default=None, min_length=1)
    method: HttpMethod | None = None
    description: str | None = None
    request_raw: str | None = None
    query_params: list[EndpointQueryParam] = Field(default_factory=list)
    request_body: str | None = None
    request_content_type: str | None = Field(default=None, max_length=127)
    request_headers: list[EndpointRequestHeader] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_target_defined(self) -> "PcfImportEndpoint":
        if not self.path and not self.request_raw:
            raise ValueError("Каждый endpoint должен содержать path или request_raw")
        return self


class PcfImportHost(InputBaseModel):
    ip_address: str | None = Field(default=None, max_length=45)
    hostname: str | None = Field(default=None, max_length=255)
    status: HostStatus = HostStatus.UNKNOWN
    notes: str | None = None
    ports: list[PcfImportPort] = Field(default_factory=list)
    endpoints: list[PcfImportEndpoint] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_target_defined(self) -> "PcfImportHost":
        if not self.ip_address and not self.hostname:
            raise ValueError("Каждая запись host должна содержать ip_address или hostname")
        return self


class PcfImportPayload(InputBaseModel):
    hosts: list[PcfImportHost] = Field(default_factory=list)


class AuditLogOut(ORMBase):
    id: int
    user_id: int | None
    username: str | None = None
    action: str
    entity_type: str | None
    entity_id: int | None
    details: dict | None
    ip_address: str | None
    created_at: datetime
