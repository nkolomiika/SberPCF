from datetime import date, datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, ValidationInfo, field_validator, model_validator

from app.enums import (
    AssetType,
    CvssVersion,
    HostStatus,
    HttpMethod,
    PortState,
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
    id: UUID
    username: str
    role: UserRole
    must_change_password: bool


class RefreshResponse(BaseModel):
    ok: bool = True
    must_change_password: bool = False


class UserCreate(InputBaseModel):
    username: str = Field(min_length=1, max_length=100)
    email: EmailStr
    full_name: str | None = Field(default=None, max_length=255)
    tags: list[str] = Field(default_factory=list)
    password: str | None = Field(default=None, min_length=8, max_length=128)
    role: UserRole = UserRole.PENTESTER
    send_invite_email: bool = False


class UserUpdate(InputBaseModel):
    username: str | None = Field(default=None, min_length=1, max_length=100)
    email: EmailStr | None = None
    full_name: str | None = Field(default=None, max_length=255)
    tags: list[str] | None = None
    role: UserRole | None = None
    is_active: bool | None = None


class UserProfileUpdate(InputBaseModel):
    username: str | None = Field(default=None, min_length=1, max_length=100)
    email: EmailStr | None = None
    full_name: str | None = Field(default=None, max_length=255)
    tags: list[str] | None = None


class OwnPasswordChangeRequest(InputBaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)


class ForceChangePasswordRequest(InputBaseModel):
    new_password: str = Field(min_length=8, max_length=128)


class PasswordResetOut(BaseModel):
    ok: bool = True
    email_sent_to: EmailStr
    must_change_password: bool = True
    mail_preview_url: str | None = None


class UserOut(ORMBase):
    id: UUID
    username: str
    email: EmailStr
    full_name: str | None = None
    tags: list[str] = Field(default_factory=list)
    avatar_url: str | None = None
    role: UserRole
    is_active: bool
    must_change_password: bool = False
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
    id: UUID
    name: str
    folder: str
    description: str | None
    start_date: date | None
    end_date: date | None
    timeline_frozen_at: datetime | None
    status: ProjectStatus
    created_by: UUID
    created_at: datetime
    updated_at: datetime


class ProjectFolderCreate(InputBaseModel):
    name: str = Field(min_length=1, max_length=255)
    parent_id: UUID | None = None


class ProjectFolderMove(InputBaseModel):
    parent_id: UUID | None = None


class ProjectFolderOut(ORMBase):
    id: UUID
    name: str
    path: str
    parent_id: UUID | None
    created_by: UUID
    created_at: datetime
    updated_at: datetime


class ProjectMemberCreate(InputBaseModel):
    user_id: UUID


class ProjectMemberOut(BaseModel):
    user_id: UUID
    username: str
    email: EmailStr
    role: UserRole
    added_at: datetime


class HostCreate(InputBaseModel):
    ip_address: str | None = Field(default=None, max_length=45)
    hostname: str | None = Field(default=None, max_length=255)
    status: HostStatus = HostStatus.UNKNOWN
    notes: str | None = None

    @model_validator(mode="after")
    def validate_target_defined(self) -> "HostCreate":
        if not self.ip_address and not self.hostname:
            raise ValueError("Нужно указать ip_address или hostname")
        return self


class HostUpdate(InputBaseModel):
    ip_address: str | None = Field(default=None, max_length=45)
    hostname: str | None = Field(default=None, max_length=255)
    status: HostStatus | None = None
    notes: str | None = None


class HostOut(ORMBase):
    id: UUID
    project_id: UUID
    ip_address: str | None
    hostname: str | None
    status: HostStatus
    notes: str | None
    created_at: datetime
    updated_at: datetime


class PortCreate(InputBaseModel):
    port_number: int = Field(ge=1, le=65535)
    protocol: Protocol = Protocol.TCP
    state: PortState = PortState.OPEN


class PortUpdate(InputBaseModel):
    port_number: int | None = Field(default=None, ge=1, le=65535)
    protocol: Protocol | None = None
    state: PortState | None = None


class PortOut(ORMBase):
    id: UUID
    host_id: UUID
    port_number: int
    protocol: Protocol
    state: PortState
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
    id: UUID
    port_id: UUID
    name: str
    version: str | None
    banner: str | None
    created_at: datetime
    updated_at: datetime


class EndpointQueryParam(InputBaseModel):
    name: str = Field(min_length=1, max_length=200)
    value: str | None = None
    required: bool = False
    description: str | None = None


class EndpointRequestHeader(InputBaseModel):
    name: str = Field(min_length=1, max_length=200)
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
    id: UUID
    host_id: UUID
    path: str
    method: HttpMethod | None
    description: str | None
    query_params: list[EndpointQueryParam] = Field(default_factory=list)
    request_body: str | None
    request_content_type: str | None
    request_headers: list[EndpointRequestHeader] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime

    @field_validator("request_headers", mode="before")
    @classmethod
    def _coerce_request_headers(cls, value: object) -> object:
        return value if value is not None else []


class VulnerabilityWorkflowStep(InputBaseModel):
    id: str = Field(min_length=1, max_length=100)
    title: str = Field(min_length=1, max_length=500)
    description: str | None = None
    image_file_ids: list[UUID] = Field(default_factory=list)
    endpoint_id: UUID | None = None
    endpoint_request_raw: str | None = None


class VulnerabilityCreate(InputBaseModel):
    host_id: UUID
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


class VulnerabilityStatusPatch(InputBaseModel):
    status: VulnerabilityStatus


class VulnerabilityOut(ORMBase):
    id: UUID
    project_id: UUID
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
    created_by: UUID
    created_at: datetime
    updated_at: datetime


class VulnerabilityAssetCreate(InputBaseModel):
    asset_type: AssetType
    asset_id: UUID


class VulnerabilityAssetOut(ORMBase):
    id: UUID
    vulnerability_id: UUID
    asset_type: AssetType
    asset_id: UUID


class FileOut(ORMBase):
    id: UUID
    original_name: str
    content_type: str
    size_bytes: int
    uploaded_by: UUID
    uploaded_at: datetime


class CommentCreate(InputBaseModel):
    content: str = Field(min_length=1)


class CommentUpdate(InputBaseModel):
    content: str = Field(min_length=1)


class MentionOut(BaseModel):
    user_id: UUID
    username: str


class CommentOut(ORMBase):
    id: UUID
    vulnerability_id: UUID
    user_id: UUID
    username: str
    content: str
    mentions: list[MentionOut]
    created_at: datetime
    updated_at: datetime


class NotificationContext(BaseModel):
    vulnerability_id: UUID | None = None
    vulnerability_title: str | None = None
    project_id: UUID | None = None
    host_id: UUID | None = None
    commenter_username: str | None = None


class NotificationOut(ORMBase):
    id: UUID
    type: str
    comment_id: UUID | None
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
    host_id: UUID
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
    id: UUID
    user_id: UUID | None
    username: str | None = None
    action: str
    entity_type: str | None
    entity_id: UUID | None
    details: dict | None
    ip_address: str | None
    created_at: datetime
