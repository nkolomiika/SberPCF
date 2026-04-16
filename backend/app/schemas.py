from datetime import date, datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, model_validator

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


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=128)


class LoginResponse(BaseModel):
    id: UUID
    username: str
    role: UserRole


class RefreshResponse(BaseModel):
    ok: bool = True


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    role: UserRole = UserRole.PENTESTER


class UserUpdate(BaseModel):
    username: str | None = Field(default=None, min_length=1, max_length=100)
    email: EmailStr | None = None
    role: UserRole | None = None
    is_active: bool | None = None


class PasswordResetRequest(BaseModel):
    new_password: str = Field(min_length=8, max_length=128)


class UserOut(ORMBase):
    id: UUID
    username: str
    email: EmailStr
    role: UserRole
    is_active: bool
    created_at: datetime


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    folder: str = Field(default="Без папки", min_length=1, max_length=255)
    description: str | None = None
    start_date: date | None = None
    end_date: date | None = None

    @model_validator(mode="after")
    def validate_dates(self) -> "ProjectCreate":
        if self.start_date and self.end_date and self.end_date < self.start_date:
            raise ValueError("Дата окончания проекта не может быть раньше даты начала")
        return self


class ProjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    folder: str | None = Field(default=None, min_length=1, max_length=255)
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
    status: ProjectStatus
    created_by: UUID
    created_at: datetime
    updated_at: datetime


class ProjectFolderCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    parent_id: UUID | None = None


class ProjectFolderMove(BaseModel):
    parent_id: UUID | None = None


class ProjectFolderOut(ORMBase):
    id: UUID
    name: str
    path: str
    parent_id: UUID | None
    created_by: UUID
    created_at: datetime
    updated_at: datetime


class ProjectMemberCreate(BaseModel):
    user_id: UUID


class ProjectMemberOut(BaseModel):
    user_id: UUID
    username: str
    email: EmailStr
    role: UserRole
    added_at: datetime


class HostCreate(BaseModel):
    ip_address: str | None = Field(default=None, max_length=45)
    hostname: str | None = Field(default=None, max_length=255)
    status: HostStatus = HostStatus.UNKNOWN
    notes: str | None = None

    @model_validator(mode="after")
    def validate_target_defined(self) -> "HostCreate":
        if not self.ip_address and not self.hostname:
            raise ValueError("Нужно указать ip_address или hostname")
        return self


class HostUpdate(BaseModel):
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


class PortCreate(BaseModel):
    port_number: int = Field(ge=1, le=65535)
    protocol: Protocol = Protocol.TCP
    state: PortState = PortState.OPEN


class PortUpdate(BaseModel):
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


class ServiceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    version: str | None = Field(default=None, max_length=100)
    banner: str | None = None


class ServiceUpdate(BaseModel):
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


class EndpointCreate(BaseModel):
    path: str | None = Field(default=None, min_length=1)
    method: HttpMethod | None = None
    description: str | None = None
    request_raw: str | None = None

    @model_validator(mode="after")
    def validate_endpoint_target_defined(self) -> "EndpointCreate":
        if not self.path and not self.request_raw:
            raise ValueError("Нужно указать path или request_raw")
        return self


class EndpointUpdate(BaseModel):
    path: str | None = Field(default=None, min_length=1)
    method: HttpMethod | None = None
    description: str | None = None
    request_raw: str | None = None


class EndpointOut(ORMBase):
    id: UUID
    host_id: UUID
    path: str
    method: HttpMethod | None
    description: str | None
    created_at: datetime
    updated_at: datetime


class VulnerabilityCreate(BaseModel):
    title: str = Field(min_length=1, max_length=500)
    description: str | None = None
    severity: Severity
    cvss_version: CvssVersion | None = None
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: str | None = Field(default=None, max_length=255)
    cwe_id: str | None = Field(default=None, max_length=20)
    status: VulnerabilityStatus = VulnerabilityStatus.OPEN
    steps_to_reproduce: str | None = None
    impact: str | None = None
    recommendations: str | None = None


class VulnerabilityUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=500)
    description: str | None = None
    severity: Severity | None = None
    cvss_version: CvssVersion | None = None
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: str | None = Field(default=None, max_length=255)
    cwe_id: str | None = Field(default=None, max_length=20)
    status: VulnerabilityStatus | None = None
    steps_to_reproduce: str | None = None
    impact: str | None = None
    recommendations: str | None = None


class VulnerabilityStatusPatch(BaseModel):
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
    steps_to_reproduce: str | None
    impact: str | None
    recommendations: str | None
    created_by: UUID
    created_at: datetime
    updated_at: datetime


class VulnerabilityAssetCreate(BaseModel):
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


class CommentCreate(BaseModel):
    content: str = Field(min_length=1)


class CommentUpdate(BaseModel):
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
