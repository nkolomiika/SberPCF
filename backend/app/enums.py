import enum


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    PENTESTER = "pentester"


class ProjectStatus(str, enum.Enum):
    ACTIVE = "active"
    HANDOVER_TO_DEVELOPMENT = "handover_to_development"
    VULNERABILITY_RECHECK = "vulnerability_recheck"
    COMPLETED = "completed"
    ARCHIVED = "archived"


class HostStatus(str, enum.Enum):
    UP = "up"
    DOWN = "down"
    UNKNOWN = "unknown"


class OsType(str, enum.Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    FREEBSD = "freebsd"
    ANDROID = "android"
    IOS = "ios"
    OTHER = "other"
    UNKNOWN = "unknown"


class Protocol(str, enum.Enum):
    TCP = "tcp"
    UDP = "udp"


class PortState(str, enum.Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class HttpMethod(str, enum.Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CvssVersion(str, enum.Enum):
    V31 = "3.1"
    V40 = "4.0"


class VulnerabilityStatus(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"
    WONT_FIX = "wont_fix"
    ACCEPTED_RISK = "accepted_risk"


class AssetType(str, enum.Enum):
    HOST = "host"
    PORT = "port"
    SERVICE = "service"
    ENDPOINT = "endpoint"


class NotificationType(str, enum.Enum):
    MENTION = "mention"
