export type UserRole = "admin" | "pentester";

export interface User {
  id: number;
  username: string;
  email: string;
  full_name: string | null;
  avatar_url: string | null;
  role: UserRole;
  /**
   * Global project role. "lead" unlocks team management inside the projects the
   * user is a member of; it is configured workspace-wide on the members page.
   */
  project_role: "lead" | "pentester";
  is_active: boolean;
  password_changed_at: string | null;
  created_at: string;
}

export interface AuthLoginResponse {
  id: number;
  username: string;
  role: UserRole;
}

export interface PasswordResetResult {
  ok: boolean;
  email_sent_to: string;
  mail_preview_url: string | null;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

export type ProjectStatus =
  | "active"
  /** Работы приостановлены — проект не активен, но и не завершён. */
  | "freeze"
  | "handover_to_development"
  | "vulnerability_recheck"
  | "completed"
  | "archived";

export interface Project {
  id: number;
  name: string;
  folder: string;
  description: string | null;
  start_date: string | null;
  end_date: string | null;
  timeline_frozen_at: string | null;
  status: ProjectStatus;
  created_by: number;
  created_at: string;
  updated_at: string;
}

export interface ProjectStats {
  project_id: number;
  status: ProjectStatus;
  hosts_count: number;
  total_findings: number;
  open_findings: number;
}

export interface ProjectFolder {
  id: number;
  name: string;
  path: string;
  parent_id: number | null;
  created_by: number;
  created_at: string;
  updated_at: string;
}

export interface ProjectMember {
  user_id: number;
  username: string;
  email: string;
  role: UserRole;
  /** Глобальная проектная роль пользователя — настраивается на странице /members. */
  project_role: "lead" | "pentester";
  added_at: string;
}

/** Событие ленты активности проекта (`GET /projects/{id}/activity`). */
export interface ProjectActivityItem {
  id: number;
  action: string;
  entity_type: string | null;
  entity_id: number | null;
  user_id: number | null;
  username: string | null;
  /** Для уязвимостей — название и severity; у остальных сущностей null. */
  title: string | null;
  severity: Vulnerability["severity"] | null;
  /** Ссылка на карточку сущности, например /projects/1/vulns/7. */
  url: string | null;
  details: Record<string, unknown> | null;
  created_at: string | null;
}

export interface ProjectNote {
  id: number;
  project_id: number;
  parent_id: number | null;
  title: string;
  content: string | null;
  sort_order: number;
  created_by: number;
  /** Имя автора — бэкенд резолвит его сам, т.к. /users доступен только админу. */
  created_by_username: string | null;
  updated_by: number | null;
  created_at: string;
  updated_at: string;
}

export interface ProjectNoteComment {
  id: number;
  project_id: number;
  note_id: number;
  user_id: number;
  username: string;
  avatar_url: string | null;
  content: string;
  created_at: string;
  updated_at: string;
}

export interface HostIpAddress {
  id: number;
  host_id: number;
  ip_address: string;
  label: string | null;
  is_primary: boolean;
  ports: Port[];
  created_at: string;
  updated_at: string;
}

export type OsType =
  | "windows"
  | "linux"
  | "macos"
  | "freebsd"
  | "android"
  | "ios"
  | "other"
  | "unknown";

export const OS_TYPE_OPTIONS: { value: OsType; label: string }[] = [
  { value: "windows", label: "Windows" },
  { value: "linux", label: "Linux" },
  { value: "macos", label: "macOS" },
  { value: "freebsd", label: "FreeBSD" },
  { value: "android", label: "Android" },
  { value: "ios", label: "iOS" },
  { value: "other", label: "Другая" },
];

export interface Host {
  id: number;
  project_id: number;
  ip_address: string | null;
  ip_addresses: HostIpAddress[];
  hostname: string | null;
  status: "up" | "down" | "unknown";
  os_type: OsType;
  notes: string | null;
  created_at: string;
  updated_at: string;
}

export interface HostDetails extends Host {
  endpoints: Endpoint[];
}

export interface HostTreeStats {
  portsCount: number;
  ipAddressesCount: number;
  endpointsCount: number;
  vulnerabilitiesCount: number;
}

export interface Port {
  id: number;
  host_id: number;
  ip_address_id: number;
  port_number: number;
  protocol: "tcp" | "udp";
  state: "open" | "closed" | "filtered";
  /** Сервисы порта — бэкенд отдаёт их вместе с портом (PortOut.services). */
  services: Service[];
  created_at: string;
  updated_at: string;
}

export interface Service {
  id: number;
  port_id: number;
  name: string;
  version: string | null;
  banner: string | null;
  created_at: string;
  updated_at: string;
}

export interface EndpointRequestHeader {
  name: string;
  value: string;
}

export interface Endpoint {
  id: number;
  host_id: number;
  path: string;
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" | "QUERY" | null;
  description: string | null;
  query_params: EndpointQueryParam[];
  request_body: string | null;
  request_content_type: string | null;
  request_headers?: EndpointRequestHeader[];
  created_at: string;
  updated_at: string;
}

export interface EndpointQueryParam {
  name: string;
  value: string | null;
  required: boolean;
  description: string | null;
}

export interface Vulnerability {
  id: number;
  project_id: number;
  title: string;
  description: string | null;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "open" | "in_progress" | "fixed" | "wont_fix" | "accepted_risk";
  cvss_version: "4.0" | null;
  cvss_score: number | null;
  cvss_vector: string | null;
  cwe_id: string | null;
  workflow_steps: VulnerabilityWorkflowStep[];
  steps_to_reproduce: string | null;
  impact: string | null;
  recommendations: string | null;
  created_by: number;
  /** Имя автора — бэкенд резолвит его сам, т.к. /users доступен только админу. */
  created_by_username: string | null;
  created_at: string;
  updated_at: string;
}

export interface VulnerabilityWorkflowStep {
  id: string;
  description: string | null;
  image_file_ids: number[];
  endpoint_id: number | null;
  endpoint_request_raw: string | null;
}

export interface VulnerabilityAsset {
  id: number;
  vulnerability_id: number;
  asset_type: "host" | "port" | "service" | "endpoint";
  asset_id: number;
}

export interface VulnerabilityFile {
  id: number;
  original_name: string;
  content_type: string;
  size_bytes: number;
  uploaded_by: number;
  uploaded_at: string;
}

export interface Mention {
  user_id: number;
  username: string;
}

export interface VulnerabilityComment {
  id: number;
  vulnerability_id: number;
  user_id: number;
  username: string;
  avatar_url: string | null;
  content: string;
  mentions: Mention[];
  created_at: string;
  updated_at: string;
}

export interface VulnerabilityDetails extends Vulnerability {
  assets: VulnerabilityAsset[];
  files: VulnerabilityFile[];
  comments_count: number;
}

export interface ImportResult {
  hosts_created: number;
  ports_created: number;
  services_created: number;
  endpoints_created: number;
  errors: string[];
}

export interface OpenApiImportResult {
  host_id: number;
  spec_host: string | null;
  endpoints_created: number;
  endpoints_skipped: number;
  errors: string[];
}

/** Поводы для уведомления — ровно те четыре, что создаёт бэкенд (NotificationType). */
export type NotificationKind =
  /** Упоминание @username в комментарии к находке или заметке. */
  | "mention"
  /** Пользователя добавили в проект. */
  | "project_member_added"
  /** Изменился статус находки, которую он завёл. */
  | "vuln_status_changed"
  /** Изменился статус проекта, в котором он состоит. */
  | "project_status_changed";

export interface Notification {
  id: number;
  type: NotificationKind;
  comment_id: number | null;
  note_comment_id: number | null;
  is_read: boolean;
  created_at: string;
  context: {
    vulnerability_id: number | null;
    vulnerability_title: string | null;
    note_id: number | null;
    note_title: string | null;
    project_id: number | null;
    project_name: string | null;
    host_id: number | null;
    /** Кто это сделал: автор комментария либо тот, кто сменил статус. */
    commenter_username: string | null;
    /** Выставленный статус — у уведомлений о смене статуса. */
    status: string | null;
  } | null;
}

export interface AgentApiToken {
  id: number;
  name: string;
  token_prefix: string;
  scopes: string[];
  all_projects: boolean;
  created_by: number;
  expires_at: string | null;
  revoked_at: string | null;
  last_used_at: string | null;
  created_at: string;
  updated_at: string;
  project_ids: number[];
}

export interface AuditLog {
  id: number;
  user_id: number | null;
  username: string | null;
  action: string;
  entity_type: string | null;
  entity_id: number | null;
  details: Record<string, unknown> | null;
  ip_address: string | null;
  created_at: string;
}
