export type UserRole = "admin" | "pentester";

export interface User {
  id: string;
  username: string;
  email: string;
  full_name: string | null;
  avatar_url: string | null;
  role: UserRole;
  is_active: boolean;
  must_change_password: boolean;
  password_changed_at: string | null;
  created_at: string;
}

export interface AuthLoginResponse {
  id: string;
  username: string;
  role: UserRole;
  must_change_password: boolean;
}

export interface PasswordResetResult {
  ok: boolean;
  email_sent_to: string;
  must_change_password: boolean;
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
  | "handover_to_development"
  | "vulnerability_recheck"
  | "completed"
  | "archived";

export interface Project {
  id: string;
  name: string;
  folder: string;
  description: string | null;
  start_date: string | null;
  end_date: string | null;
  timeline_frozen_at: string | null;
  status: ProjectStatus;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface ProjectFolder {
  id: string;
  name: string;
  path: string;
  parent_id: string | null;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface ProjectMember {
  user_id: string;
  username: string;
  email: string;
  role: UserRole;
  added_at: string;
}

export interface ProjectNote {
  id: string;
  project_id: string;
  parent_id: string | null;
  title: string;
  content: string | null;
  sort_order: number;
  created_by: string;
  updated_by: string | null;
  created_at: string;
  updated_at: string;
}

export interface ProjectNoteComment {
  id: string;
  project_id: string;
  note_id: string;
  user_id: string;
  username: string;
  avatar_url: string | null;
  content: string;
  created_at: string;
  updated_at: string;
}

export interface HostIpAddress {
  id: string;
  host_id: string;
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
  id: string;
  project_id: string;
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
  id: string;
  host_id: string;
  ip_address_id: string;
  port_number: number;
  protocol: "tcp" | "udp";
  state: "open" | "closed" | "filtered";
  created_at: string;
  updated_at: string;
}

export interface Service {
  id: string;
  port_id: string;
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
  id: string;
  host_id: string;
  path: string;
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" | null;
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
  id: string;
  project_id: string;
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
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface VulnerabilityWorkflowStep {
  id: string;
  description: string | null;
  image_file_ids: string[];
  endpoint_id: string | null;
  endpoint_request_raw: string | null;
}

export interface VulnerabilityAsset {
  id: string;
  vulnerability_id: string;
  asset_type: "host" | "port" | "service" | "endpoint";
  asset_id: string;
}

export interface VulnerabilityFile {
  id: string;
  original_name: string;
  content_type: string;
  size_bytes: number;
  uploaded_by: string;
  uploaded_at: string;
}

export interface Mention {
  user_id: string;
  username: string;
}

export interface VulnerabilityComment {
  id: string;
  vulnerability_id: string;
  user_id: string;
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
  host_id: string;
  spec_host: string | null;
  endpoints_created: number;
  endpoints_skipped: number;
  errors: string[];
}

export interface Notification {
  id: string;
  type: string;
  comment_id: string | null;
  note_comment_id: string | null;
  is_read: boolean;
  created_at: string;
  context: {
    vulnerability_id: string | null;
    vulnerability_title: string | null;
    note_id: string | null;
    note_title: string | null;
    project_id: string | null;
    host_id: string | null;
    commenter_username: string | null;
  } | null;
}

export interface AgentApiToken {
  id: string;
  name: string;
  token_prefix: string;
  scopes: string[];
  all_projects: boolean;
  created_by: string;
  expires_at: string | null;
  revoked_at: string | null;
  last_used_at: string | null;
  created_at: string;
  updated_at: string;
  project_ids: string[];
}

export interface AuditLog {
  id: string;
  user_id: string | null;
  username: string | null;
  action: string;
  entity_type: string | null;
  entity_id: string | null;
  details: Record<string, unknown> | null;
  ip_address: string | null;
  created_at: string;
}
