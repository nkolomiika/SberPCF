export type UserRole = "admin" | "pentester" | "developer";

export interface User {
  id: string;
  username: string;
  email: string;
  full_name: string | null;
  tags: string[];
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
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

export interface Project {
  id: string;
  name: string;
  folder: string;
  description: string | null;
  start_date: string | null;
  end_date: string | null;
  status: "active" | "completed" | "archived";
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

export interface Host {
  id: string;
  project_id: string;
  ip_address: string | null;
  hostname: string | null;
  status: "up" | "down" | "unknown";
  notes: string | null;
  created_at: string;
  updated_at: string;
}

export interface HostDetails extends Host {
  ports: Port[];
  endpoints: Endpoint[];
}

export interface HostTreeStats {
  portsCount: number;
  endpointsCount: number;
  vulnerabilitiesCount: number;
}

export interface Port {
  id: string;
  host_id: string;
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

export interface Endpoint {
  id: string;
  host_id: string;
  path: string;
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" | null;
  description: string | null;
  created_at: string;
  updated_at: string;
}

export interface Vulnerability {
  id: string;
  project_id: string;
  title: string;
  description: string | null;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "open" | "in_progress" | "fixed" | "wont_fix" | "accepted_risk";
  cvss_version: "3.1" | "4.0" | null;
  cvss_score: number | null;
  cvss_vector: string | null;
  cwe_id: string | null;
  steps_to_reproduce: string | null;
  impact: string | null;
  recommendations: string | null;
  created_by: string;
  created_at: string;
  updated_at: string;
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

export interface Notification {
  id: string;
  type: string;
  comment_id: string | null;
  is_read: boolean;
  created_at: string;
  context: {
    vulnerability_id: string | null;
    vulnerability_title: string | null;
    project_id: string | null;
    commenter_username: string | null;
  } | null;
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
