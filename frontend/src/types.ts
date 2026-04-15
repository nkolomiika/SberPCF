export type UserRole = "admin" | "pentester";

export interface User {
  id: string;
  username: string;
  email: string;
  role: UserRole;
  is_active: boolean;
  created_at: string;
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
  description: string | null;
  start_date: string | null;
  end_date: string | null;
  status: "active" | "completed" | "archived";
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface Host {
  id: string;
  project_id: string;
  ip_address: string | null;
  hostname: string | null;
  os: string | null;
  status: "up" | "down" | "unknown";
  notes: string | null;
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
