/* Shapes rendered by the STORM UI.
 *
 * This module used to also carry the prototype's seed data (DETAIL / ALL /
 * NOTIFS / ACTIVITY). Everything the UI shows now comes from the backend, so
 * only the types remain — each entity carries its real backend id.
 */

export type PortState = "open" | "filtered" | "closed";
/** QUERY — метод из RFC-драфта httpbis; остальное — обычные глаголы. */
export type Method = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "QUERY";
export type HostStatus = "up" | "down" | "unknown";
/** Global project role — mirrors the backend's User.project_role. */
export type Role = "lead" | "pentester";
/** Workspace-level (account) role — separate from the project role. */
export type WsRole = "admin" | "user";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
/** Mirrors the backend's VulnerabilityStatus verbatim — no lossy re-mapping. */
export type VStatus = "open" | "in_progress" | "fixed" | "wont_fix" | "accepted_risk";
export type ProjectStatus = "active" | "archived";

export interface Port {
  n: number;
  proto: string;
  state: PortState;
  svc: string;
}

export interface Endpoint {
  /** Backend endpoint id — required to delete it through the API. */
  id: number;
  m: Method;
  p: string;
}

export interface Host {
  id: number;
  host: string;
  ip: string;
  status: HostStatus;
  /** Every IP of the host; `ip` above is the primary one. */
  ips: string[];
  ports: Port[];
  endpoints: Endpoint[];
}

export interface Member {
  /** Backend user id — required to remove the member through the API. */
  id: number;
  initials: string;
  name: string;
  email: string;
  role: Role;
  color: string;
}

export interface Vuln {
  /** Backend vulnerability id — used for deep links (/projects/{p}/vulns/{id}). */
  id: number;
  sev: Severity;
  title: string;
  host: string;
  status: VStatus;
  author: string;
  updated: string;
  steps?: string[];
  stepImages?: Record<number, string[]>;
  description?: string;
  impact?: string;
  remediation?: string;
  cwe?: string;
  vector?: string;
}

export interface Note {
  /** Backend project-note id. */
  id: number;
  title: string;
  when: string;
  excerpt: string;
  author: string;
}

/** The open project, assembled from the backend collections — a view, not a store. */
export interface ProjectDetail {
  status: ProjectStatus;
  desc: string;
  start: string;
  end: string;
  /** Percentage of the engagement window elapsed (derived from start/end). */
  progress: number;
  title: string;
  hosts: Host[];
  members: Member[];
  vulns: Vuln[];
  notes: Note[];
}

export interface WorkspaceUser {
  /** Backend user id — required to call the users API. */
  id: number;
  key: string;
  name: string;
  email: string;
  role: WsRole;
  projectRole: Role;
}

export interface ApiKey {
  id: number;
  name: string;
  key: string;
  scopes: string[];
  created: string;
}
