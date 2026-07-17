/* Design tokens ported from the STORM prototype (PCF.dc.html).
   Colour pairs are {bg, color}; single dot/text colours are plain strings. */

import type { HostStatus, Method, PortState, Role, Severity, VStatus, WsRole } from "./data";

export interface ColorPair {
  bg: string;
  color: string;
}

/** Host status dot colours. */
export const STDOT: Record<HostStatus, string> = {
  up: "#3FA26B",
  down: "#C0455B",
  unknown: "#c99a2b",
};

/** Port pill colours by TCP/UDP state. */
export const PORT: Record<PortState, ColorPair> = {
  open: { bg: "#E7F5EE", color: "#2E8B57" },
  filtered: { bg: "#FBF1DF", color: "#B7862B" },
  closed: { bg: "#EEF1F6", color: "#8A97AB" },
};

/** HTTP method badge colours. */
export const METHOD: Record<Method, ColorPair> = {
  GET: { bg: "#E7F5EE", color: "#2E8B57" },
  POST: { bg: "#EAF0FC", color: "#2E5FBF" },
  PUT: { bg: "#F1ECFB", color: "#7A4DB8" },
  PATCH: { bg: "#FBF1DF", color: "#B7862B" },
  DELETE: { bg: "#FCEBED", color: "#C0455B" },
  QUERY: { bg: "#E4F6FA", color: "#1E8BA8" },
};

/** Severity badge colours. */
export const SEV: Record<Severity, ColorPair> = {
  critical: { bg: "#FCEBEE", color: "#C0455B" },
  high: { bg: "#FCEEE6", color: "#D9683C" },
  medium: { bg: "#FBF3E2", color: "#B7862B" },
  low: { bg: "#EAF0FC", color: "#2E5FBF" },
  info: { bg: "#EEF1F6", color: "#6b7a90" },
};

/** Vulnerability status dot/text colour. */
export const VSTATUS: Record<VStatus, string> = {
  open: "#C0455B",
  in_progress: "#B7862B",
  fixed: "#2E8B57",
  wont_fix: "#8A97AB",
  accepted_risk: "#7A4DB8",
};

/** Human labels for the backend's vulnerability statuses. */
export const VSTATUS_LABEL: Record<VStatus, string> = {
  open: "Open",
  in_progress: "In progress",
  fixed: "Fixed",
  wont_fix: "Won't fix",
  accepted_risk: "Accepted risk",
};

/** Statuses in the order they are offered in pickers and filters. */
export const VSTATUS_ORDER: VStatus[] = ["open", "in_progress", "fixed", "wont_fix", "accepted_risk"];

/** A finding still needing work — the "unresolved" filter and the open-count tile. */
export const VSTATUS_OPEN: VStatus[] = ["open", "in_progress"];

/** Default HTTP status shown per method in the endpoints view. */
export const EPSTATUS: Record<Method, string> = {
  GET: "200",
  POST: "201",
  PUT: "200",
  PATCH: "200",
  DELETE: "204",
  QUERY: "200",
};

/** Project status chip: label + colours + dot. Mirrors the backend's ProjectStatus. */
export const PROJ_STATUS: Record<string, { label: string; bg: string; color: string; dot: string }> = {
  active: { label: "Active", bg: "#E7F5EE", color: "#2E8B57", dot: "#3FA26B" },
  // Заморожен — голубой.
  freeze: { label: "Freeze", bg: "#E4F6FA", color: "#1E8BA8", dot: "#35B3D2" },
  handover_to_development: { label: "Handover to dev", bg: "#F1ECFB", color: "#7A4DB8", dot: "#9B72D8" },
  vulnerability_recheck: { label: "Recheck", bg: "#EAF0FC", color: "#2E5FBF", dot: "#4C74C7" },
  completed: { label: "Completed", bg: "#FBF3E2", color: "#B7862B", dot: "#E8A13C" },
  archived: { label: "Archived", bg: "#EEF1F6", color: "#8A97AB", dot: "#b3bccd" },
};

/** Project role badge colours. */
export const ROLE: Record<Role, ColorPair> = {
  lead: { bg: "#EAF0FC", color: "#2E5FBF" },
  pentester: { bg: "#E7F5EE", color: "#2E8B57" },
};

/** Workspace (account) role badge colours. */
export const WS_ROLE: Record<WsRole, ColorPair> = {
  admin: { bg: "#F1ECFB", color: "#7A4DB8" },
  user: { bg: "#EEF1F6", color: "#6b7a90" },
};

export const WS_ROLE_LABEL: Record<WsRole, string> = {
  admin: "Admin",
  user: "User",
};

/** Activity log tag colours (dark chips). */
export const ATAG: Record<string, ColorPair> = {
  new: { bg: "#1c3a2a", color: "#5FD597" },
  down: { bg: "#3a1f24", color: "#F1889A" },
  changed: { bg: "#3a3320", color: "#E8C05A" },
  dns: { bg: "#1f2c44", color: "#7FA8F0" },
};

/** Host-status summary tiles. */
export const HSTAT: Record<HostStatus, { label: string; color: string; bg: string }> = {
  up: { label: "Up", color: "#2E8B57", bg: "#E7F5EE" },
  down: { label: "Down", color: "#C0455B", bg: "#FBEAEC" },
  unknown: { label: "Unknown", color: "#B7862B", bg: "#FBF1DF" },
};

/** Vulnerability-status summary tiles. */
export const VSTAT: Record<VStatus, { label: string; color: string; bg: string }> = {
  open: { label: "Open", color: "#C0455B", bg: "#FBEAEC" },
  in_progress: { label: "In progress", color: "#B7862B", bg: "#FBF1DF" },
  fixed: { label: "Fixed", color: "#2E8B57", bg: "#E7F5EE" },
  wont_fix: { label: "Won't fix", color: "#8A97AB", bg: "#EEF1F6" },
  accepted_risk: { label: "Accepted risk", color: "#7A4DB8", bg: "#F1ECFB" },
};

/** Project-list "findings" badge colours. */
export const FINDING_SEV: Record<"none" | "med" | "high", { fBg: string; fColor: string; fDot: string }> = {
  none: { fBg: "#EEF1F6", fColor: "#8A97AB", fDot: "#c3ccda" },
  med: { fBg: "#FDF3E7", fColor: "#B26A16", fDot: "#E8A13C" },
  high: { fBg: "#FCEBED", fColor: "#C0455B", fDot: "#E0748A" },
};

export const API_SCOPES = ["read:hosts", "read:vulns", "write:notes", "write:vulns", "admin"];

/** Avatar colour rotation used when adding new project members. */
export const MEMBER_COLORS = ["#2E5FBF", "#2E8B57", "#7A4DB8", "#C06A2E"];

export type EditorType = "host" | "ip" | "endpoint" | "vuln" | "note" | "member";

export interface EditorField {
  k: string;
  label: string;
  /** `combo` = free-text input with type-to-search suggestions; use it instead of
      `select` when the option list can grow long (hosts, users). */
  type: "text" | "textarea" | "select" | "tags" | "combo";
  ph?: string;
  opts?: string[];
}

/* Every field here must map onto something the API stores — a field with no
   backend counterpart silently loses whatever the user typed on the next reload.
   `opts: []` is filled in at runtime from live data (hosts, workspace users). */
export const EDITOR_FIELDS: Record<EditorType, EditorField[]> = {
  host: [
    { k: "host", label: "Hostname", type: "text", ph: "e.g. app.acme-corp.com" },
    { k: "ip", label: "IP address", type: "text", ph: "e.g. 10.0.0.7" },
    // Ports hang off the host's IP, so they need one — see saveHostEditor.
    { k: "ports", label: "Ports", type: "tags", ph: "e.g. 443/tcp — press Enter" },
    { k: "status", label: "Status", type: "select", opts: ["up", "down", "unknown"] },
  ],
  // An IP always belongs to a host; `opts` is filled from the project's hosts.
  ip: [
    { k: "hostName", label: "Host", type: "combo", ph: "Начните вводить имя хоста…", opts: [] },
    { k: "ip", label: "IP address", type: "text", ph: "e.g. 10.0.0.7" },
    { k: "label", label: "Label", type: "text", ph: "external / internal / mgmt" },
  ],
  endpoint: [
    { k: "hostName", label: "Host", type: "combo", ph: "Начните вводить имя хоста…", opts: [] },
    { k: "method", label: "Method", type: "select", opts: ["GET", "POST", "PUT", "PATCH", "DELETE"] },
    { k: "path", label: "Path", type: "text", ph: "e.g. /api/users" },
  ],
  vuln: [
    { k: "title", label: "Title", type: "text", ph: "e.g. Stored XSS in comments" },
    // Searchable: a project can have many hosts, and a plain select is unusable then.
    { k: "host", label: "Affected host", type: "combo", ph: "Начните вводить имя хоста…", opts: [] },
    // Only on "add" — see saveVulnEditor: severity follows the CVSS vector afterwards.
    { k: "sev", label: "Severity", type: "select", opts: ["critical", "high", "medium", "low", "info"] },
    { k: "status", label: "Status", type: "select", opts: ["open", "in progress", "resolved"] },
  ],
  note: [
    { k: "title", label: "Title", type: "text", ph: "Note title" },
    { k: "excerpt", label: "Content", type: "textarea", ph: "Write your note…" },
  ],
  // The lead/pentester role is global and is set on the workspace Members page —
  // adding someone here only links an existing user to the project. Searchable:
  // a workspace can hold far more people than a dropdown is usable for.
  member: [{ k: "userKey", label: "User", type: "combo", ph: "Начните вводить username…", opts: [] }],
};

export const TYPELABEL: Record<EditorType, string> = {
  host: "host",
  ip: "IP address",
  endpoint: "endpoint",
  vuln: "vulnerability",
  note: "note",
  member: "member",
};
