/* STORM — Offensive Security Research & Management Console.
   React port of the design prototype (PCF.dc.html). Every collection it renders
   is loaded from the backend; data.ts carries the view shapes only. */

import {
  lazy,
  Suspense,
  useEffect,
  useRef,
  useState,
  type ChangeEvent,
  type ClipboardEvent as ReactClipboardEvent,
  type CSSProperties,
  type KeyboardEvent as ReactKeyboardEvent,
  type MouseEvent as ReactMouseEvent,
  type ReactNode,
} from "react";
import { useLocation, useNavigate } from "react-router-dom";
import "./storm.css";
import { Icon, SberMark } from "./icons";

/* TipTap/ProseMirror is ~460 kB — more than the rest of the app put together, and
   only the note editor needs it. Loading it on demand keeps that weight off every
   other screen. */
const StormMarkdownEditor = lazy(() => import("./StormMarkdownEditor"));
import { useAuthStore, useToastStore } from "../store";
import {
  getApiErrorMessage,
  getApiErrorStatus,
  getProjects,
  getProjectStats,
  getUsers,
  createProject as apiCreateProject,
  updateProject as apiUpdateProject,
  deleteProject as apiDeleteProject,
  createUser as apiCreateUser,
  updateUser as apiUpdateUser,
  deleteUser as apiDeleteUser,
  getHosts as apiGetHosts,
  getHost as apiGetHost,
  createHost as apiCreateHost,
  updateHost as apiUpdateHost,
  deleteHost as apiDeleteHost,
  createPort as apiCreatePort,
  createEndpoint as apiCreateEndpoint,
  updateEndpoint as apiUpdateEndpoint,
  getEndpoints as apiGetEndpoints,
  deleteEndpoint as apiDeleteEndpoint,
  getProjectMembers as apiGetProjectMembers,
  addProjectMember as apiAddProjectMember,
  removeProjectMember as apiRemoveProjectMember,
  getVulnerabilities as apiGetVulnerabilities,
  getVulnerability as apiGetVulnerability,
  createVulnerability as apiCreateVulnerability,
  updateVulnerability as apiUpdateVulnerability,
  deleteVulnerability as apiDeleteVulnerability,
  addVulnerabilityAsset as apiAddVulnerabilityAsset,
  deleteVulnerabilityAsset as apiDeleteVulnerabilityAsset,
  listProjectNotes as apiListProjectNotes,
  createProjectNote as apiCreateProjectNote,
  updateProjectNote as apiUpdateProjectNote,
  deleteProjectNote as apiDeleteProjectNote,
  getProjectActivity as apiGetProjectActivity,
  listNotifications as apiListNotifications,
  markNotificationRead as apiMarkNotificationRead,
  markAllNotificationsRead as apiMarkAllNotificationsRead,
  listAgentTokens as apiListAgentTokens,
  createAgentToken as apiCreateAgentToken,
  revokeAgentToken as apiRevokeAgentToken,
  downloadProjectCertificationReport as apiDownloadCertificationReport,
  downloadProjectAcceptanceReport as apiDownloadAcceptanceReport,
} from "../api";
import { calculateCvssScore, severityFromCvssScore } from "../cvss";
import { PROJECT_STATUS_ORDER } from "../projectStatus";
import type {
  Notification as ApiNotification,
  ProjectActivityItem,
  ProjectMember as ApiProjectMember,
  ProjectNote,
  ProjectStats,
  ProjectStatus,
  Endpoint as ApiEndpoint,
  Host as ApiHost,
  Port as ApiPort,
  Service as ApiService,
  Vulnerability as ApiVulnerability,
} from "../types";
import {
  type ApiKey,
  type Endpoint,
  type Host,
  type Member,
  type Method,
  type Note,
  type ProjectDetail,
  type Role,
  type Severity,
  type Vuln,
  type VStatus,
  type WorkspaceUser,
  type WsRole,
} from "./data";
import {
  API_SCOPES,
  EDITOR_FIELDS,
  EPSTATUS,
  FINDING_SEV,
  MEMBER_COLORS,
  METHOD,
  PORT,
  PROJ_STATUS,
  ROLE,
  SEV,
  STDOT,
  TYPELABEL,
  VSTATUS,
  VSTATUS_LABEL,
  VSTATUS_OPEN,
  VSTATUS_ORDER,
  WS_ROLE,
  WS_ROLE_LABEL,
  type EditorType,
} from "./tokens";

type NavId = "projects" | "tasks" | "mine" | "docs" | "members";
type ViewId = "list" | "detail" | "profile" | "workspaceMembers";
type SectionId = "overview" | "hosts" | "vulns" | "notes" | "members" | "activity";
type ReconView = "hosts" | "ips" | "endpoints";
type ProfileTab = "account" | "security" | "api";
/** Word report templates the backend can generate (POST /projects/{id}/reports/{kind}). */
type ReportKind = "szi" | "pp";
/** What the export dialog exports: the project report, or one of the recon lists. */
type ExportScope = "report" | "hosts" | "ips" | "endpoints";
const REPORT_KINDS: { kind: ReportKind; title: string; desc: string }[] = [
  { kind: "szi", title: "Отчёт для сертификации", desc: "Отчёт по результатам испытаний СЗИ — для сертификационных испытаний." },
  { kind: "pp", title: "Отчёт внутренней приёмки", desc: "Протокол приёмки — для внутренней приёмки работ." },
];

interface NoteForm {
  title: string;
  excerpt: string;
  author: string;
}

interface VulnDetailForm {
  title?: string;
  host?: string;
  sev?: Severity;
  status?: VStatus;
  stepsList?: string[];
  stepImages?: Record<number, string[]>;
  description?: string;
  impact?: string;
  remediation?: string;
  cwe?: string;
  vector?: string;
}

interface StormState {
  userMenuOpen: boolean;
  notifOpen: boolean;
  modalOpen: boolean;
  sidebarCollapsed: boolean;
  lightboxSrc: string | null;
  apiProjects: ApiProjectRow[] | null;
  projectsLoading: boolean;
  projectsError: string | null;
  reloadTick: number;
  projEditId: number | null;
  confirmProjectId: number | null;
  /* ---- project detail: every collection below is backend-backed ----
     `null` = not loaded yet, `[]` = loaded and empty. Each has a `*Tick`
     counter that its loader effect watches, so a mutation reloads it. */
  activity: ProjectActivityItem[] | null;
  activityLoading: boolean;
  activityError: string | null;
  activityTick: number;
  /** Key of the activity group whose full list is open in a modal. */
  activityModalKey: string | null;
  /** Real hosts for `openProjectId`, mapped to Storm's shape. `null` = not loaded yet. */
  apiHosts: Host[] | null;
  hostsLoading: boolean;
  hostsTick: number;
  apiMembers: Member[] | null;
  membersTick: number;
  apiVulns: Vuln[] | null;
  vulnsTick: number;
  apiNotes: Note[] | null;
  notesTick: number;
  /** Set when the backend answers 403 for the open project → renders the no-access screen. */
  accessDenied: boolean;
  notifs: ApiNotification[];
  reconView: ReconView;
  openHostId: number | null;
  reconMenuOpen: boolean;
  hostQuery: string;
  /* Recon view filters. Methods are multi-select like every other pill filter:
     empty = all. */
  epMethods: Method[];
  epHostQuery: string;
  epPathQuery: string;
  ipQuery: string;
  epExpanded: string[];
  confirmOpen: boolean;
  confirmType: EditorType | null;
  confirmIndex: number;
  confirmLabel: string;
  noteEditorOpen: boolean;
  noteEditorMode: "add" | "edit";
  noteEditorIndex: number;
  noteForm: NoteForm;
  epOpen: boolean;
  epData: { method: Method; path: string; host: string; hostId: number; endpointId: number };
  /** Raw request being edited — saved to the endpoint (request_raw). */
  epRequest: string;
  /* The response is a scratchpad: there is no column for it on the backend, so it
     is deliberately not saved — it exists to be tweaked and copied out. */
  epResponse: string;
  epSaving: boolean;
  exportModalOpen: boolean;
  /** Backend report template: "szi" = certification, "pp" = internal acceptance. */
  exportKind: ReportKind;
  exportBusy: boolean;
  /** What the export dialog is for: the project's Word report, or a recon list. */
  exportScope: ExportScope;
  exportFormat: "list" | "openapi";
  /** Note open in the viewer, by backend id — it is part of the URL. */
  openNoteId: number | null;
  editorOpen: boolean;
  editorType: EditorType;
  editorMode: "add" | "edit";
  editorIndex: number;
  editorForm: Record<string, string | string[]>;
  tagDrafts: Record<string, string>;
  nav: NavId;
  tab: "active" | "archived";
  query: string;
  projSort: "last" | "first";
  newName: string;
  newDesc: string;
  newStart: string;
  newEnd: string;
  view: ViewId;
  openProjectId: number | null;
  projEditOpen: boolean;
  projEditName: string;
  projEditDesc: string;
  projEditStart: string;
  projEditEnd: string;
  projEditStatus: ProjectStatus;
  section: SectionId;
  expanded: number[];
  profileTab: ProfileTab;
  apiKeys: ApiKey[];
  apiKeyModalOpen: boolean;
  apiKeyName: string;
  apiKeyScopes: Record<string, boolean>;
  workspaceUsers: WorkspaceUser[];
  usersTick: number;
  wsUserModalOpen: boolean;
  wsUserMode: "add" | "edit";
  wsUserIndex: number;
  wsUserName: string;
  wsUserEmail: string;
  wsUserRole: WsRole;
  wsUserProjectRole: Role;
  memberQuery: string;
  /** Multi-select project-role filter (empty = no filtering). */
  memberRoles: Role[];
  wsMemberQuery: string;
  /** Multi-select workspace-role filter (empty = no filtering). */
  wsMemberRoles: WsRole[];
  /** Multi-select project-role filter on the workspace Members page (empty = no filtering). */
  wsMemberProjectRoles: Role[];
  twoFAEnabled: boolean;
  twoFASetupOpen: boolean;
  twoFACode: string;
  vulnFilterAuthor: string;
  /* Multi-select filters: every pill toggles, and an empty selection means "All"
     — so deselecting the last pill lands back on All by itself. */
  vulnFilterStatuses: VStatus[];
  vulnFilterSeverities: Severity[];
  vulnFilterHost: string;
  /** Real backend vulnerability id (not a list index) — it is part of the URL. */
  openVulnId: number | null;
  vulnDetailForm: VulnDetailForm;
}

const initialState: StormState = {
  userMenuOpen: false,
  notifOpen: false,
  modalOpen: false,
  sidebarCollapsed: false,
  lightboxSrc: null,
  apiProjects: null,
  projectsLoading: false,
  projectsError: null,
  reloadTick: 0,
  projEditId: null,
  confirmProjectId: null,
  activity: null,
  activityLoading: false,
  activityError: null,
  activityTick: 0,
  activityModalKey: null,
  apiHosts: null,
  hostsLoading: false,
  hostsTick: 0,
  apiMembers: null,
  membersTick: 0,
  apiVulns: null,
  vulnsTick: 0,
  apiNotes: null,
  notesTick: 0,
  accessDenied: false,
  notifs: [],
  reconView: "hosts",
  openHostId: null,
  reconMenuOpen: false,
  hostQuery: "",
  epMethods: [],
  epHostQuery: "",
  epPathQuery: "",
  ipQuery: "",
  epExpanded: [],
  confirmOpen: false,
  confirmType: null,
  confirmIndex: -1,
  confirmLabel: "",
  noteEditorOpen: false,
  noteEditorMode: "add",
  noteEditorIndex: -1,
  noteForm: { title: "", excerpt: "", author: "" },
  epOpen: false,
  epData: { method: "GET", path: "", host: "", hostId: 0, endpointId: 0 },
  epRequest: "",
  epResponse: "",
  epSaving: false,
  exportModalOpen: false,
  exportKind: "szi",
  exportBusy: false,
  exportScope: "report",
  exportFormat: "list",
  openNoteId: null,
  editorOpen: false,
  editorType: "host",
  editorMode: "add",
  editorIndex: -1,
  editorForm: {},
  tagDrafts: {},
  nav: "projects",
  tab: "active",
  query: "",
  projSort: "last",
  newName: "",
  newDesc: "",
  newStart: "",
  newEnd: "",
  view: "list",
  openProjectId: null,
  projEditOpen: false,
  projEditName: "",
  projEditDesc: "",
  projEditStart: "",
  projEditEnd: "",
  projEditStatus: "active",
  section: "overview",
  expanded: [],
  profileTab: "account",
  apiKeys: [],
  apiKeyModalOpen: false,
  apiKeyName: "",
  apiKeyScopes: {},
  workspaceUsers: [],
  usersTick: 0,
  wsUserModalOpen: false,
  wsUserMode: "add",
  wsUserIndex: -1,
  wsUserName: "",
  wsUserEmail: "",
  wsUserRole: "user",
  wsUserProjectRole: "pentester",
  memberQuery: "",
  memberRoles: [],
  wsMemberQuery: "",
  wsMemberRoles: [],
  wsMemberProjectRoles: [],
  twoFAEnabled: true,
  twoFASetupOpen: false,
  twoFACode: "",
  vulnFilterAuthor: "",
  vulnFilterStatuses: [],
  vulnFilterSeverities: [],
  vulnFilterHost: "",
  openVulnId: null,
  vulnDetailForm: {},
};

const CARD: CSSProperties = { background: "#fff", border: "1px solid #e9edf4", borderRadius: 16 };
const PILL_ON: CSSProperties = { background: "#4C74C7", color: "#fff", border: "1px solid #4C74C7" };
const PILL_OFF: CSSProperties = { background: "#fff", color: "#5A6B84", border: "1px solid #dbe1ec" };
const stop = (e: { stopPropagation: () => void }) => e.stopPropagation();
const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);
/** Multi-select filter toggle: add the value if absent, drop it if already held. */
const toggleIn = <T,>(arr: T[], v: T): T[] => (arr.includes(v) ? arr.filter((x) => x !== v) : [...arr, v]);
/** Coerce an editor-form value (string or tag-array) to a plain string. */
const fstr = (v: string | string[] | undefined): string => (typeof v === "string" ? v : "");

/** dd.mm.yyyy → yyyy-mm-dd (for <input type=date>) and back. */
const toISODate = (s?: string): string => {
  if (!s) return "";
  const m = String(s).match(/^(\d{2})\.(\d{2})\.(\d{4})$/);
  return m ? `${m[3]}-${m[2]}-${m[1]}` : s;
};
const toDispDate = (s?: string): string => {
  if (!s) return "";
  const m = String(s).match(/^(\d{4})-(\d{2})-(\d{2})$/);
  return m ? `${m[3]}.${m[2]}.${m[1]}` : s;
};

/** Relative "time ago" from an ISO timestamp. */
function relTime(iso?: string | null): string {
  if (!iso) return "";
  const s = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (s < 60) return "just now";
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} h ago`;
  const d = Math.floor(h / 24);
  if (d === 1) return "Yesterday";
  if (d < 30) return `${d} days ago`;
  return `${Math.floor(d / 30)} mo ago`;
}

/** Build the URL path that represents the current navigation state.
 *
 * The open vulnerability is part of the path (`…/vulns/{id}`) so that a finding
 * can be deep-linked — that is what notification and activity-feed links point
 * at. Keep this in sync with `navStateFromPath`: any field encoded here must be
 * parsed back there, or the round-trip through the router will drop it.
 */
function pathFor(s: {
  view: ViewId;
  nav: NavId;
  openProjectId: number | null;
  section: SectionId;
  reconView: ReconView;
  profileTab: ProfileTab;
  openVulnId: number | null;
  openNoteId: number | null;
}): string {
  if (s.view === "profile") return s.profileTab === "account" ? "/profile" : `/profile/${s.profileTab}`;
  if (s.view === "workspaceMembers") return "/members";
  if (s.view === "detail" && s.openProjectId != null) {
    const base = `/projects/${s.openProjectId}`;
    if (s.section === "overview") return base;
    if (s.section === "hosts") return `${base}/${s.reconView}`;
    if (s.section === "vulns" && s.openVulnId != null) return `${base}/vulns/${s.openVulnId}`;
    if (s.section === "notes" && s.openNoteId != null) return `${base}/notes/${s.openNoteId}`;
    return `${base}/${s.section}`;
  }
  return ({ projects: "/projects", tasks: "/tasks", mine: "/my-tasks", docs: "/docs", members: "/members" } as Record<NavId, string>)[s.nav] || "/projects";
}

/** Parse a URL path back into the navigation-state fields it encodes. */
function navStateFromPath(path: string): Partial<StormState> {
  const parts = path.split("/").filter(Boolean);
  const head = parts[0];
  if (!head) return { view: "list", nav: "projects" };
  if (head === "projects") {
    if (parts.length === 1) return { view: "list", nav: "projects", openProjectId: null, openVulnId: null, openNoteId: null, openHostId: null };
    const id = Number(parts[1]);
    const seg = parts[2];
    const base: Partial<StormState> = {
      view: "detail",
      nav: "projects",
      openProjectId: Number.isFinite(id) ? id : null,
      openVulnId: null,
      openNoteId: null,
      openHostId: null,
    };
    /** `/…/vulns/7` → 7; a missing or non-numeric segment → null. */
    const entityId = () => {
      const n = Number(parts[3]);
      return parts[3] != null && Number.isFinite(n) ? n : null;
    };
    if (!seg) return { ...base, section: "overview" };
    if (seg === "hosts" || seg === "ips" || seg === "endpoints") return { ...base, section: "hosts", reconView: seg };
    // /projects/{id}/vulns/{vulnId} and /projects/{id}/notes/{noteId} — deep links.
    if (seg === "vulns") return { ...base, section: "vulns", openVulnId: entityId() };
    if (seg === "notes") return { ...base, section: "notes", openNoteId: entityId() };
    if (seg === "members" || seg === "activity") return { ...base, section: seg };
    return { ...base, section: "overview" };
  }
  if (head === "tasks") return { view: "list", nav: "tasks" };
  if (head === "my-tasks") return { view: "list", nav: "mine" };
  if (head === "docs") return { view: "list", nav: "docs" };
  if (head === "members") return { view: "workspaceMembers", nav: "members" };
  if (head === "profile") return { view: "profile", profileTab: ["security", "api"].includes(parts[1]) ? (parts[1] as ProfileTab) : "account" };
  return { view: "list", nav: "projects" };
}

/** A project row as shown in the (backend-backed) Projects list. */
interface ApiProjectRow {
  id: number;
  name: string;
  description: string;
  status: ProjectStatus;
  startISO: string;
  endISO: string;
  updated: string;
  createdBy: number;
  openFindings: number;
  totalFindings: number;
  hostsCount: number;
}

function initialsOf(name: string): string {
  const parts = name.trim().split(/[^A-Za-zА-Яа-яЁё0-9]+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return (parts[0] || "U").slice(0, 2).toUpperCase();
}

/** CVSS 4.0 scorer.
 *
 * Раньше здесь была упрощённая формула из прототипа (сумма весов), которая
 * расходилась со спецификацией: например
 * CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N давала 8.8
 * вместо 7.3. Реальный CVSS 4.0 считается по MacroVector-таблицам, поэтому
 * используем спецификационную реализацию из ../cvss — ту же оценку выдаёт и
 * бэкенд (библиотека cvss), так что превью и сохранённое значение совпадают.
 */
function computeCvss4(vector?: string): { score: number; sev: Severity } | null {
  const v = (vector || "").trim();
  if (!/^CVSS:4\.0\//i.test(v)) return null;
  const { score } = calculateCvssScore("4.0", v);
  if (score === null || Number.isNaN(score)) return null;
  return { score, sev: severityFromCvssScore(score) as Severity };
}

/** Minimal Markdown → React renderer for the read-only note viewer. */
function mdInline(text: string, kb: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  let rest = text;
  let key = 0;
  const re = /(\*\*([^*]+)\*\*|\*([^*]+)\*|`([^`]+)`|\[([^\]]+)\]\(([^)]+)\))/;
  let m: RegExpExecArray | null;
  while ((m = re.exec(rest))) {
    if (m.index > 0) nodes.push(rest.slice(0, m.index));
    if (m[2] != null) nodes.push(<strong key={`${kb}-${key++}`}>{m[2]}</strong>);
    else if (m[3] != null) nodes.push(<em key={`${kb}-${key++}`}>{m[3]}</em>);
    else if (m[4] != null)
      nodes.push(
        <code key={`${kb}-${key++}`} style={{ background: "#eef1f7", borderRadius: 5, padding: "1px 5px", fontFamily: "ui-monospace,Menlo,monospace", fontSize: ".9em" }}>
          {m[4]}
        </code>
      );
    else if (m[5] != null)
      nodes.push(
        <a key={`${kb}-${key++}`} href={m[6]} style={{ color: "#4C74C7" }}>
          {m[5]}
        </a>
      );
    rest = rest.slice(m.index + m[0].length);
  }
  if (rest) nodes.push(rest);
  return nodes;
}
function renderMarkdown(src: string): ReactNode {
  const lines = src.replace(/\r/g, "").split("\n");
  const blocks: ReactNode[] = [];
  let list: string[] | null = null;
  let key = 0;
  const flush = () => {
    if (list) {
      const items = list;
      const k = key++;
      blocks.push(
        <ul key={`b${k}`} style={{ margin: "4px 0 8px", paddingLeft: 20 }}>
          {items.map((it, i) => (
            <li key={i} style={{ margin: "2px 0" }}>
              {mdInline(it, `li${k}-${i}`)}
            </li>
          ))}
        </ul>
      );
      list = null;
    }
  };
  for (const ln of lines) {
    const hm = ln.match(/^(#{1,3})\s+(.*)$/);
    const li = ln.match(/^\s*[-*]\s+(.*)$/);
    if (hm) {
      flush();
      const lvl = hm[1].length;
      const size = lvl === 1 ? 18 : lvl === 2 ? 15.5 : 13.5;
      const k = key++;
      blocks.push(
        <div key={`b${k}`} style={{ fontWeight: 800, fontSize: size, color: "#0F1B2D", margin: "8px 0 4px" }}>
          {mdInline(hm[2], `h${k}`)}
        </div>
      );
    } else if (li) {
      (list = list || []).push(li[1]);
    } else if (ln.trim() === "") {
      flush();
    } else {
      flush();
      const k = key++;
      blocks.push(
        <div key={`b${k}`} style={{ margin: "3px 0" }}>
          {mdInline(ln, `p${k}`)}
        </div>
      );
    }
  }
  flush();
  return <div style={{ fontSize: 13.5, lineHeight: 1.6, color: "#3a4a60" }}>{blocks}</div>;
}

/** Deterministic sparkline point string (ported from prototype). */
function sparkline(seed: number, current: number): string {
  const n = 6;
  const w = 74;
  const h = 30;
  const pad = 3;
  const vals: number[] = [];
  let v = Math.max(0, current - (2 + (seed % 4)));
  for (let i = 0; i < n - 1; i++) {
    v = Math.max(0, v + (((seed * (i + 3)) % 5) - 2));
    vals.push(v);
  }
  vals.push(current);
  const max = Math.max(1, ...vals);
  const stepX = w / (n - 1);
  return vals.map((val, i) => `${Math.round(i * stepX)},${Math.round(h - pad - (val / max) * (h - pad * 2))}`).join(" ");
}

// ================= backend hosts → Storm host shape =================
/* The backend serialises each port with its services (schemas.py `PortOut.services`),
   but the shared `Port` type in ../types does not declare the field yet. Widen it
   locally rather than reaching outside this module. */
type ApiPortWithServices = ApiPort & { services?: ApiService[] };

const STORM_METHODS: Method[] = ["GET", "POST", "PUT", "PATCH", "DELETE"];

/** The API also emits HEAD/OPTIONS/null, which Storm's `Method` union has no pill for. */
function toStormMethod(m: ApiEndpoint["method"]): Method {
  return m && (STORM_METHODS as string[]).includes(m) ? (m as Method) : "GET";
}

/** Ports live under each IP on the backend; Storm shows them flat per host. */
function toStormPorts(h: ApiHost): Host["ports"] {
  return h.ip_addresses
    .flatMap((ip) => ip.ports as ApiPortWithServices[])
    .map((p) => ({ n: p.port_number, proto: p.protocol, state: p.state, svc: p.services?.[0]?.name ?? "" }));
}

function toStormHost(h: ApiHost, endpoints: Endpoint[] = []): Host {
  return {
    id: h.id,
    host: h.hostname || h.ip_address || "—",
    ip: h.ip_address || "",
    ips: h.ip_addresses.map((a) => a.ip_address),
    status: h.status,
    ports: toStormPorts(h),
    endpoints,
  };
}

// ================= backend vulns / notes / members → Storm shapes =================
/** Backend workflow steps carry ids/endpoints/images; Storm's editor shows the text only. */
function toStormVuln(v: ApiVulnerability, hostName: string): Vuln {
  return {
    id: v.id,
    sev: v.severity,
    title: v.title,
    // Storm speaks the backend's status vocabulary directly — nothing to map.
    status: v.status,
    host: hostName,
    author: v.created_by_username || "—",
    updated: relTime(v.updated_at),
    steps: v.workflow_steps.map((s) => s.description || "").filter(Boolean),
    description: v.description || "",
    impact: v.impact || "",
    remediation: v.recommendations || "",
    cwe: v.cwe_id || "",
    vector: v.cvss_vector || "",
  };
}

function toStormNote(n: ProjectNote): Note {
  return {
    id: n.id,
    title: n.title,
    when: toDispDate((n.updated_at || n.created_at || "").slice(0, 10)),
    excerpt: n.content || "",
    author: n.created_by_username || "—",
  };
}

function toStormMember(m: ApiProjectMember, idx: number): Member {
  return {
    id: m.user_id,
    initials: initialsOf(m.username),
    name: m.username,
    email: m.email,
    role: m.project_role,
    color: MEMBER_COLORS[idx % MEMBER_COLORS.length],
  };
}

// ================= activity feed =================
/* Marker + colour for the dark event panel: green + = added, red − = removed,
   amber ~ = changed — the prototype's scheme, tuned to the Storm palette. */
const ACT_TONE = {
  add: { mark: "+", color: "#5FD39A" },
  change: { mark: "~", color: "#E8A13C" },
  remove: { mark: "−", color: "#EF8A9C" },
  info: { mark: "•", color: "#8FB4F5" },
} as const;
type ActTone = (typeof ACT_TONE)[keyof typeof ACT_TONE];
/** Severity chip on the dark panel — filled with the severity's own colour. */
const ACT_SEV: Record<Severity, string> = {
  critical: "#C0455B",
  high: "#D9683C",
  medium: "#B7862B",
  low: "#2E5FBF",
  info: "#6b7a90",
};

/** Beyond this many lines a card collapses and offers "Show more". */
const ACT_LINE_LIMIT = 10;

interface ActivityLine {
  key: string;
  text: string;
  severity?: Severity | null;
}
interface ActivityGroup {
  key: string;
  actor: string;
  /** Reads as one sentence with `subject`: "admin added 3 IP addresses". */
  verb: string;
  subject: string;
  tone: ActTone;
  time: string;
  lines: ActivityLine[];
  /** Findings are standalone cards, so the card links to that one finding. */
  vulnId?: number | null;
}

/** Human noun per entity type, singular/plural. Ports are deliberately absent —
    they are excluded from the feed (see ACT_HIDDEN). */
const ACT_NOUN: Record<string, [string, string]> = {
  vulnerability: ["finding", "findings"],
  host: ["host", "hosts"],
  host_ip_address: ["IP address", "IP addresses"],
  ip_address: ["IP address", "IP addresses"],
  service: ["service", "services"],
  endpoint: ["endpoint", "endpoints"],
  project_note: ["note", "notes"],
  note: ["note", "notes"],
  project: ["project", "projects"],
  project_member: ["member", "members"],
  member: ["member", "members"],
  comment: ["comment", "comments"],
  note_comment: ["comment", "comments"],
};

/** Entity types the feed never shows: ports are too noisy to be worth a row. */
const ACT_HIDDEN = new Set(["port"]);
/** Entity types that are always their own card, never merged with siblings. */
const ACT_STANDALONE = new Set(["vulnerability", "project"]);

const actDetail = (a: ProjectActivityItem, k: string): string => {
  const v = a.details?.[k];
  return typeof v === "string" ? v : typeof v === "number" ? String(v) : "";
};

/** Resolves an entity id to a display name — see `activityLine`'s fallback. */
type ActivityResolver = (entityType: string | null, entityId: number | null) => string | null;

/* One feed line: just the thing that was touched. The card header already says
   what kind of objects these are ("added 3 IP addresses"), so the lines carry no
   HOST/IP/ENDPOINT tag — only a coloured +/−/~ marker for added/removed/changed.

   CREATE events carry the entity in their audit details; UPDATE/DELETE ones do
   not, so the name is resolved from the loaded project data instead of printing
   a meaningless "#12". */
function activityLine(a: ProjectActivityItem, resolve: ActivityResolver): ActivityLine {
  const base = { key: String(a.id) };
  const fallback = resolve(a.entity_type, a.entity_id) ?? (a.entity_id != null ? `#${a.entity_id}` : "—");
  switch (a.entity_type) {
    case "vulnerability":
      // A deleted finding cannot be enriched (`title`) or resolved — its name is
      // whatever the DELETE event recorded at the time.
      return { ...base, text: a.title || actDetail(a, "title") || fallback, severity: a.severity ?? (actDetail(a, "severity") as Severity) ?? null };
    case "host": {
      const ip = actDetail(a, "ip_address");
      const name = actDetail(a, "hostname") || ip || fallback;
      return { ...base, text: ip && name !== ip ? `${name} · ${ip}` : name };
    }
    case "host_ip_address":
    case "ip_address":
      // The label (external / internal / mgmt) adds nothing here — just the address.
      return { ...base, text: actDetail(a, "ip_address") || fallback };
    case "service":
      return { ...base, text: actDetail(a, "service") || actDetail(a, "name") || fallback };
    case "endpoint":
      return { ...base, text: actDetail(a, "endpoint") || actDetail(a, "path") || fallback };
    case "project_note":
    case "note":
      return { ...base, text: a.title || actDetail(a, "title") || fallback };
    case "project":
      return { ...base, text: actDetail(a, "project") || a.title || fallback };
    case "project_member":
    case "member":
      return { ...base, text: actDetail(a, "username") || actDetail(a, "user") || fallback };
    default:
      return { ...base, text: a.title || fallback };
  }
}

/** What the action applied to, straight after the verb: "3 IP addresses", "finding". */
function activitySubject(type: string, n: number): string {
  const noun = ACT_NOUN[type] ?? [type.replace(/_/g, " "), `${type.replace(/_/g, " ")}s`];
  return n === 1 ? noun[0] : `${n} ${noun[1]}`;
}

/* One card per action *per entity type*: adding hosts, IPs and endpoints are
   separate actions and never share a card. Findings and projects are always
   standalone — each reported finding is its own entry. Ports are dropped. */
function groupActivity(items: ProjectActivityItem[], resolve: ActivityResolver = () => null): ActivityGroup[] {
  const groups: ActivityGroup[] = [];
  let bucket: ProjectActivityItem[] = [];
  const flush = () => {
    if (!bucket.length) return;
    const first = bucket[0];
    const type = first.entity_type || "event";
    const tone =
      first.action === "CREATE" ? ACT_TONE.add
      : first.action === "DELETE" ? ACT_TONE.remove
      : first.action === "UPDATE" ? ACT_TONE.change
      : ACT_TONE.info;
    // Findings are "reported"; everything else is added / updated / removed.
    const verb =
      first.action === "CREATE" ? (type === "vulnerability" ? "reported" : "added")
      : first.action === "UPDATE" ? "updated"
      : first.action === "DELETE" ? "removed"
      : first.action.toLowerCase().replace(/_/g, " ");
    groups.push({
      key: `g${first.id}`,
      actor: first.username || "System",
      verb,
      subject: activitySubject(type, bucket.length),
      tone,
      time: relTime(first.created_at),
      lines: bucket.map((a) => activityLine(a, resolve)),
      // Findings are standalone, so the card carries exactly one finding to link to.
      vulnId: type === "vulnerability" ? first.entity_id : null,
    });
    bucket = [];
  };
  items
    .filter((a) => !ACT_HIDDEN.has(a.entity_type || ""))
    .forEach((a) => {
      const prev = bucket[0];
      const breaks =
        prev != null &&
        (prev.username !== a.username ||
          prev.action !== a.action ||
          prev.entity_type !== a.entity_type ||
          ACT_STANDALONE.has(a.entity_type || ""));
      if (breaks) flush();
      bucket.push(a);
    });
  flush();
  return groups;
}

/** Percentage of the engagement window that has elapsed (the overview progress bar). */
function elapsedPct(startISO: string, endISO: string): number {
  const start = Date.parse(startISO);
  const end = Date.parse(endISO);
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) return 0;
  const pct = ((Date.now() - start) / (end - start)) * 100;
  return Math.max(0, Math.min(100, Math.round(pct)));
}

export function StormApp() {
  const [state, setStateRaw] = useState<StormState>(initialState);
  const setState = (patch: Partial<StormState> | ((s: StormState) => Partial<StormState>)) =>
    setStateRaw((prev) => ({ ...prev, ...(typeof patch === "function" ? patch(prev) : patch) }));
  const toggle = (k: keyof StormState) => setStateRaw((s) => ({ ...s, [k]: !s[k] }));

  // ---- logged-in user (real backend auth) ----
  const authUser = useAuthStore((s) => s.user);
  const signOut = useAuthStore((s) => s.signOut);
  const pushToast = useToastStore((s) => s.pushToast);
  const navigate = useNavigate();
  const location = useLocation();
  const realUsername = authUser?.username || "";
  const realIsAdmin = authUser?.role === "admin";
  const me = realUsername;
  const meWsRole: WsRole = realIsAdmin ? "admin" : "user";
  const isAdmin = meWsRole === "admin";
  const meEmail = authUser?.email || "";
  const meDisplay = authUser?.full_name || realUsername;
  const meRoleLabel = meWsRole === "admin" ? "Administrator" : "User";
  const meId = String(authUser?.id ?? "");
  const meInitials = initialsOf(authUser?.full_name || realUsername || "U");

  /** Any request that 403s for the open project flips the no-access screen on. */
  const handleProjectError = (e: unknown, fallback: string) => {
    if (getApiErrorStatus(e) === 403 || getApiErrorStatus(e) === 404) {
      setStateRaw((s) => ({ ...s, accessDenied: true }));
      return;
    }
    pushToast(getApiErrorMessage(e, fallback), "error");
  };

  // ================= projects: load from backend =================
  const reloadProjects = () => setStateRaw((s) => ({ ...s, reloadTick: s.reloadTick + 1 }));
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      setStateRaw((s) => ({ ...s, projectsLoading: true, projectsError: null }));
      try {
        const [res, stats] = await Promise.all([
          getProjects(1, 100),
          // Aggregate stats are best-effort: fall back to zeros rather than failing the list.
          getProjectStats().catch(() => [] as ProjectStats[]),
        ]);
        const statsById = new Map(stats.map((s) => [s.project_id, s]));
        const rows: ApiProjectRow[] = res.items.map((p) => {
          const st = statsById.get(p.id);
          return {
            id: p.id,
            name: p.name,
            description: p.description || "No description yet",
            status: p.status,
            startISO: p.start_date || "",
            endISO: p.end_date || "",
            updated: relTime(p.updated_at),
            createdBy: p.created_by,
            openFindings: st?.open_findings ?? 0,
            totalFindings: st?.total_findings ?? 0,
            hostsCount: st?.hosts_count ?? 0,
          };
        });
        if (!cancelled) setStateRaw((s) => ({ ...s, apiProjects: rows, projectsLoading: false }));
      } catch (e) {
        if (!cancelled) setStateRaw((s) => ({ ...s, apiProjects: [], projectsError: getApiErrorMessage(e, "Не удалось загрузить проекты"), projectsLoading: false }));
      }
    })();
    return () => {
      cancelled = true;
    };
     
  }, [state.reloadTick]);

  /* ================= workspace users: load from backend =================
     `GET /users` is admin-only, so this must not run for anyone else: it would
     403 and pop a "Недостаточно прав" toast on every page (that is what showed
     up while simply sitting on the Activity tab). `project_role` is a global
     user attribute and the workspace members page is where it is configured. */
  const reloadUsers = () => setStateRaw((s) => ({ ...s, usersTick: s.usersTick + 1 }));
  useEffect(() => {
    if (!isAdmin) {
      setStateRaw((s) => (s.workspaceUsers.length === 0 ? s : { ...s, workspaceUsers: [] }));
      return;
    }
    let cancelled = false;
    void (async () => {
      try {
        const res = await getUsers(1, 200);
        const rows: WorkspaceUser[] = res.items.map((u) => ({
          id: u.id,
          key: u.username,
          name: u.username,
          email: u.email,
          role: u.role === "admin" ? "admin" : "user",
          projectRole: u.project_role,
        }));
        if (!cancelled) setStateRaw((s) => ({ ...s, workspaceUsers: rows }));
      } catch (e) {
        // Best-effort: keep the list empty rather than breaking the app.
        if (!cancelled) {
          setStateRaw((s) => ({ ...s, workspaceUsers: [] }));
          pushToast(getApiErrorMessage(e, "Не удалось загрузить пользователей"), "error");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.usersTick, isAdmin]);

  // ================= hosts: load from backend =================
  /* Endpoints are fetched up-front alongside the list because the Recon →
     Endpoints view aggregates them across every host, so loading them lazily on
     row expand would leave that view permanently empty. */
  const reloadHosts = () => setStateRaw((s) => ({ ...s, hostsTick: s.hostsTick + 1 }));
  useEffect(() => {
    const pid = state.openProjectId;
    if (pid == null) {
      setStateRaw((s) => (s.apiHosts === null && !s.hostsLoading ? s : { ...s, apiHosts: null, hostsLoading: false }));
      return;
    }
    let cancelled = false;
    void (async () => {
      setStateRaw((s) => ({ ...s, hostsLoading: true }));
      try {
        const res = await apiGetHosts(pid);
        const rows = await Promise.all(
          res.items.map(async (h) => {
            try {
              const det = await apiGetHost(pid, h.id);
              return toStormHost(h, det.endpoints.map((e) => ({ id: e.id, m: toStormMethod(e.method), p: e.path })));
            } catch {
              // Best-effort: a host whose detail fails still belongs in the list.
              return toStormHost(h);
            }
          })
        );
        if (!cancelled) setStateRaw((s) => ({ ...s, apiHosts: rows, hostsLoading: false }));
      } catch (e) {
        if (!cancelled) {
          setStateRaw((s) => ({ ...s, apiHosts: [], hostsLoading: false }));
          handleProjectError(e, "Не удалось загрузить хосты");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.openProjectId, state.hostsTick]);

  /** Hosts rendered by the whole Recon section. Backend-only — never the seed. */
  const hosts: Host[] = state.apiHosts ?? [];
  const hostNameById = (id: number) => hosts.find((h) => h.id === id)?.host ?? "";
  /* Subdomains are not a stored field — they are simply the project's other hosts
     that live under this one's name (www.acme.com under acme.com). Derived here so
     the tree reflects the real host list instead of a parallel, hand-kept one. */
  const subdomainsOf = (host: Host): Host[] =>
    hosts.filter((h) => h.id !== host.id && h.host.toLowerCase().endsWith(`.${host.host.toLowerCase()}`));

  // ================= members: load from backend =================
  const reloadMembers = () => setStateRaw((s) => ({ ...s, membersTick: s.membersTick + 1 }));
  useEffect(() => {
    const pid = state.openProjectId;
    if (pid == null) {
      setStateRaw((s) => (s.apiMembers === null ? s : { ...s, apiMembers: null }));
      return;
    }
    let cancelled = false;
    void (async () => {
      try {
        // Readable by every project member (require_project_access) — a 403 here
        // means no access to the project at all, so it raises the no-access screen.
        const rows = await apiGetProjectMembers(pid);
        if (!cancelled) setStateRaw((s) => ({ ...s, apiMembers: rows.map(toStormMember) }));
      } catch (e) {
        if (!cancelled) {
          setStateRaw((s) => ({ ...s, apiMembers: [] }));
          handleProjectError(e, "Не удалось загрузить участников");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.openProjectId, state.membersTick]);

  // ================= vulnerabilities: load from backend =================
  /* The list endpoint does not say which host a finding is on — that lives in its
     asset links — so the affected host is resolved per finding against the
     project's already-loaded hosts. The author's name, by contrast, ships with
     the payload (`created_by_username`), because /users is admin-only. */
  const reloadVulns = () => setStateRaw((s) => ({ ...s, vulnsTick: s.vulnsTick + 1 }));
  useEffect(() => {
    const pid = state.openProjectId;
    if (pid == null) {
      setStateRaw((s) => (s.apiVulns === null ? s : { ...s, apiVulns: null }));
      return;
    }
    let cancelled = false;
    void (async () => {
      try {
        const res = await apiGetVulnerabilities(pid);
        const rows = await Promise.all(
          res.items.map(async (v) => {
            let hostName = "";
            try {
              const det = await apiGetVulnerability(pid, v.id);
              const link = det.assets.find((a) => a.asset_type === "host");
              if (link) hostName = hostNameById(link.asset_id);
            } catch {
              /* best-effort: a finding without a resolvable host still lists */
            }
            return toStormVuln(v, hostName);
          })
        );
        if (!cancelled) setStateRaw((s) => ({ ...s, apiVulns: rows }));
      } catch (e) {
        if (!cancelled) {
          setStateRaw((s) => ({ ...s, apiVulns: [] }));
          handleProjectError(e, "Не удалось загрузить уязвимости");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.openProjectId, state.vulnsTick, state.apiHosts]);

  // ================= notes: load from backend =================
  const reloadNotes = () => setStateRaw((s) => ({ ...s, notesTick: s.notesTick + 1 }));
  useEffect(() => {
    const pid = state.openProjectId;
    if (pid == null) {
      setStateRaw((s) => (s.apiNotes === null ? s : { ...s, apiNotes: null }));
      return;
    }
    let cancelled = false;
    void (async () => {
      try {
        const rows = await apiListProjectNotes(pid);
        if (!cancelled) setStateRaw((s) => ({ ...s, apiNotes: rows.map(toStormNote) }));
      } catch (e) {
        if (!cancelled) {
          setStateRaw((s) => ({ ...s, apiNotes: [] }));
          handleProjectError(e, "Не удалось загрузить заметки");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.openProjectId, state.notesTick]);

  // ================= notifications: load from backend =================
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const res = await apiListNotifications();
        if (!cancelled) setStateRaw((s) => ({ ...s, notifs: res.items }));
      } catch {
        // Best-effort: an empty bell beats breaking the shell.
        if (!cancelled) setStateRaw((s) => ({ ...s, notifs: [] }));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // ================= current project detail =================
  /* `d` is assembled from the collections loaded above — it is a view over real
     backend state, not a store. Nothing mutates it: every edit calls the API and
     bumps the matching `*Tick` to reload. */
  const projRow = state.apiProjects?.find((p) => p.id === state.openProjectId) ?? null;
  const projName = projRow?.name ?? "";
  const d: ProjectDetail = {
    status: projRow && (projRow.status === "archived" || projRow.status === "completed") ? "archived" : "active",
    desc: projRow?.description === "No description yet" ? "" : projRow?.description ?? "",
    start: toDispDate(projRow?.startISO),
    end: toDispDate(projRow?.endISO),
    progress: elapsedPct(projRow?.startISO ?? "", projRow?.endISO ?? ""),
    title: projName,
    hosts,
    members: state.apiMembers ?? [],
    vulns: state.apiVulns ?? [],
    notes: state.apiNotes ?? [],
  };

  // ================= role model / access control =================
  // Project visibility (rule 1.1) is enforced by the backend — getProjects only
  // returns projects the caller may see, and the detail endpoints 403 otherwise.
  const isProjectCreator = projRow != null && authUser != null && projRow.createdBy === authUser.id;
  /** The lead role is global (User.project_role); it only unlocks anything inside a project the user belongs to. */
  const isProjectLead = authUser?.project_role === "lead" && (state.apiMembers ?? []).some((m) => m.id === authUser.id);
  /** Rule 1.2 — only admin / creator / lead may see (and manage) project members. */
  const canViewMembers = isAdmin || isProjectCreator || isProjectLead;
  /** The same three roles may edit the project card (name / description / dates).
      Mirrors ProjectService.ensure_can_edit_project — the backend is the gate,
      this only hides a button the user would be refused anyway. */
  const canEditProject = isAdmin || isProjectCreator || isProjectLead;
  /* In the projects list there is no membership loaded per row, but a non-admin
     only ever receives projects they belong to (rule 1.1) — so a listed row plus
     the global lead role already means "lead of a project I'm in". */
  const canEditProjectRow = (row: ApiProjectRow) =>
    isAdmin || (authUser != null && row.createdBy === authUser.id) || authUser?.project_role === "lead";

  // ================= navigation =================
  // Возврат к списку обязан сбрасывать открытый проект — иначе состояние всё ещё
  // «в проекте», и URL может залипнуть на /projects/{id}.
  const selProjects = () =>
    setState({
      nav: "projects",
      view: "list",
      openProjectId: null,
      section: "overview",
      expanded: [],
      openVulnId: null,
      openNoteId: null,
      openHostId: null,
    });
  const openProject = (id: number) =>
    setState({ view: "detail", openProjectId: id, section: "overview", expanded: [], openVulnId: null, openNoteId: null, accessDenied: false });
  const openProfile = () => setState({ view: "profile", userMenuOpen: false, profileTab: "account" });
  const selWSMembers = () => setState({ nav: "members", view: "workspaceMembers" });
  /* Project activity, not the global audit log: /projects/{id}/activity is scoped to
     the project and readable by every member, while /audit-logs stays admin-only. */
  const reloadActivity = () => setStateRaw((s) => ({ ...s, activityTick: s.activityTick + 1 }));
  const loadActivity = (pid: number) => {
    setStateRaw((s) => ({ ...s, activityLoading: true, activityError: null }));
    void (async () => {
      try {
        const items = await apiGetProjectActivity(pid, 50);
        setStateRaw((s) => ({ ...s, activity: items, activityLoading: false }));
      } catch (e) {
        if (getApiErrorStatus(e) === 403 || getApiErrorStatus(e) === 404) {
          setStateRaw((s) => ({ ...s, activity: [], activityLoading: false, accessDenied: true }));
          return;
        }
        setStateRaw((s) => ({ ...s, activity: [], activityError: getApiErrorMessage(e, "Не удалось загрузить активность"), activityLoading: false }));
      }
    })();
  };
  /** A section tab always lands on that section's list, never on a card left open in it. */
  const setSection = (s: SectionId) => setState({ section: s, reconMenuOpen: false, openVulnId: null, openNoteId: null, noteEditorOpen: false });
  const selRecon = (v: ReconView) => setState({ section: "hosts", reconView: v, reconMenuOpen: false, openHostId: null });

  /* ---- URL ↔ navigation-state sync (deep links to sections / projects) ----
     Two effects mirror each other: URL → state, and state → URL. They must never
     both act on the same change, because the second one always runs with the
     state of the render it was scheduled in — i.e. the *old* state:

     - On mount that state is `initialState` (projects list), so URL → state must
       win or the deep link gets overwritten with "/projects" (navSyncMounted).
     - On browser Back the URL changes first; state → URL then still sees the
       previous screen and navigates straight back *forward*, so Back appears
       dead and history grows on every press (adoptingUrlRef).

     Whoever changed first wins; the other side stands down for that one run. */
  const adoptingUrlRef = useRef(false);
  useEffect(() => {
    const patch = navStateFromPath(location.pathname);
    const keys = Object.keys(patch) as (keyof StormState)[];
    // `state` here is the render the URL change arrived in — comparing against it
    // tells us whether this is an external navigation we still have to adopt.
    if (!keys.some((k) => state[k] !== patch[k])) return;
    adoptingUrlRef.current = true;
    setStateRaw((s) => ({ ...s, ...patch }));
    // Deps are the pathname alone on purpose: this must fire only when the URL
    // moves. Adding `state` would re-run it on every state change and re-apply
    // the old URL over a navigation the user just made.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location.pathname]);
  const navSyncMounted = useRef(false);
  useEffect(() => {
    if (!navSyncMounted.current) {
      navSyncMounted.current = true;
      return;
    }
    if (adoptingUrlRef.current) {
      adoptingUrlRef.current = false;
      return;
    }
    const p = pathFor({
      view: state.view,
      nav: state.nav,
      openProjectId: state.openProjectId,
      section: state.section,
      reconView: state.reconView,
      profileTab: state.profileTab,
      openVulnId: state.openVulnId,
      openNoteId: state.openNoteId,
    });
    if (p !== location.pathname) navigate(p);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.view, state.nav, state.openProjectId, state.section, state.reconView, state.profileTab, state.openVulnId, state.openNoteId, location.pathname]);
  /* Loaded as soon as the project opens, like every other collection — the tab's
     counter has to be right before the tab is ever visited. Entering the tab
     re-fetches, since the feed is a shared audit trail that others add to. */
  useEffect(() => {
    if (state.openProjectId != null) loadActivity(state.openProjectId);
    else setStateRaw((s) => (s.activity === null ? s : { ...s, activity: null }));
  }, [state.openProjectId, state.activityTick]);
  useEffect(() => {
    if (state.view === "detail" && state.section === "activity" && state.openProjectId != null) reloadActivity();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.view, state.section]);
  // Leaving a project clears a previous 403 so the next one starts from a clean slate.
  useEffect(() => {
    setStateRaw((s) => (s.accessDenied ? { ...s, accessDenied: false } : s));
  }, [state.openProjectId]);
  /* Deep link (/projects/{p}/vulns/{v}, e.g. from a notification): the URL sets
     openVulnId before the findings have loaded, so the edit form is filled in
     once the matching finding arrives. */
  useEffect(() => {
    if (state.openVulnId == null || state.apiVulns == null) return;
    const v = state.apiVulns.find((x) => x.id === state.openVulnId);
    if (!v) return;
    setStateRaw((s) => (s.vulnDetailForm.title === v.title ? s : { ...s, vulnDetailForm: vulnFormFrom(v) }));
     
  }, [state.openVulnId, state.apiVulns]);

  // ================= projects list (backend-backed) =================
  /** The backend rejects this too (422) — checked here so the form says so before submitting. */
  const datesInvalid = (startISO: string, endISO: string) => !!startISO && !!endISO && endISO < startISO;
  const DATES_ERROR = "Дата начала не может быть позже даты окончания";

  const createProject = async () => {
    const name = state.newName.trim();
    if (!name) {
      setState({ modalOpen: false });
      return;
    }
    if (datesInvalid(state.newStart, state.newEnd)) {
      pushToast(DATES_ERROR, "error");
      return;
    }
    try {
      await apiCreateProject({
        name,
        description: state.newDesc.trim() || undefined,
        start_date: state.newStart || undefined,
        end_date: state.newEnd || undefined,
      });
      setState({ modalOpen: false, newName: "", newDesc: "", newStart: "", newEnd: "", tab: "active" });
      reloadProjects();
    } catch (e) {
      pushToast(getApiErrorMessage(e, "Не удалось создать проект"), "error");
    }
  };

  // ================= edit project =================
  // Opened from a list row → targets a real backend project (projEditId set).
  const openProjEditRow = (row: ApiProjectRow) =>
    setState({
      projEditOpen: true,
      projEditId: row.id,
      projEditName: row.name,
      projEditDesc: row.description === "No description yet" ? "" : row.description,
      projEditStart: row.startISO,
      projEditEnd: row.endISO,
      projEditStatus: row.status,
    });
  // Opened from the project detail — targets the open project.
  const openProjEdit = () =>
    setState({
      projEditOpen: true,
      projEditId: state.openProjectId,
      projEditName: projRow?.name ?? "",
      projEditDesc: d.desc,
      projEditStart: projRow?.startISO ?? "",
      projEditEnd: projRow?.endISO ?? "",
      projEditStatus: projRow?.status ?? "active",
    });
  const closeProjEdit = () => setState({ projEditOpen: false });
  const saveProjEdit = async () => {
    const name = state.projEditName.trim();
    if (!name || !state.projEditId) {
      setState({ projEditOpen: false });
      return;
    }
    if (datesInvalid(state.projEditStart, state.projEditEnd)) {
      pushToast(DATES_ERROR, "error");
      return;
    }
    try {
      await apiUpdateProject(state.projEditId, {
        name,
        description: state.projEditDesc.trim(),
        start_date: state.projEditStart || undefined,
        end_date: state.projEditEnd || undefined,
        status: state.projEditStatus,
      });
      setState({ projEditOpen: false });
      reloadProjects();
    } catch (e) {
      pushToast(getApiErrorMessage(e, "Не удалось сохранить проект"), "error");
    }
  };
  const askDeleteProject = (row: ApiProjectRow) => setState({ confirmOpen: true, confirmType: null, confirmProjectId: row.id, confirmLabel: row.name });

  // ================= export: Word reports =================
  /* Both reports are generated by the backend from the project's real data
     (ReportService.generate). `kind` is the backend's template id — "szi" and
     "pp" — surfaced under readable names. */
  const openExportModal = () => setState({ exportModalOpen: true, exportKind: "szi", exportScope: "report" });
  const closeExportModal = () => setState({ exportModalOpen: false });

  /* ---- recon exports (hosts / IPs / endpoints) ----
     The dialog exports exactly what the view's filters left on screen, so the
     filter row above the table is the selection UI — no second set of controls
     that could disagree with it. Generated client-side from data already loaded. */
  const downloadText = (text: string, filename: string, mime = "text/plain") => {
    const url = URL.createObjectURL(new Blob([text], { type: `${mime};charset=utf-8` }));
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const slug = (s: string) => (s.replace(/[^\w.-]+/g, "_").replace(/^_+|_+$/g, "") || "export").slice(0, 60);

  /** Endpoints as a minimal OpenAPI 3 document — one path per endpoint. */
  const endpointsAsOpenApi = (): string => {
    const paths: Record<string, Record<string, unknown>> = {};
    endpointGroups.forEach((g) =>
      g.endpoints.forEach((e) => {
        // OpenAPI keys by path, so the host goes into the operation's server list.
        const path = e.p.startsWith("/") ? e.p : `/${e.p}`;
        paths[path] = paths[path] ?? {};
        paths[path][e.m.toLowerCase()] = {
          summary: `${e.m} ${e.p}`,
          servers: [{ url: `https://${g.host}` }],
          responses: { "200": { description: "OK" } },
        };
      })
    );
    return JSON.stringify({ openapi: "3.0.3", info: { title: `${projName} — endpoints`, version: "1.0.0" }, paths }, null, 2);
  };

  const doReconExport = () => {
    const name = slug(projName);
    if (state.exportScope === "hosts") {
      downloadText(hostsList.map(({ h }) => h.host).join("\n"), `${name}_hosts.txt`);
    } else if (state.exportScope === "ips") {
      downloadText(ipsRows.map((r) => r.ip).join("\n"), `${name}_ips.txt`);
    } else if (state.exportFormat === "openapi") {
      downloadText(endpointsAsOpenApi(), `${name}_endpoints.json`, "application/json");
    } else {
      downloadText(endpointGroups.flatMap((g) => g.endpoints.map((e) => `${e.m} https://${g.host}${e.p}`)).join("\n"), `${name}_endpoints.txt`);
    }
    setState({ exportModalOpen: false });
  };

  const openReconExport = (scope: ExportScope) => setState({ exportModalOpen: true, exportScope: scope, exportFormat: "list" });
  const doExport = async () => {
    const pid = state.openProjectId;
    if (pid == null) return;
    const kind = state.exportKind;
    setState({ exportBusy: true });
    try {
      const blob = kind === "szi" ? await apiDownloadCertificationReport(pid) : await apiDownloadAcceptanceReport(pid);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${projName || "report"}_${kind}.docx`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setState({ exportModalOpen: false, exportBusy: false });
    } catch (e) {
      setState({ exportBusy: false });
      pushToast(getApiErrorMessage(e, "Не удалось сформировать отчёт"), "error");
    }
  };

  // ================= detail: hosts / recon =================
  const toggleHost = (id: number) =>
    setState((s) => ({ expanded: s.expanded.includes(id) ? s.expanded.filter((x) => x !== id) : [...s.expanded, id] }));
  const openHostDetail = (id: number) => setState({ openHostId: id });
  const closeHostDetail = () => setState({ openHostId: null });
  const toggleReconMenu = () => setState((s) => ({ reconMenuOpen: !s.reconMenuOpen }));

  const toggleEpGroup = (host: string) =>
    setState((s) => ({ epExpanded: s.epExpanded.includes(host) ? s.epExpanded.filter((x) => x !== host) : [...s.epExpanded, host] }));
  /* The raw request is loaded from the endpoint itself — what was stored, not a
     made-up template. When it has never been filled in, a skeleton request line
     is offered as a starting point. The response has no backend field, so it
     starts empty and stays local. */
  const openEndpoint = (ep: { method: Method; path: string; host: string; hostId: number; endpointId: number }) => {
    setState({ epOpen: true, epData: ep, epRequest: "", epResponse: "", epSaving: false });
    const pid = state.openProjectId;
    if (pid == null) return;
    void (async () => {
      try {
        const list = await apiGetEndpoints(pid, ep.hostId);
        const stored = list.find((e) => e.id === ep.endpointId);
        const headers = (stored?.request_headers ?? []).map((h) => `${h.name}: ${h.value}`).join("\n");
        const body = stored?.request_body ?? "";
        const raw = [`${ep.method} ${ep.path} HTTP/1.1`, `Host: ${ep.host}`, headers, "", body].filter((p, i) => p !== "" || i === 3).join("\n");
        setStateRaw((s) => (s.epOpen && s.epData.endpointId === ep.endpointId ? { ...s, epRequest: raw.trimEnd() } : s));
      } catch {
        /* best-effort: an empty box is better than a fabricated one */
      }
    })();
  };
  const closeEndpoint = () => setState({ epOpen: false });

  const saveEndpointRequest = async () => {
    const pid = state.openProjectId;
    const { hostId, endpointId } = state.epData;
    if (pid == null || !endpointId) return;
    setState({ epSaving: true });
    try {
      await apiUpdateEndpoint(pid, hostId, endpointId, { request_raw: state.epRequest });
      setState({ epSaving: false });
      pushToast("Запрос сохранён", "success");
      reloadHosts();
    } catch (e) {
      setState({ epSaving: false });
      pushToast(getApiErrorMessage(e, "Не удалось сохранить запрос"), "error");
    }
  };

  const copyText = (text: string, what: string) => {
    try {
      void navigator.clipboard?.writeText(text);
      pushToast(`${what} скопирован в буфер`, "success");
    } catch {
      pushToast("Буфер обмена недоступен", "error");
    }
  };
  const copyCurl = (ep: { method: Method; path: string; host: string }) => {
    try {
      void navigator.clipboard?.writeText(`curl -X ${ep.method} 'https://${ep.host}${ep.path}'`);
    } catch {
      /* clipboard unavailable */
    }
  };
  const deleteEndpoint = async (hostId: number, endpointId: number) => {
    const pid = state.openProjectId;
    if (pid == null) return;
    try {
      await apiDeleteEndpoint(pid, hostId, endpointId);
      reloadHosts();
    } catch (e) {
      pushToast(getApiErrorMessage(e, "Не удалось удалить эндпоинт"), "error");
    }
  };

  // ================= entity editor (host / vuln / note / member) =================
  const updateForm = (k: string, v: string) => setState((s) => ({ editorForm: { ...s.editorForm, [k]: v } }));
  const setTagDraft = (k: string, v: string) => setState((s) => ({ tagDrafts: { ...s.tagDrafts, [k]: v } }));
  const addEditorTag = (k: string, val: string) => {
    const v = val.trim();
    if (!v) return;
    setState((s) => {
      const cur = s.editorForm[k];
      const arr = Array.isArray(cur) ? cur : [];
      return { editorForm: { ...s.editorForm, [k]: [...arr, v] }, tagDrafts: { ...s.tagDrafts, [k]: "" } };
    });
  };
  const removeEditorTag = (k: string, idx: number) =>
    setState((s) => {
      const cur = s.editorForm[k];
      const arr = Array.isArray(cur) ? cur : [];
      return { editorForm: { ...s.editorForm, [k]: arr.filter((_, i) => i !== idx) } };
    });
  const openEditor = (type: EditorType, mode: "add" | "edit", index: number) => {
    let form: Record<string, string | string[]> = {};
    if (mode === "edit") {
      if (type === "host") {
        const e = hosts[index];
        if (!e) return;
        form = { host: e.host, ip: e.ip, ports: e.ports.map((p) => `${p.n}/${p.proto}`), status: e.status };
      } else if (type === "vuln") {
        const e = d.vulns[index];
        if (!e) return;
        form = { title: e.title, host: e.host, sev: e.sev, status: e.status };
      } else if (type === "note") {
        const e = d.notes[index];
        if (!e) return;
        form = { title: e.title, excerpt: e.excerpt };
      }
    } else if (type === "host") form = { status: "up", ports: [] };
    else if (type === "ip") form = { hostName: "", ip: "", label: "" };
    else if (type === "endpoint") form = { hostName: "", method: "GET", path: "" };
    else if (type === "vuln") form = { sev: "medium", status: "open" };
    else if (type === "member") form = { userKey: "" };
    setState({ editorOpen: true, editorType: type, editorMode: mode, editorIndex: index, editorForm: form, tagDrafts: {} });
  };
  const closeEditor = () => setState({ editorOpen: false });

  /** "443/tcp" / "443" → a createPort payload; anything unparseable is skipped. */
  const parsePortTag = (tag: string): { port_number: number; protocol: "tcp" | "udp" } | null => {
    const m = tag.trim().match(/^(\d{1,5})(?:\s*\/\s*(tcp|udp))?$/i);
    if (!m) return null;
    const n = Number(m[1]);
    if (!Number.isFinite(n) || n < 1 || n > 65535) return null;
    return { port_number: n, protocol: (m[2]?.toLowerCase() as "tcp" | "udp") || "tcp" };
  };

  /* The "Hostname" field is sent as `hostname`, so a bare domain (test.com) is a
     valid hostname-only host. Ports live under an IP on the backend, so each port
     tag needs a follow-up createPort call against the host's primary IP — which
     only exists if an IP was given. */
  const saveHostEditor = async () => {
    const { editorMode: mode, editorIndex: index, editorForm: f } = state;
    const pid = state.openProjectId;
    if (pid == null) {
      setState({ editorOpen: false });
      return;
    }
    const hostname = fstr(f.host).trim();
    const ip = fstr(f.ip).trim();
    const status = (fstr(f.status) as Host["status"]) || "unknown";
    const portTags = Array.isArray(f.ports) ? f.ports : [];
    try {
      const saved =
        mode === "add"
          ? await apiCreateHost(pid, { hostname, ip_address: ip || undefined, status })
          : await (async () => {
              const target = hosts[index];
              if (!target) return null;
              return apiUpdateHost(pid, target.id, { hostname, ip_address: ip || undefined, status });
            })();
      if (!saved) {
        setState({ editorOpen: false });
        return;
      }
      // Ports hang off an IP; without one there is nothing to attach them to.
      const primaryIp = saved.ip_addresses.find((a) => a.is_primary) ?? saved.ip_addresses[0];
      const known = new Set(saved.ip_addresses.flatMap((a) => a.ports).map((p) => `${p.port_number}/${p.protocol}`));
      const wanted = portTags.map(parsePortTag).filter((p): p is { port_number: number; protocol: "tcp" | "udp" } => p !== null);
      const missing = wanted.filter((p) => !known.has(`${p.port_number}/${p.protocol}`));
      if (missing.length && !primaryIp) {
        pushToast("Порты не сохранены: сначала укажите IP-адрес хоста", "error");
      } else if (missing.length && primaryIp) {
        await Promise.all(missing.map((p) => apiCreatePort(pid, saved.id, { ip_address_id: primaryIp.id, ...p })));
      }
      if (portTags.length && wanted.length < portTags.length) {
        pushToast("Часть портов пропущена: ожидается формат 443/tcp", "error");
      }
      setState({ editorOpen: false });
      reloadHosts();
    } catch (e) {
      pushToast(getApiErrorMessage(e, mode === "add" ? "Не удалось добавить хост" : "Не удалось сохранить хост"), "error");
    }
  };

  /* A finding must hang off a host (`host_id` is required on create), so the
     "Affected host" field is a searchable picker over the project's real hosts.
     Severity is only settable on create: once a finding has a CVSS score the
     backend derives severity from it on every update (ProjectService keeps the
     score authoritative), so an edit-time severity field would be a no-op. It is
     changed by editing the CVSS vector on the finding's card. */
  const saveVulnEditor = async () => {
    const { editorMode: mode, editorIndex: index, editorForm: f } = state;
    const pid = state.openProjectId;
    if (pid == null) return;
    const title = (fstr(f.title) || "Untitled").trim();
    const status = (fstr(f.status) as VStatus) || "open";
    try {
      if (mode === "add") {
        const host = hosts.find((h) => h.host === fstr(f.host));
        if (!host) {
          pushToast("Выберите хост, к которому относится находка", "error");
          return;
        }
        await apiCreateVulnerability(pid, { title, status, severity: (fstr(f.sev) as Severity) || "medium", host_id: host.id });
      } else {
        const target = d.vulns[index];
        if (!target) return;
        // No `severity` here on purpose: sending one would either be ignored (when
        // a CVSS score exists) or silently overwrite the real severity.
        await apiUpdateVulnerability(pid, target.id, { title, status });
        await relinkVulnHost(pid, target.id, fstr(f.host));
      }
      setState({ editorOpen: false });
      reloadVulns();
    } catch (e) {
      pushToast(getApiErrorMessage(e, mode === "add" ? "Не удалось добавить уязвимость" : "Не удалось сохранить уязвимость"), "error");
    }
  };

  /* `host_id` only exists on create, so moving a finding to another host means
     repointing its host asset link. Without this the "Affected host" field would
     silently do nothing when editing. */
  const relinkVulnHost = async (pid: number, vulnId: number, hostName: string) => {
    const host = hosts.find((h) => h.host === hostName);
    if (!host) return;
    const det = await apiGetVulnerability(pid, vulnId);
    const link = det.assets.find((a) => a.asset_type === "host");
    if (link?.asset_id === host.id) return;
    await apiAddVulnerabilityAsset(pid, vulnId, { asset_type: "host", asset_id: host.id });
    if (link) await apiDeleteVulnerabilityAsset(pid, vulnId, link.id);
  };

  const saveNoteEditorEntity = async () => {
    const { editorMode: mode, editorIndex: index, editorForm: f } = state;
    const pid = state.openProjectId;
    if (pid == null) return;
    const payload = { title: (fstr(f.title) || "Untitled").trim(), content: fstr(f.excerpt).trim() };
    try {
      if (mode === "add") await apiCreateProjectNote(pid, payload);
      else {
        const target = d.notes[index];
        if (!target) return;
        await apiUpdateProjectNote(pid, target.id, payload);
      }
      setState({ editorOpen: false });
      reloadNotes();
    } catch (e) {
      pushToast(getApiErrorMessage(e, mode === "add" ? "Не удалось добавить заметку" : "Не удалось сохранить заметку"), "error");
    }
  };

  /* Adding a member only links an existing user to the project — the lead /
     pentester role is global and is set on the workspace Members page, never here. */
  const saveMemberEditor = async () => {
    const pid = state.openProjectId;
    if (pid == null) return;
    // The field is free text with suggestions, so a half-typed name lands here —
    // say so instead of closing the dialog as if it had worked.
    const typed = fstr(state.editorForm.userKey).trim();
    const u = state.workspaceUsers.find((x) => x.key.toLowerCase() === typed.toLowerCase());
    if (!u) {
      pushToast(typed ? `Пользователь «${typed}» не найден` : "Выберите пользователя", "error");
      return;
    }
    try {
      await apiAddProjectMember(pid, u.id);
      setState({ editorOpen: false });
      reloadMembers();
    } catch (e) {
      pushToast(getApiErrorMessage(e, "Не удалось добавить участника"), "error");
    }
  };

  /* There is no per-IP endpoint: a host's addresses are replaced wholesale via
     updateHost. The current list is re-fetched first so labels and is_primary of
     the existing addresses survive the round-trip. */
  const saveIpEditor = async () => {
    const pid = state.openProjectId;
    const f = state.editorForm;
    if (pid == null) return;
    const host = hosts.find((h) => h.host === fstr(f.hostName));
    const ip = fstr(f.ip).trim();
    if (!host || !ip) {
      pushToast(host ? "Укажите IP-адрес" : "Выберите хост", "error");
      return;
    }
    try {
      const current = await apiGetHost(pid, host.id);
      if (current.ip_addresses.some((a) => a.ip_address === ip)) {
        pushToast("Такой IP уже есть у этого хоста", "error");
        return;
      }
      await apiUpdateHost(pid, host.id, {
        ip_addresses: [
          ...current.ip_addresses.map((a) => ({ ip_address: a.ip_address, label: a.label, is_primary: a.is_primary })),
          { ip_address: ip, label: fstr(f.label).trim() || null, is_primary: current.ip_addresses.length === 0 },
        ],
      });
      setState({ editorOpen: false });
      reloadHosts();
    } catch (e) {
      pushToast(getApiErrorMessage(e, "Не удалось добавить IP-адрес"), "error");
    }
  };

  const saveEndpointEditor = async () => {
    const pid = state.openProjectId;
    const f = state.editorForm;
    if (pid == null) return;
    const host = hosts.find((h) => h.host === fstr(f.hostName));
    const path = fstr(f.path).trim();
    if (!host || !path) {
      pushToast(host ? "Укажите путь эндпоинта" : "Выберите хост", "error");
      return;
    }
    try {
      await apiCreateEndpoint(pid, host.id, { path, method: (fstr(f.method) as Method) || "GET" });
      setState({ editorOpen: false });
      reloadHosts();
    } catch (e) {
      pushToast(getApiErrorMessage(e, "Не удалось добавить эндпоинт"), "error");
    }
  };

  const saveEditor = async () => {
    if (state.editorType === "host") return saveHostEditor();
    if (state.editorType === "ip") return saveIpEditor();
    if (state.editorType === "endpoint") return saveEndpointEditor();
    if (state.editorType === "vuln") return saveVulnEditor();
    if (state.editorType === "note") return saveNoteEditorEntity();
    if (state.editorType === "member") return saveMemberEditor();
  };

  // ================= delete confirm =================
  const askDelete = (type: EditorType, index: number, label: string) =>
    setState({ confirmOpen: true, confirmType: type, confirmIndex: index, confirmLabel: label, confirmProjectId: null });
  const closeConfirm = () => setState({ confirmOpen: false, confirmProjectId: null });
  const confirmDelete = async () => {
    if (state.confirmProjectId) {
      const id = state.confirmProjectId;
      setState({ confirmOpen: false, confirmProjectId: null });
      try {
        await apiDeleteProject(id);
        reloadProjects();
      } catch (e) {
        pushToast(getApiErrorMessage(e, "Не удалось удалить проект"), "error");
      }
      return;
    }
    const { confirmType: t, confirmIndex: i } = state;
    const pid = state.openProjectId;
    setState({ confirmOpen: false });
    if (!t || pid == null) return;
    // Every collection is backend-backed: delete through the API, then reload.
    const targets: Record<EditorType, { id: number | undefined; call: (id: number) => Promise<void>; reload: () => void; err: string }> = {
      host: { id: hosts[i]?.id, call: (id) => apiDeleteHost(pid, id), reload: reloadHosts, err: "Не удалось удалить хост" },
      // Rows in the IPs view address one address of a host, not the host itself.
      ip: { id: ipsRows[i] ? i : undefined, call: () => removeHostIp(pid, ipsRows[i].hostId, ipsRows[i].ip), reload: reloadHosts, err: "Не удалось удалить IP-адрес" },
      endpoint: { id: endpointRows[i]?.endpointId, call: (id) => apiDeleteEndpoint(pid, endpointRows[i].hostId, id), reload: reloadHosts, err: "Не удалось удалить эндпоинт" },
      vuln: { id: d.vulns[i]?.id, call: (id) => apiDeleteVulnerability(pid, id), reload: reloadVulns, err: "Не удалось удалить уязвимость" },
      note: { id: d.notes[i]?.id, call: (id) => apiDeleteProjectNote(pid, id), reload: reloadNotes, err: "Не удалось удалить заметку" },
      member: {
        id: d.members[i]?.id,
        call: (id) => apiRemoveProjectMember(pid, id),
        /* Removing yourself removes the project from your list (rule 1.1: a
           non-admin only sees projects they belong to), so leave the detail —
           staying would mean 403s on the next request and a project the list
           still shows. Admins keep access regardless of membership. */
        reload: () => {
          const leftMyself = d.members[i]?.id === authUser?.id && !isAdmin;
          if (!leftMyself) {
            reloadMembers();
            return;
          }
          selProjects();
          reloadProjects();
          pushToast("Вы вышли из проекта — он больше не в вашем списке", "success");
        },
        err: "Не удалось удалить участника",
      },
    };
    const target = targets[t];
    if (target.id == null) return;
    try {
      await target.call(target.id);
      target.reload();
    } catch (e) {
      pushToast(getApiErrorMessage(e, target.err), "error");
    }
  };

  /** Drops one address by writing back the host's remaining ip_addresses. */
  const removeHostIp = async (pid: number, hostId: number, ip: string) => {
    const current = await apiGetHost(pid, hostId);
    const rest = current.ip_addresses.filter((a) => a.ip_address !== ip);
    await apiUpdateHost(pid, hostId, {
      ip_addresses: rest.map((a) => ({ ip_address: a.ip_address, label: a.label, is_primary: a.is_primary })),
    });
  };

  // ================= notes =================
  const openNoteEditor = (mode: "add" | "edit", index: number) => {
    const n = mode === "edit" ? d.notes[index] : null;
    setState({
      noteEditorOpen: true,
      noteEditorMode: mode,
      noteEditorIndex: index,
      noteForm: { title: n ? n.title : "", excerpt: n ? n.excerpt : "", author: n ? n.author : me },
    });
  };
  const closeNoteEditor = () => setState({ noteEditorOpen: false });
  /* Opening a note always shows it rendered — including your own. Editing is a
     deliberate act (the pencil / the viewer's Edit button), not what a click on
     the note means. `id` is the backend id: it goes into the URL. */
  const openNoteViewer = (id: number) => setState({ section: "notes", openNoteId: id, noteEditorOpen: false });
  const closeNoteViewer = () => setState({ openNoteId: null, noteEditorOpen: false });
  const updateNoteForm = (k: keyof NoteForm, v: string) => setState((s) => ({ noteForm: { ...s.noteForm, [k]: v } }));
  const saveNote = async () => {
    const { noteEditorMode: mode, noteEditorIndex: index, noteForm: f } = state;
    const pid = state.openProjectId;
    if (pid == null) return;
    const payload = { title: (f.title || "Untitled").trim(), content: (f.excerpt || "").trim() };
    try {
      if (mode === "add") await apiCreateProjectNote(pid, payload);
      else {
        const target = d.notes[index];
        if (!target) return;
        await apiUpdateProjectNote(pid, target.id, payload);
      }
      setState({ noteEditorOpen: false });
      reloadNotes();
    } catch (e) {
      pushToast(getApiErrorMessage(e, mode === "add" ? "Не удалось создать заметку" : "Не удалось сохранить заметку"), "error");
    }
  };

  // ================= vulnerability detail =================
  /** The overview's "open findings" tile — everything still needing work. */
  const goToOpenVulns = () => setState({ section: "vulns", vulnFilterStatuses: [...VSTATUS_OPEN], vulnFilterAuthor: "", vulnFilterSeverities: [], vulnFilterHost: "" });
  const goToMyFindings = () => setState({ section: "vulns", vulnFilterAuthor: me, vulnFilterStatuses: [], vulnFilterSeverities: [], vulnFilterHost: "" });
  const vulnFormFrom = (v: Vuln): VulnDetailForm => {
    const stepsList = Array.isArray(v.steps) ? v.steps.slice() : [];
    return {
      title: v.title,
      host: v.host,
      sev: v.sev,
      status: v.status,
      stepsList: stepsList.length ? stepsList : [""],
      stepImages: v.stepImages ?? {},
      description: v.description || "",
      impact: v.impact || "",
      remediation: v.remediation || "",
      cwe: v.cwe || "",
      vector: v.vector || "",
    };
  };
  /** `id` is the real backend id — it goes into the URL, so findings can be deep-linked. */
  const openVulnDetail = (id: number) => {
    const v = d.vulns.find((x) => x.id === id);
    setState({ section: "vulns", openVulnId: id, vulnDetailForm: v ? vulnFormFrom(v) : {} });
  };
  const closeVulnDetail = () => setState({ openVulnId: null });
  const updateVulnDetailForm = <K extends keyof VulnDetailForm>(k: K, v: VulnDetailForm[K]) =>
    setState((s) => ({ vulnDetailForm: { ...s.vulnDetailForm, [k]: v } }));
  const addVdStep = () => setState((s) => ({ vulnDetailForm: { ...s.vulnDetailForm, stepsList: [...(s.vulnDetailForm.stepsList ?? []), ""] } }));
  const removeVdStep = (i: number) =>
    setState((s) => {
      const imgs = { ...(s.vulnDetailForm.stepImages ?? {}) };
      delete imgs[i];
      const shifted: Record<number, string[]> = {};
      Object.keys(imgs).forEach((k) => {
        const n = +k;
        shifted[n > i ? n - 1 : n] = imgs[n];
      });
      return { vulnDetailForm: { ...s.vulnDetailForm, stepsList: (s.vulnDetailForm.stepsList ?? []).filter((_, idx) => idx !== i), stepImages: shifted } };
    });
  const updateVdStep = (i: number, val: string) =>
    setState((s) => {
      const list = [...(s.vulnDetailForm.stepsList ?? [])];
      list[i] = val;
      return { vulnDetailForm: { ...s.vulnDetailForm, stepsList: list } };
    });
  const pasteVdStepImage = (i: number, e: ReactClipboardEvent<HTMLInputElement>) => {
    const items = e.clipboardData?.items ?? [];
    for (const it of Array.from(items)) {
      if (it.type && it.type.indexOf("image") === 0) {
        e.preventDefault();
        const file = it.getAsFile();
        if (!file) continue;
        const reader = new FileReader();
        reader.onload = (ev) =>
          setState((s) => {
            const imgs = { ...(s.vulnDetailForm.stepImages ?? {}) };
            imgs[i] = [...(imgs[i] ?? []), String(ev.target?.result ?? "")];
            return { vulnDetailForm: { ...s.vulnDetailForm, stepImages: imgs } };
          });
        reader.readAsDataURL(file);
      }
    }
  };
  const removeVdStepImage = (i: number, imgIdx: number) =>
    setState((s) => {
      const imgs = { ...(s.vulnDetailForm.stepImages ?? {}) };
      imgs[i] = (imgs[i] ?? []).filter((_, idx) => idx !== imgIdx);
      return { vulnDetailForm: { ...s.vulnDetailForm, stepImages: imgs } };
    });
  const saveVulnDetail = async () => {
    const { openVulnId: id, vulnDetailForm: f } = state;
    const pid = state.openProjectId;
    if (id == null || pid == null) return;
    const current = d.vulns.find((v) => v.id === id);
    if (!current) return;
    // A valid vector wins over the severity picker — that is what the score means.
    const c = computeCvss4(f.vector);
    const vector = (f.vector ?? "").trim();
    try {
      await apiUpdateVulnerability(pid, id, {
        title: (f.title ?? current.title).trim(),
        severity: (c ? c.sev : f.sev) || current.sev,
        status: f.status || current.status,
        description: f.description ?? "",
        impact: f.impact ?? "",
        recommendations: f.remediation ?? "",
        cwe_id: (f.cwe ?? "").trim() || null,
        cvss_vector: vector || null,
        cvss_version: vector ? "4.0" : null,
        cvss_score: c ? c.score : null,
        // Step images are still client-only (they are pasted data URLs, not uploads),
        // so only the step text round-trips through the backend.
        workflow_steps: (f.stepsList ?? [])
          .filter((s) => s.trim())
          .map((s, i) => ({ id: `step-${i + 1}`, description: s })),
      });
      setState({ openVulnId: null });
      reloadVulns();
    } catch (e) {
      pushToast(getApiErrorMessage(e, "Не удалось сохранить уязвимость"), "error");
    }
  };

  // ================= profile / API keys / 2FA / workspace users =================
  /* "API keys" are the backend's agent tokens. The raw token is returned once, on
     creation, and only its prefix is stored — so the list shows `prefix…`, never a
     full key. */
  const reloadApiKeys = () => {
    void (async () => {
      try {
        const rows = await apiListAgentTokens();
        setStateRaw((s) => ({
          ...s,
          apiKeys: rows
            .filter((t) => !t.revoked_at)
            .map((t) => ({ id: t.id, name: t.name, key: `${t.token_prefix}…`, scopes: t.scopes, created: toDispDate(t.created_at.slice(0, 10)) })),
        }));
      } catch {
        // Best-effort: agent tokens are admin-only, so a 403 just means an empty list.
        setStateRaw((s) => ({ ...s, apiKeys: [] }));
      }
    })();
  };
  useEffect(() => {
    if (state.view === "profile" && state.profileTab === "api") reloadApiKeys();
     
  }, [state.view, state.profileTab]);
  const openApiKeyModal = () => setState({ apiKeyModalOpen: true, apiKeyName: "", apiKeyScopes: {} });
  const closeApiKeyModal = () => setState({ apiKeyModalOpen: false });
  const toggleApiScope = (s: string) => setState((st) => ({ apiKeyScopes: { ...st.apiKeyScopes, [s]: !st.apiKeyScopes[s] } }));
  const createApiKey = async () => {
    const name = state.apiKeyName.trim();
    if (!name) return;
    const scopes = API_SCOPES.filter((s) => state.apiKeyScopes[s]);
    if (!scopes.length) return;
    try {
      const created = await apiCreateAgentToken({ name, scopes, project_ids: [], all_projects: true });
      setState({ apiKeyModalOpen: false });
      // The token is shown once and never again — the backend keeps only its hash.
      pushToast(`Токен создан, скопируйте его сейчас: ${created.token}`, "success");
      reloadApiKeys();
    } catch (e) {
      pushToast(getApiErrorMessage(e, "Не удалось создать токен"), "error");
    }
  };
  const revokeApiKey = async (id: number) => {
    try {
      await apiRevokeAgentToken(id);
      reloadApiKeys();
    } catch (e) {
      pushToast(getApiErrorMessage(e, "Не удалось отозвать токен"), "error");
    }
  };

  const openWSUserEditor = (mode: "add" | "edit", index: number) => {
    const u = mode === "edit" ? state.workspaceUsers[index] : null;
    setState({
      wsUserModalOpen: true,
      wsUserMode: mode,
      wsUserIndex: index,
      wsUserName: u ? u.name : "",
      wsUserEmail: u ? u.email : "",
      wsUserRole: u ? u.role : "user",
      wsUserProjectRole: u ? u.projectRole : "pentester",
    });
  };
  const closeWSUserEditor = () => setState({ wsUserModalOpen: false });
  // The workspace role maps onto the backend account role; the project role is a
  // global user attribute and is sent alongside it.
  const saveWSUser = async () => {
    const name = state.wsUserName.trim();
    const email = state.wsUserEmail.trim();
    if (!name || !email) return;
    const role = state.wsUserRole === "admin" ? "admin" : "pentester";
    const projectRole = state.wsUserProjectRole;
    const adding = state.wsUserMode === "add";
    try {
      if (adding) {
        await apiCreateUser({ username: name, email, role, project_role: projectRole, send_invite_email: true });
      } else {
        const u = state.workspaceUsers[state.wsUserIndex];
        if (!u) return;
        await apiUpdateUser(u.id, { username: name, role, project_role: projectRole });
      }
      setState({ wsUserModalOpen: false });
      reloadUsers();
    } catch (e) {
      pushToast(getApiErrorMessage(e, adding ? "Не удалось создать пользователя" : "Не удалось сохранить пользователя"), "error");
    }
  };
  const deleteWSUser = async (index: number) => {
    const u = state.workspaceUsers[index];
    if (!u) return;
    try {
      await apiDeleteUser(u.id);
      reloadUsers();
    } catch (e) {
      pushToast(getApiErrorMessage(e, "Не удалось удалить пользователя"), "error");
    }
  };

  const startTwoFA = () => setState({ twoFASetupOpen: true, twoFACode: "" });
  const cancelTwoFA = () => setState({ twoFASetupOpen: false });
  const confirmTwoFA = () => {
    if (state.twoFACode.trim().length < 6) return;
    setState({ twoFAEnabled: true, twoFASetupOpen: false });
  };
  const disableTwoFA = () => setState({ twoFAEnabled: false });

  // ================= notifications =================
  /* Each notification carries the ids of what it is about (context.project_id /
     vulnerability_id), so clicking it navigates straight to the finding. The
     previous version matched a seed project *by name* against the real projects,
     which never matched — openProjectId stayed null and the click fell back to
     the projects list. */
  const goToNotif = (n: ApiNotification) => {
    const pid = n.context?.project_id ?? null;
    const vid = n.context?.vulnerability_id ?? null;
    const nid = n.context?.note_id ?? null;
    void apiMarkNotificationRead(n.id).catch(() => {
      /* best-effort: the read flag is not worth blocking navigation on */
    });
    // Land on whatever the notification is actually about: the finding, the note,
    // or — for "added to project" / project status — the project itself.
    const section: SectionId = vid != null ? "vulns" : nid != null ? "notes" : "overview";
    setStateRaw((s) => ({
      ...s,
      notifs: s.notifs.map((x) => (x.id === n.id ? { ...x, is_read: true } : x)),
      notifOpen: false,
      ...(pid == null
        ? {}
        : {
            view: "detail" as const,
            nav: "projects" as const,
            openProjectId: pid,
            section,
            expanded: [],
            openVulnId: vid,
            openNoteId: nid,
            vulnDetailForm: {},
            accessDenied: false,
          }),
    }));
    if (pid == null) pushToast("Уведомление не привязано к проекту", "error");
  };

  const markAllNotifsRead = () => {
    void apiMarkAllNotificationsRead().catch((e) => pushToast(getApiErrorMessage(e, "Не удалось отметить уведомления"), "error"));
    setStateRaw((s) => ({ ...s, notifs: s.notifs.map((x) => ({ ...x, is_read: true })) }));
  };

  // ---------------------------------------------------------------- derived
  const isActive = state.tab === "active";
  const q = state.query.trim().toLowerCase();
  // Rule 1.1 is enforced server-side: getProjects returns only visible projects.
  const allProjects = state.apiProjects ?? [];
  const isArchivedStatus = (s: ProjectStatus) => s === "archived" || s === "completed";
  const projRows = allProjects
    .filter((p) => (state.tab === "active" ? !isArchivedStatus(p.status) : isArchivedStatus(p.status)))
    .filter((p) => !q || p.name.toLowerCase().includes(q));
  if (state.projSort === "first") projRows.reverse();

  const activeCount = allProjects.filter((p) => !isArchivedStatus(p.status)).length;
  const archivedCount = allProjects.filter((p) => isArchivedStatus(p.status)).length;
  // Tab-scoped (no search filter): stat tiles must not react to `query`.
  const tabProjects = allProjects.filter((p) => (isActive ? !isArchivedStatus(p.status) : isArchivedStatus(p.status)));

  const navBg = (id: NavId) => (state.nav === id ? "#EEF3FC" : "transparent");
  const navColor = (id: NavId) => (state.nav === id ? "#2E5FBF" : "#5A6B84");

  const isList = state.view === "list" && state.nav === "projects";
  const isStub = state.view === "list" && state.nav !== "projects" && state.nav !== "members";
  const stubTitle = ({ tasks: "Tasks", mine: "My Tasks", docs: "Docs" } as Record<string, string>)[state.nav] || "";
  const stubDesc =
    ({ tasks: "Track and assign engagement tasks across the team.", mine: "Your personally assigned tasks and reviews.", docs: "Reports, templates and shared documentation." } as Record<string, string>)[
      state.nav
    ] || "";

  /* Notification rows, built from the backend payload. There are exactly four
     reasons to be notified (NotificationKind), and each reads differently — the
     row is a sentence: "<who> <action> <subject>". */
  const NOTIF_AVATAR_COLORS = ["#2E5FBF", "#7A4DB8", "#C06A2E", "#C0455B", "#2E8B57"];
  const notifs = state.notifs.map((n) => {
    const ctx = n.context;
    const who = ctx?.commenter_username || "System";
    const project = ctx?.project_name || state.apiProjects?.find((p) => p.id === ctx?.project_id)?.name || "";
    const statusLabel = ctx?.status ? VSTATUS_LABEL[ctx.status as VStatus] ?? PROJ_STATUS[ctx.status]?.label ?? ctx.status : "";
    const row = { action: "", subject: "" };
    switch (n.type) {
      case "project_member_added":
        row.action = "added you to";
        row.subject = project;
        break;
      case "vuln_status_changed":
        row.action = `set your finding to ${statusLabel} —`;
        row.subject = ctx?.vulnerability_title || "";
        break;
      case "project_status_changed":
        row.action = `changed the project status to ${statusLabel} —`;
        row.subject = project;
        break;
      default:
        row.action = "mentioned you in";
        row.subject = ctx?.vulnerability_title || ctx?.note_title || "";
    }
    return {
      key: n.id,
      initials: initialsOf(who),
      avBg: NOTIF_AVATAR_COLORS[n.id % NOTIF_AVATAR_COLORS.length],
      user: `@${who}`,
      action: row.action,
      where: row.subject,
      // The project is already the subject of project-level events; don't repeat it.
      meta: [n.type === "mention" || n.type === "vuln_status_changed" ? project : "", relTime(n.created_at)].filter(Boolean).join(" · "),
      unread: !n.is_read,
      onClick: () => goToNotif(n),
    };
  });
  const newCount = notifs.filter((n) => n.unread).length;
  const hasUnread = newCount > 0;

  const sideW = state.sidebarCollapsed ? "76px" : "236px";

  // ---- section tab styling ----
  const sec = state.section;
  const secStyle = (k: SectionId) => ({
    color: sec === k ? "#2E5FBF" : "#5A6B84",
    bar: sec === k ? "#4C74C7" : "transparent",
    badgeColor: sec === k ? "#2E5FBF" : "#8A97AB",
    badgeBg: sec === k ? "#DBE7FB" : "#EEF1F6",
  });

  // ---- hosts / recon derived ----
  const rv = state.reconView;
  const portPillsOf = (ports: Host["ports"]) => ports.map((p) => ({ label: `${p.n}/${p.proto}`, ...(PORT[p.state] ?? PORT.closed) }));

  // Hosts are searched by name here; addresses have their own search in the IPs view.
  const hostsList = hosts
    .map((h, idx) => ({ h, idx }))
    .filter((x) => {
      const hq = state.hostQuery.trim().toLowerCase();
      return !hq || x.h.host.toLowerCase().includes(hq);
    });

  const _hd = state.openHostId != null ? hosts.find((h) => h.id === state.openHostId) : undefined;

  const sevCounts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  d.vulns.forEach((v) => (sevCounts[v.sev] = (sevCounts[v.sev] || 0) + 1));
  const sevBars = (["critical", "high", "medium", "low", "info"] as Severity[]).map((k) => ({
    label: cap(k),
    color: SEV[k].color,
    tileBg: SEV[k].bg,
    count: sevCounts[k],
    onClick: () => setState({ section: "vulns", vulnFilterSeverities: [k], vulnFilterStatuses: [], vulnFilterAuthor: "", vulnFilterHost: "" }),
  }));

  const vulnStCounts = Object.fromEntries(VSTATUS_ORDER.map((k) => [k, 0])) as Record<VStatus, number>;
  d.vulns.forEach((v) => (vulnStCounts[v.status] = (vulnStCounts[v.status] || 0) + 1));
  const openVulnCount = VSTATUS_OPEN.reduce((n, k) => n + vulnStCounts[k], 0);
  const myFindingsCount = d.vulns.filter((v) => v.author === me).length;

  const vfA = state.vulnFilterAuthor.trim().toLowerCase();
  const vfS = state.vulnFilterStatuses;
  const vfSev = state.vulnFilterSeverities;
  const vfH = state.vulnFilterHost.trim().toLowerCase();
  // Within a group the selected values are OR-ed; the groups are AND-ed. An empty
  // group filters nothing, which is what makes "All" light up on its own.
  const vulns = d.vulns
    .map((v, idx) => ({ v, idx }))
    .filter(
      ({ v }) =>
        (!vfA || v.author.toLowerCase().includes(vfA)) &&
        (vfS.length === 0 || vfS.includes(v.status)) &&
        (vfSev.length === 0 || vfSev.includes(v.sev)) &&
        (!vfH || v.host.toLowerCase().includes(vfH))
    )
    .map(({ v, idx }, i) => ({
      num: i + 1,
      sev: v.sev,
      title: v.title,
      host: v.host,
      status: v.status,
      author: v.author,
      updated: v.updated,
      // The card is addressed by backend id (it lands in the URL); the editor and
      // delete still address the list position.
      onOpen: () => openVulnDetail(v.id),
      onEdit: (e: ReactMouseEvent) => {
        e.stopPropagation();
        openEditor("vuln", "edit", idx);
      },
      onDelete: (e: ReactMouseEvent) => {
        e.stopPropagation();
        askDelete("vuln", idx, v.title);
      },
    }));

  /** Pill styling for a multi-select filter; `on` also covers the "All" pill (empty selection). */
  const vfPill = (on: boolean): CSSProperties => (on ? PILL_ON : PILL_OFF);

  // A host can carry several IPs (external / internal / mgmt) — the IPs view lists
  // them all, one row per address. Row actions target the address, not the host.
  // One search box matches either side of the row: the address or its host.
  const ipQ = state.ipQuery.trim().toLowerCase();
  const ipsRows = hosts
    .flatMap(({ ...h }, idx) => h.ips.map((ip) => ({ h, idx, ip })))
    .filter(({ ip }) => ip && ip !== "—")
    .filter(({ h, ip }) => !ipQ || ip.toLowerCase().includes(ipQ) || h.host.toLowerCase().includes(ipQ))
    .map(({ h, idx, ip }, i) => ({
      ip,
      hostId: h.id,
      host: h.host,
      statusColor: STDOT[h.status] ?? STDOT.unknown,
      status: h.status,
      onEdit: (e: ReactMouseEvent) => {
        e.stopPropagation();
        openEditor("host", "edit", idx);
      },
      onDelete: (e: ReactMouseEvent) => {
        e.stopPropagation();
        askDelete("ip", i, ip);
      },
    }));
  /** Flat endpoint list, so a confirm dialog can address one by position. */
  const endpointRows = hosts.flatMap((h) => h.endpoints.map((e) => ({ hostId: h.id, endpointId: e.id, host: h.host, label: `${e.m} ${e.p}` })));
  /* Endpoints view filters: method pills (empty = all), plus separate searches for
     the host and the endpoint path — they are different questions ("everything on
     this host" vs "where is /login"), so one combined box would answer neither. */
  const epHostQ = state.epHostQuery.trim().toLowerCase();
  const epPathQ = state.epPathQuery.trim().toLowerCase();
  const endpointGroups = hosts
    .filter((h) => !epHostQ || h.host.toLowerCase().includes(epHostQ))
    .map((h) => ({
      hostId: h.id,
      host: h.host,
      endpoints: h.endpoints.filter(
        (e) => (state.epMethods.length === 0 || state.epMethods.includes(e.m)) && (!epPathQ || e.p.toLowerCase().includes(epPathQ))
      ),
      expanded: state.epExpanded.includes(h.host),
    }))
    .filter((g) => g.endpoints.length > 0)
    .map((g) => ({ ...g, count: g.endpoints.length }));
  // Counts what the filters actually left on screen.
  const endpointTotal = endpointGroups.reduce((s, g) => s + g.count, 0);
  /** How many rows the current filters would export — declared here because the
      recon lists above are what it counts. */
  const exportCount = state.exportScope === "hosts" ? hostsList.length : state.exportScope === "ips" ? ipsRows.length : endpointTotal;

  // The chip shows the project's real status (active / freeze / …), not the
  // coarse active-vs-archived split the tabs use.
  const stCh = PROJ_STATUS[projRow?.status ?? "active"] ?? PROJ_STATUS.active;

  const sectionLabel =
    sec === "hosts"
      ? ({ hosts: "Hosts", ips: "IPs", endpoints: "Endpoints" } as Record<string, string>)[rv] || "Hosts"
      : ({ overview: "Overview", vulns: "Vulnerabilities", notes: "Notes", members: "Members", activity: "Activity" } as Record<string, string>)[sec] || "Overview";
  /** The item open inside the section, if any — the last crumb (e.g. the note's title). */
  const crumbLeaf =
    sec === "notes" && state.openNoteId != null
      ? d.notes.find((n) => n.id === state.openNoteId)?.title ?? ""
      : sec === "vulns" && state.openVulnId != null
        ? d.vulns.find((v) => v.id === state.openVulnId)?.title ?? ""
        : sec === "hosts" && _hd
          ? _hd.host
          : "";

  // ---- editor fields (options that depend on live data are filled in here) ----
  let efCfg = EDITOR_FIELDS[state.editorType] ?? [];
  if (state.editorType === "member") {
    const existing = d.members.map((m) => m.name);
    const avail = state.workspaceUsers.filter((u) => !existing.includes(u.name));
    efCfg = efCfg.map((f) => (f.k === "userKey" ? { ...f, opts: avail.map((u) => u.key) } : f));
  }
  if (state.editorType === "vuln") {
    // Severity is only meaningful on create: afterwards the CVSS vector drives it
    // (the backend recomputes it from the score), so the field would be a no-op.
    if (state.editorMode === "edit") efCfg = efCfg.filter((f) => f.k !== "sev");
    // A finding must point at a real host — the picker offers the project's hosts.
    efCfg = efCfg.map((f) => (f.k === "host" ? { ...f, opts: hosts.map((h) => h.host) } : f));
  }
  // IPs and endpoints hang off a host, so their pickers list the project's hosts.
  if (state.editorType === "ip" || state.editorType === "endpoint") {
    efCfg = efCfg.map((f) => (f.k === "hostName" ? { ...f, opts: hosts.map((h) => h.host) } : f));
  }
  const editorFields = efCfg.map((f) => ({
    key: f.k,
    label: f.label,
    isText: f.type === "text",
    isTextarea: f.type === "textarea",
    isSelect: f.type === "select",
    isTags: f.type === "tags",
    isCombo: f.type === "combo",
    value: fstr(state.editorForm[f.k]),
    placeholder: f.ph || "",
    onInput: (e: ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => updateForm(f.k, e.target.value),
    tagDraft: state.tagDrafts[f.k] || "",
    onTagDraft: (e: ChangeEvent<HTMLInputElement>) => setTagDraft(f.k, e.target.value),
    onTagKeyDown: (e: ReactKeyboardEvent<HTMLInputElement>) => {
      if (e.key === "Enter") {
        e.preventDefault();
        addEditorTag(f.k, e.currentTarget.value);
      }
    },
    tags: (Array.isArray(state.editorForm[f.k]) ? (state.editorForm[f.k] as string[]) : []).map((t, ti) => ({ value: t, onRemove: () => removeEditorTag(f.k, ti) })),
    options: (f.opts ?? []).map((o) => ({
      value: o,
      label:
        f.k === "userKey"
          ? (state.workspaceUsers.find((u) => u.key === o)?.email ? `${o} — ${state.workspaceUsers.find((u) => u.key === o)!.email}` : o)
          : cap(o),
    })),
  }));

  const so = secStyle("overview");
  const sh = secStyle("hosts");
  const sv = secStyle("vulns");
  const sn = secStyle("notes");
  const sm = secStyle("members");
  const sa = secStyle("activity");

  // Those who may view project members (admin / creator / lead) may also manage them.
  const canManageMembers = canViewMembers;

  const vd = state.vulnDetailForm;
  const vdCvss = computeCvss4(vd.vector);
  const vdSev: Severity = (vdCvss ? vdCvss.sev : vd.sev) || "medium";
  const vdScore = vdCvss ? vdCvss.score.toFixed(1) : "—";

  const pfNav = (tab: ProfileTab): CSSProperties =>
    state.profileTab === tab ? { background: "#EAF0FC", color: "#2E5FBF", boxShadow: "inset 3px 0 0 #2E5FBF" } : { background: "transparent", color: "#5A6B84", boxShadow: "inset 3px 0 0 transparent" };

  // ================================================================= RENDER

  const eyebrow = (crumbs: { label: string; onClick?: () => void; muted?: boolean }[]): ReactNode => (
    <div className="mono" style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 11, letterSpacing: 1.2, textTransform: "uppercase", color: "#a0abbd", fontWeight: 700, marginBottom: 10 }}>
      <span style={{ width: 6, height: 6, borderRadius: "50%", background: "#2E5FBF" }} />
      {crumbs.map((c, i) => (
        <span key={i} style={{ display: "contents" }}>
          {i > 0 && <span>/</span>}
          <span className={c.onClick ? "clk" : undefined} onClick={c.onClick} style={{ cursor: c.onClick ? "pointer" : undefined, color: c.muted ? "#7c8aa0" : undefined }}>
            {c.label}
          </span>
        </span>
      ))}
    </div>
  );

  // ---------- Projects list ----------
  const renderProjects = () => (
    <div className="route" style={{ padding: "40px 48px 36px", width: "100%" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 20 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 40, fontWeight: 800, letterSpacing: "-1px", color: "#0F1B2D" }}>Projects</h1>
          <div style={{ fontSize: 15, color: "#8A97AB", marginTop: 8 }}>
            {isActive ? `Showing active projects · ${activeCount} active` : `Showing archived projects · ${archivedCount} archived`}
          </div>
        </div>
        <button className="clk" onClick={() => setState({ modalOpen: true })} style={{ display: "flex", alignItems: "center", gap: 9, height: 46, padding: "0 22px", border: "none", borderRadius: 13, background: "#4C74C7", color: "#fff", font: "700 14px Inter,sans-serif", boxShadow: "0 6px 18px rgba(76,116,199,.3)" }}>
          <Icon name="plus" size={17} sw={2.4} />
          New project
        </button>
      </div>

      {/* stat cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5,minmax(0,1fr))", gap: 16, margin: "26px 0 22px" }}>
        {[
          { icon: "trend-up" as const, iconColor: "#3d6fd6", label: "Active", value: String(activeCount), spark: "0,24 22,24 32,16 50,16 60,9 74,9", stroke: "#3d6fd6", w: 74 },
          { icon: "archive" as const, iconColor: "#8A97AB", label: "Archived", value: String(archivedCount), spark: "0,22 36,22 46,13 74,13", stroke: "#b3bccd", w: 74 },
          { icon: "clock" as const, iconColor: "#E0748A", label: "Open issues", value: String(tabProjects.reduce((s, p) => s + p.openFindings, 0)), spark: "0,23 16,23 26,18 40,18 50,12 62,12 74,10", stroke: "#EF8A9C", w: 74 },
          { icon: "star" as const, iconColor: "#6E86C6", label: "Projects", value: String(tabProjects.length), spark: "0,24 14,24 22,19 34,19 42,13 56,13 64,7 74,7", stroke: "#7ea3e6", w: 74 },
          { icon: "server" as const, iconColor: "#3FA26B", label: "Hosts", value: String(tabProjects.reduce((s, p) => s + p.hostsCount, 0)), spark: "0,24 13,21 26,22 39,15 52,11 66,5", stroke: "#43B074", w: 66 },
        ].map((c) => (
          <div key={c.label} className="statc" style={{ ...CARD, padding: "16px 18px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, color: "#8A97AB", font: "600 11.5px Inter,sans-serif", letterSpacing: ".5px", textTransform: "uppercase" }}>
              <Icon name={c.icon} size={15} color={c.iconColor} sw={2.1} />
              {c.label}
            </div>
            <div style={{ display: "flex", alignItems: "flex-end", justifyContent: "space-between", marginTop: 8 }}>
              <div className="mono" style={{ fontWeight: 800, fontSize: 26, color: "#0F1B2D", lineHeight: 1, letterSpacing: "-1px" }}>{c.value}</div>
              <svg width={c.w} height="30" viewBox={`0 0 ${c.w} 30`} fill="none" style={{ flex: "none" }}>
                <polyline points={c.spark} stroke={c.stroke} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </div>
          </div>
        ))}
      </div>

      {/* controls */}
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16, flexWrap: "wrap" }}>
        <div style={{ display: "flex", gap: 8 }}>
          <div className="tab" onClick={() => setState({ tab: "active" })} style={{ display: "flex", alignItems: "center", gap: 9, padding: "9px 15px", borderRadius: 11, font: "700 13.5px Inter,sans-serif", background: isActive ? "#fff" : "transparent", border: `1px solid ${isActive ? "#dbe1ec" : "transparent"}`, color: isActive ? "#0F1B2D" : "#8A97AB" }}>
            <Icon name="trend-up" size={15} sw={2.2} />
            Active
            <span className="mono" style={{ minWidth: 20, height: 20, padding: "0 5px", borderRadius: 6, background: isActive ? "#4C74C7" : "#E3EBFF", color: isActive ? "#fff" : "#4C74C7", fontSize: 11, fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center" }}>{activeCount}</span>
          </div>
          <div className="tab" onClick={() => setState({ tab: "archived" })} style={{ display: "flex", alignItems: "center", gap: 9, padding: "9px 15px", borderRadius: 11, font: "700 13.5px Inter,sans-serif", background: !isActive ? "#fff" : "transparent", border: `1px solid ${!isActive ? "#dbe1ec" : "transparent"}`, color: !isActive ? "#0F1B2D" : "#8A97AB" }}>
            <Icon name="archive" size={15} />
            Archived
            <span className="mono" style={{ minWidth: 20, height: 20, padding: "0 5px", borderRadius: 6, background: !isActive ? "#4C74C7" : "#E3EBFF", color: !isActive ? "#fff" : "#4C74C7", fontSize: 11, fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center" }}>{archivedCount}</span>
          </div>
        </div>
        <div style={{ flex: 1 }} />
        <label className="fq" style={{ position: "relative", display: "flex", alignItems: "center", width: 280 }}>
          <svg style={{ position: "absolute", left: 13 }} width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#9aa6b8" strokeWidth="2" strokeLinecap="round">
            <circle cx="11" cy="11" r="7" />
            <path d="M21 21l-4-4" />
          </svg>
          <input placeholder="Filter projects…" value={state.query} onChange={(e) => setState({ query: e.target.value })} />
        </label>
        <div className="clk iconbtn" onClick={() => setState((s) => ({ projSort: s.projSort === "first" ? "last" : "first" }))} style={{ display: "flex", alignItems: "center", gap: 9, height: 40, padding: "0 15px", border: "1px solid #dbe1ec", borderRadius: 11, background: "#fff", font: "600 13px Inter,sans-serif", color: "#5A6B84" }}>
          <Icon name="sort" size={16} />
          {state.projSort === "first" ? "First updated" : "Last updated"}
        </div>
      </div>

      {/* table */}
      <div style={{ ...CARD, overflow: "hidden" }}>
        <div style={{ display: "grid", gridTemplateColumns: "48px minmax(0,1fr) minmax(0,1fr) minmax(0,1fr) 150px 70px", padding: "13px 22px", borderBottom: "1px solid #eef1f7", font: "700 11px Inter,sans-serif", letterSpacing: ".6px", color: "#a0abbd", textTransform: "uppercase" }}>
          <div>#</div>
          <div>Project</div>
          <div>Description</div>
          <div>Findings</div>
          <div>Last updated</div>
          <div style={{ textAlign: "right" }}>Actions</div>
        </div>
        {projRows.map((r, i) => {
          const fsev = r.openFindings === 0 ? FINDING_SEV.none : r.openFindings >= 3 ? FINDING_SEV.high : FINDING_SEV.med;
          const findingsLabel = r.openFindings === 0 ? (r.totalFindings > 0 ? "No open" : "No findings") : `${r.openFindings} open`;
          return (
            <div key={r.id} className="prow clk" onClick={() => openProject(r.id)} style={{ display: "grid", gridTemplateColumns: "48px minmax(0,1fr) minmax(0,1fr) minmax(0,1fr) 150px 70px", alignItems: "center", padding: "11px 22px", borderBottom: "1px solid #f2f4f9" }}>
              <div className="mono" style={{ color: "#b3bccd", fontSize: 13, fontWeight: 600 }}>{String(i + 1).padStart(2, "0")}</div>
              <div style={{ minWidth: 0, paddingRight: 12 }}>
                <div style={{ font: "700 14.5px Inter,sans-serif", color: "#0F1B2D", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.name}</div>
              </div>
              <div style={{ fontSize: 13, color: "#6b7a90", paddingRight: 16, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.description}</div>
              <div>
                <span style={{ display: "inline-flex", alignItems: "center", gap: 6, padding: "4px 10px", borderRadius: 8, background: fsev.fBg, color: fsev.fColor, font: "600 12px Inter,sans-serif" }}>
                  <span style={{ width: 7, height: 7, borderRadius: "50%", background: fsev.fDot }} />
                  {findingsLabel}
                </span>
              </div>
              <div style={{ fontSize: 13, color: "#8A97AB" }}>{r.updated}</div>
              {/* Edit: admin / creator / lead. Delete: admin only — both mirror the backend. */}
              <div style={{ display: "flex", justifyContent: "flex-end", gap: 4 }}>
                {canEditProjectRow(r) && (
                  <div className="actbtn" onClick={(e) => { e.stopPropagation(); openProjEditRow(r); }}><Icon name="edit" size={15} /></div>
                )}
                {isAdmin && (
                  <div className="actbtn del" onClick={(e) => { e.stopPropagation(); askDeleteProject(r); }}><Icon name="trash" size={15} /></div>
                )}
              </div>
            </div>
          );
        })}
        {state.projectsLoading && projRows.length === 0 && <div style={{ padding: 52, textAlign: "center", color: "#9aa6b8", fontSize: 14 }}>Loading projects…</div>}
        {state.projectsError && <div style={{ padding: 52, textAlign: "center", color: "#C0455B", fontSize: 14 }}>{state.projectsError}</div>}
        {!state.projectsLoading && !state.projectsError && projRows.length === 0 && <div style={{ padding: 52, textAlign: "center", color: "#9aa6b8", fontSize: 14 }}>No projects found.</div>}
      </div>
    </div>
  );

  // ---------- Stub page ----------
  const renderStub = () => (
    <div className="route" style={{ padding: "40px 48px 36px", width: "100%" }}>
      {eyebrow([{ label: "Workspace", onClick: selProjects }, { label: stubTitle, muted: true }])}
      <h1 style={{ margin: 0, fontSize: 30, fontWeight: 800, letterSpacing: "-.7px", color: "#0F1B2D" }}>{stubTitle}</h1>
      <div style={{ fontSize: 13.5, color: "#8A97AB", marginTop: 6 }}>{stubDesc}</div>
      <div style={{ marginTop: 32, ...CARD, padding: "60px 24px", display: "flex", flexDirection: "column", alignItems: "center", textAlign: "center", gap: 14 }}>
        <div style={{ width: 56, height: 56, borderRadius: 14, background: "#f1f4f9", color: "#b3bccd", display: "flex", alignItems: "center", justifyContent: "center" }}>
          <Icon name="calendar" size={26} sw={1.8} />
        </div>
        <div style={{ font: "700 15px Inter,sans-serif", color: "#0F1B2D" }}>Coming soon</div>
        <div style={{ fontSize: 13, color: "#8A97AB", maxWidth: 340 }}>This area is under construction. Head back to Projects to continue your work.</div>
        <button className="clk" onClick={selProjects} style={{ marginTop: 6, height: 40, padding: "0 18px", border: "none", borderRadius: 10, background: "#4C74C7", color: "#fff", font: "700 13px Inter,sans-serif", cursor: "pointer" }}>Back to Projects</button>
      </div>
    </div>
  );

  // ---------- Workspace members (admin) ----------
  const renderWorkspaceMembers = () => (
    <div className="route" style={{ padding: "40px 48px 36px", width: "100%" }}>
      {eyebrow([{ label: "Workspace", onClick: selProjects }, { label: "Members", muted: true }])}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 20 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 30, fontWeight: 800, letterSpacing: "-.7px", color: "#0F1B2D" }}>Members</h1>
          <div style={{ fontSize: 13.5, color: "#8A97AB", marginTop: 6 }}>Everyone in your Sbertech workspace — add people here before assigning them to a project</div>
        </div>
        <button className="clk" onClick={() => openWSUserEditor("add", -1)} style={{ flex: "none", display: "inline-flex", alignItems: "center", gap: 8, height: 42, padding: "0 18px", border: "none", borderRadius: 11, background: "#2E5FBF", color: "#fff", font: "700 13.5px Inter,sans-serif", cursor: "pointer" }}>
          <Icon name="plus" size={15} sw={2.2} />
          Add member
        </button>
      </div>
      {/* search + role filter */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginTop: 22, flexWrap: "wrap" }}>
        <label className="fq" style={{ position: "relative", display: "flex", alignItems: "center", width: 280 }}>
          <svg style={{ position: "absolute", left: 13 }} width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#9aa6b8" strokeWidth="2" strokeLinecap="round"><circle cx="11" cy="11" r="7" /><path d="M21 21l-4-4" /></svg>
          <input placeholder="Search by username…" value={state.wsMemberQuery} onChange={(e) => setState({ wsMemberQuery: e.target.value })} />
        </label>
        <div style={{ flex: 1 }} />
        {/* Every pill toggles; filters combine (AND across groups, OR inside one).
            An empty group means "All", so unpicking the last pill re-selects it. */}
        <span className="mono" style={{ fontSize: 10.5, letterSpacing: 1, color: "#a8b2c2", fontWeight: 700 }}>ROLE</span>
        <div className="clk" onClick={() => setState({ wsMemberRoles: [] })} style={{ font: "600 12px Inter,sans-serif", padding: "6px 12px", borderRadius: 20, cursor: "pointer", ...vfPill(state.wsMemberRoles.length === 0) }}>All</div>
        {([{ label: "Admin", v: "admin" as const }, { label: "User", v: "user" as const }]).map((o) => (
          <div key={o.v} className="clk" onClick={() => setState((s) => ({ wsMemberRoles: toggleIn(s.wsMemberRoles, o.v) }))} style={{ font: "600 12px Inter,sans-serif", padding: "6px 12px", borderRadius: 20, cursor: "pointer", ...vfPill(state.wsMemberRoles.includes(o.v)) }}>{o.label}</div>
        ))}
        <span className="mono" style={{ fontSize: 10.5, letterSpacing: 1, color: "#a8b2c2", fontWeight: 700, marginLeft: 8 }}>PROJECT</span>
        <div className="clk" onClick={() => setState({ wsMemberProjectRoles: [] })} style={{ font: "600 12px Inter,sans-serif", padding: "6px 12px", borderRadius: 20, cursor: "pointer", ...vfPill(state.wsMemberProjectRoles.length === 0) }}>All</div>
        {([{ label: "Lead", v: "lead" as const }, { label: "Pentester", v: "pentester" as const }]).map((o) => (
          <div key={o.v} className="clk" onClick={() => setState((s) => ({ wsMemberProjectRoles: toggleIn(s.wsMemberProjectRoles, o.v) }))} style={{ font: "600 12px Inter,sans-serif", padding: "6px 12px", borderRadius: 20, cursor: "pointer", ...vfPill(state.wsMemberProjectRoles.includes(o.v)) }}>{o.label}</div>
        ))}
      </div>
      <div style={{ marginTop: 16, ...CARD, overflow: "hidden" }}>
        <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1.4fr 168px 72px", padding: "13px 20px", borderBottom: "1px solid #eef1f7", font: "700 11px Inter,sans-serif", letterSpacing: ".6px", color: "#a0abbd", textTransform: "uppercase" }}>
          <div>Name</div>
          <div>Email</div>
          <div>Role</div>
          <div />
        </div>
        {(() => {
          const wq = state.wsMemberQuery.trim().toLowerCase();
          const filtered = state.workspaceUsers
            .map((u, idx) => ({ u, idx }))
            .filter(
              ({ u }) =>
                (state.wsMemberRoles.length === 0 || state.wsMemberRoles.includes(u.role)) &&
                (state.wsMemberProjectRoles.length === 0 || state.wsMemberProjectRoles.includes(u.projectRole)) &&
                (!wq || u.name.toLowerCase().includes(wq))
            );
          if (filtered.length === 0) return <div style={{ padding: 44, textAlign: "center", color: "#9aa6b8", fontSize: 14 }}>No members match.</div>;
          return filtered.map(({ u, idx }) => (
            <div key={u.key + idx} className="prow" style={{ display: "grid", gridTemplateColumns: "1.2fr 1.4fr 168px 72px", alignItems: "center", padding: "14px 20px", borderBottom: "1px solid #f2f4f9" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 11, minWidth: 0 }}>
                <span className="mono" style={{ width: 32, height: 32, flex: "none", borderRadius: "50%", background: "#2E5FBF", color: "#fff", display: "flex", alignItems: "center", justifyContent: "center", font: "700 13px 'JetBrains Mono',monospace" }}>{(u.name[0] || "U").toUpperCase()}</span>
                <span style={{ font: "600 13.5px Inter,sans-serif", color: "#0F1B2D" }}>{u.name}</span>
              </div>
              <div className="mono" style={{ fontSize: 12.5, color: "#5A6B84", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{u.email}</div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                <span style={{ font: "700 10px Inter,sans-serif", textTransform: "uppercase", letterSpacing: ".5px", borderRadius: 6, padding: "3px 9px", background: WS_ROLE[u.role].bg, color: WS_ROLE[u.role].color }}>{WS_ROLE_LABEL[u.role]}</span>
                <span style={{ font: "700 10px Inter,sans-serif", textTransform: "uppercase", letterSpacing: ".5px", borderRadius: 6, padding: "3px 9px", background: ROLE[u.projectRole].bg, color: ROLE[u.projectRole].color }}>{u.projectRole}</span>
              </div>
              <div style={{ display: "flex", justifyContent: "flex-end", gap: 2 }}>
                <div className="actbtn" onClick={() => openWSUserEditor("edit", idx)}><Icon name="edit" size={15} /></div>
                <div className="actbtn del" onClick={() => deleteWSUser(idx)}><Icon name="trash" size={15} /></div>
              </div>
            </div>
          ));
        })()}
      </div>
    </div>
  );

  // ---------- Project detail ----------
  const tabItem = (label: string, icon: Parameters<typeof Icon>[0]["name"], st: { color: string; bar: string }, onClick: () => void, badge?: { text: string; color: string; bg: string }, extra?: ReactNode) => (
    <div className="clk" onClick={onClick} style={{ display: "flex", alignItems: "center", gap: 8, padding: "15px 15px", marginBottom: -1, whiteSpace: "nowrap", borderBottom: `2px solid ${st.bar}`, color: st.color, font: "600 14px Inter,sans-serif" }}>
      <Icon name={icon} size={17} />
      {label}
      {extra}
      {badge && <span className="mono" style={{ fontSize: 11, fontWeight: 700, color: badge.color, background: badge.bg, borderRadius: 6, padding: "1px 7px" }}>{badge.text}</span>}
    </div>
  );

  const renderDetail = () => (
    <div className="route" style={{ padding: "0 0 36px", width: "100%" }}>
      {/* tabs */}
      <div style={{ display: "flex", alignItems: "center", gap: 2, padding: "0 48px", borderBottom: "1px solid #e6eaf1", background: "#fff", overflow: "visible" }}>
        {tabItem("Overview", "layout", so, () => setSection("overview"))}
        <div style={{ position: "relative", display: "flex" }}>
          {tabItem("Recon", "server", sh, toggleReconMenu, undefined, <Icon name="chevron-down" size={14} sw={2.2} />)}
          <div className={`menu ${state.reconMenuOpen ? "open" : ""}`} style={{ position: "absolute", top: 52, left: 8, width: 214, background: "#fff", border: "1px solid #e6eaf1", borderRadius: 14, boxShadow: "0 20px 54px rgba(15,27,45,.16)", zIndex: 50, padding: 8, transformOrigin: "top left" }}>
            <div className="mono" style={{ fontSize: 10, letterSpacing: 1.5, color: "#a8b2c2", fontWeight: 700, padding: "8px 10px" }}>RECON</div>
            {([
              { v: "hosts" as const, icon: "server" as const, label: "Hosts", count: hosts.length },
              { v: "ips" as const, icon: "card" as const, label: "IPs", count: ipsRows.length },
              { v: "endpoints" as const, icon: "link" as const, label: "Endpoints", count: endpointTotal },
            ]).map((it) => {
              const on = rv === it.v;
              return (
                <div key={it.v} className="nav clk" onClick={() => selRecon(it.v)} style={{ display: "flex", alignItems: "center", gap: 12, padding: "10px 11px", borderRadius: 10, font: "600 13.5px Inter,sans-serif", color: on ? "#2E5FBF" : "#334", background: on ? "#eef3fc" : "transparent" }}>
                  <Icon name={it.icon} size={17} />
                  {it.label}
                  <span className="mono" style={{ marginLeft: "auto", fontSize: 11, fontWeight: 700, color: "#8A97AB" }}>{it.count}</span>
                </div>
              );
            })}
          </div>
        </div>
        {tabItem("Vulnerabilities", "star2", sv, () => setSection("vulns"), { text: String(d.vulns.length), color: sv.badgeColor, bg: sv.badgeBg })}
        {tabItem("Notes", "doc", sn, () => setSection("notes"), { text: String(d.notes.length), color: sn.badgeColor, bg: sn.badgeBg })}
        {canViewMembers && tabItem("Members", "users", sm, () => setSection("members"), { text: String(d.members.length), color: sm.badgeColor, bg: sm.badgeBg })}
        {tabItem("Activity", "activity", sa, () => setSection("activity"), { text: String(activityGroups.length), color: sa.color, bg: "#EEF1F6" })}
      </div>

      <div style={{ padding: "26px 48px 0" }}>
        {/* Project / Section / <open item>. The section stays clickable while an
            item is open, so it is the way back to that section's list. */}
        <div className="mono" style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12, color: "#a0abbd", fontWeight: 600, marginBottom: 14 }}>
          <span className="clk" onClick={() => setSection("overview")} style={{ color: "#4C74C7", cursor: "pointer" }}>{projName}</span>
          <span>/</span>
          {crumbLeaf ? (
            <>
              <span className="clk" onClick={() => setSection(sec)} style={{ color: "#4C74C7", cursor: "pointer" }}>{sectionLabel}</span>
              <span>/</span>
              <span style={{ color: "#7c8aa0", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{crumbLeaf}</span>
            </>
          ) : (
            <span style={{ color: "#7c8aa0" }}>{sectionLabel}</span>
          )}
        </div>

        {/* header row */}
        {sec === "overview" ? (
          <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 20, marginBottom: 24 }}>
            <div style={{ minWidth: 0 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
                <h1 style={{ margin: 0, fontSize: 32, fontWeight: 800, letterSpacing: "-.8px", color: "#0F1B2D" }}>{d.title || projName}</h1>
                <span style={{ display: "inline-flex", alignItems: "center", gap: 6, padding: "5px 12px", borderRadius: 20, background: stCh.bg, color: stCh.color, font: "700 12px Inter,sans-serif" }}>
                  <span style={{ width: 7, height: 7, borderRadius: "50%", background: stCh.dot }} />
                  {stCh.label}
                </span>
              </div>
              <div style={{ fontSize: 14, color: "#8A97AB", marginTop: 8 }}>{d.desc}</div>
            </div>
            <div style={{ display: "flex", gap: 10, flex: "none" }}>
              <button className="clk iconbtn" onClick={openExportModal} style={{ height: 42, padding: "0 16px", border: "1px solid #dbe1ec", borderRadius: 11, background: "#fff", font: "600 13px Inter,sans-serif", color: "#5A6B84", display: "flex", alignItems: "center", gap: 8 }}>
                <Icon name="file-check" size={16} />Generate report
              </button>
              {canEditProject && (
                <button className="clk" onClick={openProjEdit} style={{ height: 42, padding: "0 18px", border: "none", borderRadius: 11, background: "#4C74C7", color: "#fff", font: "700 13px Inter,sans-serif", display: "flex", alignItems: "center", gap: 8 }}>
                  <Icon name="edit" size={16} color="#fff" />Edit
                </button>
              )}
            </div>
          </div>
        ) : (
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 20, marginBottom: 22 }}>
            <h1 style={{ margin: 0, fontSize: 30, fontWeight: 800, letterSpacing: "-.7px", color: "#0F1B2D" }}>{sectionLabel}</h1>
            <div style={{ display: "flex", gap: 10, flex: "none" }}>
              {sec === "hosts" && rv === "hosts" && (
                <>
                  <button className="clk iconbtn" onClick={() => openReconExport("hosts")} style={{ height: 42, padding: "0 16px", border: "1px solid #dbe1ec", borderRadius: 11, background: "#fff", font: "600 13px Inter,sans-serif", color: "#5A6B84", display: "flex", alignItems: "center", gap: 8 }}>
                    <Icon name="download" size={16} />Export
                  </button>
                  <button className="addbtn clk" onClick={() => openEditor("host", "add", -1)} style={{ height: 42 }}>
                    <Icon name="plus" size={15} color="#fff" sw={2.6} />Add host
                  </button>
                </>
              )}
              {/* Each recon view adds the kind of object it lists; the totals row
                  below carries that view's filters. */}
              {sec === "hosts" && rv === "ips" && (
                <>
                  <button className="clk iconbtn" onClick={() => openReconExport("ips")} style={{ height: 42, padding: "0 16px", border: "1px solid #dbe1ec", borderRadius: 11, background: "#fff", font: "600 13px Inter,sans-serif", color: "#5A6B84", display: "flex", alignItems: "center", gap: 8 }}>
                    <Icon name="download" size={16} />Export
                  </button>
                  <button className="addbtn clk" onClick={() => openEditor("ip", "add", -1)} style={{ height: 42 }}>
                    <Icon name="plus" size={15} color="#fff" sw={2.6} />Add IP
                  </button>
                </>
              )}
              {sec === "hosts" && rv === "endpoints" && (
                <>
                  <button className="clk iconbtn" onClick={() => openReconExport("endpoints")} style={{ height: 42, padding: "0 16px", border: "1px solid #dbe1ec", borderRadius: 11, background: "#fff", font: "600 13px Inter,sans-serif", color: "#5A6B84", display: "flex", alignItems: "center", gap: 8 }}>
                    <Icon name="download" size={16} />Export
                  </button>
                  <button className="addbtn clk" onClick={() => openEditor("endpoint", "add", -1)} style={{ height: 42 }}>
                    <Icon name="plus" size={15} color="#fff" sw={2.6} />Add endpoint
                  </button>
                </>
              )}
              {/* В карточке уязвимости кнопка живёт в строке «All findings» (см. renderVulnDetail). */}
              {sec === "vulns" && state.openVulnId == null && (
                <button className="addbtn clk" onClick={() => openEditor("vuln", "add", -1)} style={{ height: 42 }}><Icon name="plus" size={15} color="#fff" sw={2.6} />Add issue</button>
              )}
              {sec === "notes" && (
                <button className="addbtn clk" onClick={() => openNoteEditor("add", -1)} style={{ height: 42 }}><Icon name="plus" size={15} color="#fff" sw={2.6} />Add note</button>
              )}
              {sec === "members" && canManageMembers && (
                <button className="addbtn clk" onClick={() => openEditor("member", "add", -1)} style={{ height: 42 }}><Icon name="plus" size={15} color="#fff" sw={2.6} />Add member</button>
              )}
            </div>
          </div>
        )}

        <div style={{ width: "100%" }}>
          {sec === "overview" && renderOverview()}
          {sec === "hosts" && renderRecon()}
          {sec === "vulns" && renderVulns()}
          {sec === "notes" && (state.noteEditorOpen ? renderNoteEditor() : state.openNoteId != null ? renderNoteViewer() : renderNotes())}
          {sec === "members" &&
            (canViewMembers
              ? renderMembers()
              : renderNoAccessPage("Состав команды виден администратору, лиду проекта и его создателю."))}
          {sec === "activity" && renderActivity()}
        </div>
      </div>
    </div>
  );

  const renderNoAccess = (message: string) => (
    <div className="route" style={{ ...CARD, padding: "48px 24px", display: "flex", flexDirection: "column", alignItems: "center", textAlign: "center", gap: 12 }}>
      <div style={{ width: 48, height: 48, borderRadius: 12, background: "#f1f4f9", color: "#b3bccd", display: "flex", alignItems: "center", justifyContent: "center" }}>
        <Icon name="lock" size={22} sw={1.9} />
      </div>
      <div style={{ font: "700 15px Inter,sans-serif", color: "#0F1B2D" }}>Restricted</div>
      <div style={{ fontSize: 13, color: "#8A97AB", maxWidth: 360 }}>{message}</div>
    </div>
  );

  /* Shown instead of a whole screen the user may not open: a project the backend
     refuses (403/404), or a section that is not theirs (workspace members, the
     project's team). 404 is folded in on purpose: "not found" and "not yours"
     must be indistinguishable, otherwise the id becomes an existence oracle. */
  const NO_ACCESS_PROJECT = "У вас нет доступа к этому проекту. Он доступен только участникам — попросите администратора или лида добавить вас в команду.";
  const renderNoAccessPage = (message: string = NO_ACCESS_PROJECT) => (
    <div className="route" style={{ padding: "40px 48px 36px", width: "100%", display: "flex", justifyContent: "center" }}>
      <div style={{ ...CARD, padding: "56px 40px", maxWidth: 520, width: "100%", display: "flex", flexDirection: "column", alignItems: "center", textAlign: "center", gap: 14, marginTop: 40 }}>
        <div style={{ width: 64, height: 64, borderRadius: 16, background: "#FCEBED", color: "#C0455B", display: "flex", alignItems: "center", justifyContent: "center" }}>
          <Icon name="lock" size={28} sw={1.9} />
        </div>
        <h1 style={{ margin: 0, fontSize: 24, fontWeight: 800, letterSpacing: "-.5px", color: "#0F1B2D" }}>Доступа нет</h1>
        <div style={{ fontSize: 14, color: "#8A97AB", maxWidth: 380, lineHeight: 1.6 }}>{message}</div>
        <button
          className="clk"
          onClick={selProjects}
          style={{ marginTop: 10, height: 42, padding: "0 22px", border: "none", borderRadius: 11, background: "#4C74C7", color: "#fff", font: "700 13.5px Inter,sans-serif", cursor: "pointer" }}
        >
          Вернуться к проектам
        </button>
      </div>
    </div>
  );

  const renderOverview = () => (
    <div className="route">
      <div style={{ ...CARD, padding: "20px 22px", marginBottom: 18 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
          <div style={{ font: "700 14px Inter,sans-serif", color: "#0F1B2D" }}>Engagement timeline</div>
          <div className="mono" style={{ fontSize: 12, color: "#8A97AB" }}>{d.start} → {d.end}</div>
        </div>
        <div style={{ height: 10, borderRadius: 6, background: "#eef1f6", overflow: "hidden" }}>
          <div style={{ width: `${d.progress}%`, height: "100%", background: "linear-gradient(90deg,#4C74C7,#6E93DA)", borderRadius: 6 }} />
        </div>
        <div style={{ display: "flex", justifyContent: "space-between", marginTop: 8 }}>
          <span className="mono" style={{ fontSize: 11, color: "#a0abbd" }}>Start</span>
          <span style={{ font: "600 12px Inter,sans-serif", color: "#5A6B84" }}>{d.progress}% elapsed</span>
          <span className="mono" style={{ fontSize: 11, color: "#a0abbd" }}>End</span>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 14, marginBottom: 18 }}>
        {[
          { icon: "globe" as const, color: "#3d6fd6", label: "Hosts", value: hosts.length, spark: sparkline(3, hosts.length), stroke: "#3d6fd6", onClick: () => setSection("hosts") },
          { icon: "alert-triangle" as const, color: "#C0455B", label: "Open vulns", value: openVulnCount, spark: sparkline(7, vulnStCounts.open), stroke: "#C0455B", onClick: goToOpenVulns },
          { icon: "star" as const, color: "#6E86C6", label: "My findings", value: myFindingsCount, spark: sparkline(11, myFindingsCount), stroke: "#7ea3e6", onClick: goToMyFindings },
        ].map((c) => (
          <div key={c.label} className="statc clk" onClick={c.onClick} style={{ ...CARD, padding: "16px 18px", cursor: "pointer" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, color: "#8A97AB", font: "600 11.5px Inter,sans-serif", letterSpacing: ".5px", textTransform: "uppercase" }}>
              <Icon name={c.icon} size={15} color={c.color} sw={2.1} />{c.label}
            </div>
            <div style={{ display: "flex", alignItems: "flex-end", justifyContent: "space-between", marginTop: 8 }}>
              <div className="mono" style={{ fontWeight: 800, fontSize: 26, color: "#0F1B2D", lineHeight: 1, letterSpacing: "-1px" }}>{c.value}</div>
              <svg width="74" height="30" viewBox="0 0 74 30" fill="none" style={{ flex: "none" }}>
                <polyline points={c.spark} stroke={c.stroke} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </div>
          </div>
        ))}
      </div>

      <div style={{ ...CARD, padding: "20px 22px", marginBottom: 18 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
          <div style={{ font: "700 14px Inter,sans-serif", color: "#0F1B2D" }}>Vulnerabilities across the project</div>
          <span className="clk" onClick={() => setSection("vulns")} style={{ font: "600 12px Inter,sans-serif", color: "#4C74C7" }}>View all →</span>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(5,minmax(0,1fr))", gap: 12 }}>
          {sevBars.map((b) => (
            <div key={b.label} className="clk" onClick={b.onClick} style={{ border: "1px solid #eef1f6", borderRadius: 13, padding: "15px 16px", background: b.tileBg, cursor: "pointer" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                <span style={{ width: 9, height: 9, borderRadius: 3, background: b.color }} />
                <span style={{ font: "700 10.5px Inter,sans-serif", textTransform: "uppercase", letterSpacing: ".5px", color: b.color }}>{b.label}</span>
              </div>
              <div className="mono" style={{ fontSize: 30, fontWeight: 800, color: "#0F1B2D", marginTop: 10, lineHeight: 1 }}>{b.count}</div>
            </div>
          ))}
        </div>
      </div>

      {canViewMembers && (
        <div style={{ ...CARD, padding: "20px 22px", marginBottom: 18 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
            <div style={{ font: "700 14px Inter,sans-serif", color: "#0F1B2D" }}>Team</div>
            <span className="clk" onClick={() => setSection("members")} style={{ font: "600 12px Inter,sans-serif", color: "#4C74C7" }}>Manage →</span>
          </div>
          {d.members.map((m, i) => (
            <div key={m.name + i} style={{ display: "flex", alignItems: "center", gap: 11, padding: "7px 0", borderTop: "1px solid #f2f4f9" }}>
              <span className="mono" style={{ width: 30, height: 30, flex: "none", borderRadius: "50%", background: m.color, color: "#fff", display: "flex", alignItems: "center", justifyContent: "center", font: "700 11px 'JetBrains Mono',monospace" }}>{m.initials}</span>
              <div style={{ minWidth: 0 }}>
                <div style={{ font: "600 13px Inter,sans-serif", color: "#0F1B2D" }}>{m.name}</div>
                <div className="mono" style={{ fontSize: 11, color: "#a0abbd" }}>{m.role}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );

  const portPills = (ports: Host["ports"]) => (
    <div style={{ display: "flex", flexWrap: "wrap", gap: 5 }}>
      {portPillsOf(ports).map((p, i) => (
        <span key={i} className="mono" style={{ fontSize: 11, fontWeight: 700, borderRadius: 6, padding: "2px 8px", background: p.bg, color: p.color }}>{p.label}</span>
      ))}
    </div>
  );

  const renderRecon = () => {
    if (rv === "ips") {
      return (
        <div className="route">
          <div style={{ display: "flex", alignItems: "center", gap: 9, marginBottom: 16, flexWrap: "wrap" }}>
            <span style={{ display: "inline-flex", alignItems: "center", gap: 6, font: "600 12.5px Inter,sans-serif", color: "#5A6B84", background: "#fff", border: "1px solid #e9edf4", borderRadius: 20, padding: "7px 13px" }}>Total IPs <b className="mono" style={{ color: "#0F1B2D" }}>{ipsRows.length}</b></span>
            <div style={{ flex: 1 }} />
            {/* One box for both columns of the row: the address or its host. */}
            <label className="fq" style={{ position: "relative", display: "flex", alignItems: "center", width: 280 }}>
              <svg style={{ position: "absolute", left: 13 }} width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#9aa6b8" strokeWidth="2" strokeLinecap="round"><circle cx="11" cy="11" r="7" /><path d="M21 21l-4-4" /></svg>
              <input placeholder="Search by IP or host…" value={state.ipQuery} onChange={(e) => setState({ ipQuery: e.target.value })} />
            </label>
          </div>
          <div style={{ ...CARD, overflow: "hidden" }}>
            <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) minmax(0,1.4fr) 140px 72px", padding: "13px 20px", borderBottom: "1px solid #eef1f7", font: "700 11px Inter,sans-serif", letterSpacing: ".6px", color: "#a0abbd", textTransform: "uppercase" }}>
              <div>IP address</div><div>Hostname</div><div>Status</div><div />
            </div>
            {ipsRows.map((i, idx) => (
              <div key={idx} className="prow" style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) minmax(0,1.4fr) 140px 72px", alignItems: "center", padding: "14px 20px", borderBottom: "1px solid #f2f4f9" }}>
                <div className="mono" style={{ font: "700 13.5px 'JetBrains Mono',monospace", color: "#0F1B2D" }}>{i.ip}</div>
                <div className="mono" style={{ fontSize: 12.5, color: "#5A6B84", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{i.host}</div>
                <div style={{ display: "flex", alignItems: "center", gap: 7, font: "600 12px Inter,sans-serif", color: "#5A6B84" }}><span style={{ width: 8, height: 8, borderRadius: "50%", background: i.statusColor }} />{i.status}</div>
                <div style={{ display: "flex", justifyContent: "flex-end", gap: 2 }}>
                  <div className="actbtn" onClick={i.onEdit}><Icon name="edit" size={15} /></div>
                  <div className="actbtn del" onClick={i.onDelete}><Icon name="trash" size={15} /></div>
                </div>
              </div>
            ))}
          </div>
        </div>
      );
    }
    if (rv === "endpoints") {
      return (
        <div className="route">
          <div style={{ display: "flex", alignItems: "center", gap: 9, marginBottom: 16 }}>
            <span style={{ display: "inline-flex", alignItems: "center", gap: 6, font: "600 12.5px Inter,sans-serif", color: "#5A6B84", background: "#fff", border: "1px solid #e9edf4", borderRadius: 20, padding: "7px 13px" }}>Total endpoints <b className="mono" style={{ color: "#0F1B2D" }}>{endpointTotal}</b></span>
            {/* Method pills toggle and combine; empty selection means All. */}
            <div className="clk" onClick={() => setState({ epMethods: [] })} style={{ font: "600 12px Inter,sans-serif", padding: "6px 12px", borderRadius: 20, cursor: "pointer", ...vfPill(state.epMethods.length === 0) }}>All</div>
            {STORM_METHODS.map((m) => (
              <div key={m} className="clk" onClick={() => setState((s) => ({ epMethods: toggleIn(s.epMethods, m) }))} style={{ font: "600 12px Inter,sans-serif", padding: "6px 12px", borderRadius: 20, cursor: "pointer", ...vfPill(state.epMethods.includes(m)) }}>{m}</div>
            ))}
            <div style={{ flex: 1 }} />
            <label className="fq" style={{ position: "relative", display: "flex", alignItems: "center", width: 190 }}>
              <svg style={{ position: "absolute", left: 13 }} width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#9aa6b8" strokeWidth="2" strokeLinecap="round"><circle cx="11" cy="11" r="7" /><path d="M21 21l-4-4" /></svg>
              <input placeholder="Search by host…" value={state.epHostQuery} onChange={(e) => setState({ epHostQuery: e.target.value })} />
            </label>
            <label className="fq" style={{ position: "relative", display: "flex", alignItems: "center", width: 190 }}>
              <svg style={{ position: "absolute", left: 13 }} width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#9aa6b8" strokeWidth="2" strokeLinecap="round"><circle cx="11" cy="11" r="7" /><path d="M21 21l-4-4" /></svg>
              <input placeholder="Search by endpoint…" value={state.epPathQuery} onChange={(e) => setState({ epPathQuery: e.target.value })} />
            </label>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {endpointGroups.map((g) => (
              <div key={g.host} style={{ background: "#fff", border: "1px solid #e9edf4", borderRadius: 14, overflow: "hidden" }}>
                <div className="prow clk" onClick={() => toggleEpGroup(g.host)} style={{ display: "flex", alignItems: "center", gap: 12, padding: "14px 18px" }}>
                  <Icon name="chevron-right" size={15} color="#b3bccd" sw={2.4} style={{ transform: g.expanded ? "rotate(90deg)" : "none", transition: "transform .2s" }} />
                  <Icon name="globe2" size={16} color="#8A97AB" />
                  <span className="mono" style={{ font: "700 14px 'JetBrains Mono',monospace", color: "#0F1B2D", flex: 1 }}>{g.host}</span>
                  <span className="mono" style={{ fontSize: 11.5, fontWeight: 700, color: "#5A6B84", background: "#f1f4f9", borderRadius: 7, padding: "3px 9px" }}>{g.count}</span>
                </div>
                {g.expanded && (
                  <div style={{ borderTop: "1px solid #f2f4f9", animation: "storm-fade .2s ease both" }}>
                    <div style={{ display: "grid", gridTemplateColumns: "72px minmax(0,1fr) 90px 96px", gap: 10, padding: "11px 20px 11px 50px", borderBottom: "1px solid #f2f4f9", font: "700 10.5px Inter,sans-serif", letterSpacing: ".5px", color: "#a0abbd", textTransform: "uppercase" }}>
                      <div>Method</div><div>Path</div><div>Status</div><div />
                    </div>
                    {g.endpoints.map((e: Endpoint, i: number) => {
                      const m = METHOD[e.m] ?? PORT.closed;
                      return (
                        <div key={i} className="prow clk" onClick={() => openEndpoint({ method: e.m, path: e.p, host: g.host, hostId: g.hostId, endpointId: e.id })} style={{ display: "grid", gridTemplateColumns: "72px minmax(0,1fr) 90px 96px", alignItems: "center", gap: 10, padding: "11px 20px 11px 50px", borderBottom: "1px solid #f4f6fa" }}>
                          <span className="mono" style={{ justifySelf: "start", fontWeight: 700, borderRadius: 5, padding: "2px 8px", fontSize: 10.5, background: m.bg, color: m.color }}>{e.m}</span>
                          <div className="mono" style={{ fontSize: 12.5, color: "#0F1B2D", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.p}</div>
                          <div className="mono" style={{ fontSize: 12, color: "#2E8B57", fontWeight: 700 }}>{EPSTATUS[e.m] ?? "200"}</div>
                          <div style={{ display: "flex", justifyContent: "flex-end", gap: 2 }}>
                            <div className="actbtn" title="Copy as cURL" onClick={(ev) => { ev.stopPropagation(); copyCurl({ method: e.m, path: e.p, host: g.host }); }}><Icon name="copy" size={15} /></div>
                            <div className="actbtn del" title="Delete endpoint" onClick={(ev) => { ev.stopPropagation(); void deleteEndpoint(g.hostId, e.id); }}><Icon name="trash" size={15} /></div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            ))}
            {endpointTotal === 0 && <div style={{ padding: 52, textAlign: "center", color: "#9aa6b8", fontSize: 14, background: "#fff", border: "1px solid #e9edf4", borderRadius: 14 }}>No endpoints discovered.</div>}
          </div>
        </div>
      );
    }
    // rv === "hosts"
    if (_hd) return renderHostDetail(_hd);
    return (
      <div className="route">
        {/* Same toolbar shape as the IPs view: total on the left, search on the right. */}
        <div style={{ display: "flex", alignItems: "center", gap: 9, flexWrap: "wrap", marginBottom: 16 }}>
          <span style={{ display: "inline-flex", alignItems: "center", gap: 6, font: "600 12.5px Inter,sans-serif", color: "#5A6B84", background: "#fff", border: "1px solid #e9edf4", borderRadius: 20, padding: "7px 13px" }}>Total hosts <b className="mono" style={{ color: "#0F1B2D" }}>{hostsList.length}</b></span>
          <div style={{ flex: 1 }} />
          <label className="fq" style={{ position: "relative", display: "flex", alignItems: "center", width: 280 }}>
            <svg style={{ position: "absolute", left: 13 }} width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#9aa6b8" strokeWidth="2" strokeLinecap="round"><circle cx="11" cy="11" r="7" /><path d="M21 21l-4-4" /></svg>
            <input placeholder="Search by host…" value={state.hostQuery} onChange={(e) => setState({ hostQuery: e.target.value })} />
          </label>
        </div>
        <div style={{ ...CARD, overflow: "hidden" }}>
          <div style={{ display: "grid", gridTemplateColumns: "24px minmax(0,1.25fr) minmax(0,1fr) 72px", gap: 14, padding: "12px 20px", borderBottom: "1px solid #eef1f7", font: "700 11px Inter,sans-serif", letterSpacing: ".5px", color: "#a0abbd", textTransform: "uppercase" }}>
            <div /><div>Host</div><div>Ports</div><div />
          </div>
          {hostsList.map(({ h, idx }) => {
            const exp = state.expanded.includes(h.id);
            return (
              <div key={h.id} style={{ borderBottom: "1px solid #f2f4f9" }}>
                <div className="prow clk" onClick={() => toggleHost(h.id)} style={{ display: "grid", gridTemplateColumns: "24px minmax(0,1.25fr) minmax(0,1fr) 72px", alignItems: "start", gap: 14, padding: "15px 20px" }}>
                  <Icon name="chevron-right" size={15} color="#b3bccd" sw={2.4} style={{ marginTop: 3, transform: exp ? "rotate(90deg)" : "none", transition: "transform .2s" }} />
                  <div style={{ minWidth: 0 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 10, minWidth: 0 }}>
                      <span style={{ width: 8, height: 8, flex: "none", borderRadius: "50%", background: STDOT[h.status] ?? STDOT.unknown }} />
                      <span className="clk" onClick={(ev) => { ev.stopPropagation(); openHostDetail(h.id); }} style={{ display: "inline-block", minWidth: 0 }}>
                        <span className="mono hostname" style={{ font: "700 14px 'JetBrains Mono',monospace", color: "#0F1B2D", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", cursor: "pointer" }}>{h.host}</span>
                      </span>
                    </div>
                  </div>
                  <div style={{ minWidth: 0 }}>{portPills(h.ports)}</div>
                  <div style={{ display: "flex", justifyContent: "flex-end", gap: 2 }}>
                    <div className="actbtn" onClick={(ev) => { ev.stopPropagation(); openEditor("host", "edit", idx); }}><Icon name="edit" size={15} /></div>
                    <div className="actbtn del" onClick={(ev) => { ev.stopPropagation(); askDelete("host", idx, h.host); }}><Icon name="trash" size={15} /></div>
                  </div>
                </div>
                {/* Expanding a host lists its subdomains — the addresses live in the IPs view. */}
                {exp && (
                  <div style={{ background: "#fafbfd", animation: "storm-fade .2s ease both" }}>
                    {subdomainsOf(h).map((sub) => (
                      <div key={sub.id} className="prow clk" onClick={(ev) => { ev.stopPropagation(); openHostDetail(sub.id); }} style={{ display: "grid", gridTemplateColumns: "24px minmax(0,1.25fr) minmax(0,1fr) 72px", alignItems: "start", gap: 14, padding: "13px 20px 13px 44px", borderTop: "1px solid #f2f4f9" }}>
                        <span style={{ width: 6, height: 6, borderRadius: "50%", background: STDOT[sub.status] ?? STDOT.unknown, marginTop: 8, justifySelf: "end" }} />
                        <div style={{ minWidth: 0 }}>
                          <span className="mono" style={{ font: "600 13px 'JetBrains Mono',monospace", color: "#334", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", display: "block" }}>{sub.host}</span>
                        </div>
                        <div style={{ minWidth: 0 }}>{portPills(sub.ports)}</div>
                        <div />
                      </div>
                    ))}
                    {subdomainsOf(h).length === 0 && (
                      <div style={{ padding: "13px 20px 13px 44px", borderTop: "1px solid #f2f4f9", font: "500 12.5px Inter,sans-serif", color: "#a0abbd" }}>No subdomains discovered.</div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
          {state.apiHosts === null && <div style={{ padding: 52, textAlign: "center", color: "#9aa6b8", fontSize: 14 }}>Loading hosts…</div>}
          {state.apiHosts !== null && hostsList.length === 0 && <div style={{ padding: 52, textAlign: "center", color: "#9aa6b8", fontSize: 14 }}>No hosts found.</div>}
        </div>
      </div>
    );
  };

  const renderHostDetail = (h: Host) => {
    const hidx = hosts.findIndex((x) => x.id === h.id);
    return (
      <div style={{ animation: "storm-fade .2s ease both" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 18 }}>
          <span className="clk" onClick={closeHostDetail} style={{ display: "inline-flex", alignItems: "center", gap: 6, font: "600 12.5px Inter,sans-serif", color: "#5A6B84", background: "#fff", border: "1px solid #e9edf4", borderRadius: 20, padding: "7px 13px", cursor: "pointer" }}>
            <Icon name="chevron-left" size={15} />All hosts
          </span>
        </div>
        <div style={{ ...CARD, padding: "22px 24px", marginBottom: 16 }}>
          <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 16 }}>
            <div style={{ minWidth: 0 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <span style={{ width: 9, height: 9, flex: "none", borderRadius: "50%", background: STDOT[h.status] ?? STDOT.unknown }} />
                <span className="mono" style={{ font: "800 20px 'JetBrains Mono',monospace", color: "#0F1B2D", wordBreak: "break-all" }}>{h.host}</span>
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 12 }}>
                {h.ips.map((ip, i) => (
                  <span key={i} className="mono" style={{ fontSize: 11, fontWeight: 600, color: "#5A6B84", background: "#f1f4f9", border: "1px solid #e9edf4", borderRadius: 6, padding: "3px 9px" }}>{ip}</span>
                ))}
              </div>
            </div>
            <button className="clk" onClick={() => openEditor("host", "edit", hidx)} style={{ flex: "none", display: "inline-flex", alignItems: "center", gap: 7, height: 38, padding: "0 16px", border: "1px solid #dbe1ec", borderRadius: 10, background: "#fff", font: "700 12.5px Inter,sans-serif", color: "#5A6B84", cursor: "pointer" }}>
              <Icon name="edit" size={14} />Edit host
            </button>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
          <span style={{ font: "700 13px Inter,sans-serif", color: "#0F1B2D" }}>Ports <span className="mono" style={{ color: "#8A97AB", fontWeight: 600 }}>{h.ports.length}</span></span>
        </div>
        <div style={{ ...CARD, overflow: "hidden", marginBottom: 20 }}>
          <div style={{ display: "grid", gridTemplateColumns: "minmax(0,120px) minmax(0,1fr) 110px", gap: 14, padding: "12px 20px", borderBottom: "1px solid #eef1f7", font: "700 11px Inter,sans-serif", letterSpacing: ".5px", color: "#a0abbd", textTransform: "uppercase" }}>
            <div>Port</div><div>Service</div><div>State</div>
          </div>
          {h.ports.map((p, pi) => (
            <div key={pi} className="prow" style={{ display: "grid", gridTemplateColumns: "minmax(0,120px) minmax(0,1fr) 110px", alignItems: "center", gap: 14, padding: "14px 20px", borderBottom: "1px solid #f2f4f9" }}>
              <span className="mono" style={{ font: "700 13px 'JetBrains Mono',monospace", color: "#0F1B2D" }}>{p.n}/{p.proto}</span>
              <span className="mono" style={{ fontSize: 12.5, color: "#5A6B84", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{p.svc || "—"}</span>
              <span className="mono" style={{ justifySelf: "start", fontSize: 11, fontWeight: 700, borderRadius: 6, padding: "3px 9px", ...(PORT[p.state] ?? PORT.closed) }}>{p.state}</span>
            </div>
          ))}
          {h.ports.length === 0 && <div style={{ padding: 40, textAlign: "center", color: "#9aa6b8", fontSize: 13.5 }}>No ports yet.</div>}
        </div>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
          <span style={{ font: "700 13px Inter,sans-serif", color: "#0F1B2D" }}>Endpoints <span className="mono" style={{ color: "#8A97AB", fontWeight: 600 }}>{h.endpoints.length}</span></span>
        </div>
        <div style={{ ...CARD, overflow: "hidden" }}>
          {h.endpoints.map((e, ei) => {
            const m = METHOD[e.m] ?? PORT.closed;
            return (
              <div key={ei} className="prow clk" onClick={() => openEndpoint({ method: e.m, path: e.p, host: h.host, hostId: h.id, endpointId: e.id })} style={{ display: "grid", gridTemplateColumns: "72px minmax(0,1fr) 96px", alignItems: "center", gap: 12, padding: "13px 20px", borderBottom: "1px solid #f2f4f9" }}>
                <span className="mono" style={{ justifySelf: "start", fontWeight: 700, borderRadius: 5, padding: "2px 8px", fontSize: 10.5, background: m.bg, color: m.color }}>{e.m}</span>
                <div className="mono" style={{ fontSize: 12.5, color: "#0F1B2D", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.p}</div>
                <div style={{ display: "flex", justifyContent: "flex-end", gap: 2 }}>
                  <div className="actbtn" title="Copy as cURL" onClick={(ev) => { ev.stopPropagation(); copyCurl({ method: e.m, path: e.p, host: h.host }); }}><Icon name="copy" size={15} /></div>
                  <div className="actbtn del" title="Delete endpoint" onClick={(ev) => { ev.stopPropagation(); void deleteEndpoint(h.id, e.id); }}><Icon name="trash" size={15} /></div>
                </div>
              </div>
            );
          })}
          {h.endpoints.length === 0 && <div style={{ padding: 40, textAlign: "center", color: "#9aa6b8", fontSize: 13.5 }}>No endpoints yet.</div>}
        </div>
      </div>
    );
  };

  const renderVulns = () => {
    if (state.openVulnId != null) return renderVulnDetail();
    return (
      <div className="route">
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 16, marginBottom: 16, flexWrap: "wrap" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, font: "600 12.5px Inter,sans-serif", color: "#8A97AB" }}>
            <Icon name="info" size={15} /><b className="mono" style={{ color: "#0F1B2D" }}>{vulns.length}</b> findings on this page
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
            <span className="mono" style={{ fontSize: 10.5, letterSpacing: 1, color: "#a8b2c2", fontWeight: 700 }}>AUTHOR</span>
            <input placeholder="Filter by author…" value={state.vulnFilterAuthor} onChange={(e) => setState({ vulnFilterAuthor: e.target.value })} style={{ font: "600 12px Inter,sans-serif", padding: "6px 10px", borderRadius: 20, background: "#fff", color: "#5A6B84", border: "1px solid #dbe1ec", width: 150 }} />
            {/* Status / severity are multi-select: pills toggle, several can be held at
                once, and clearing the last one falls back to "All". Driven by the token
                lists so they cannot drift from the backend's vocabularies. */}
            <span className="mono" style={{ fontSize: 10.5, letterSpacing: 1, color: "#a8b2c2", fontWeight: 700, marginLeft: 6 }}>STATUS</span>
            <div className="clk" onClick={() => setState({ vulnFilterStatuses: [] })} style={{ font: "600 12px Inter,sans-serif", padding: "6px 12px", borderRadius: 20, cursor: "pointer", ...vfPill(vfS.length === 0) }}>All</div>
            {VSTATUS_ORDER.map((s) => (
              <div key={s} className="clk" onClick={() => setState((st) => ({ vulnFilterStatuses: toggleIn(st.vulnFilterStatuses, s) }))} style={{ font: "600 12px Inter,sans-serif", padding: "6px 12px", borderRadius: 20, cursor: "pointer", ...vfPill(vfS.includes(s)) }}>{VSTATUS_LABEL[s]}</div>
            ))}
            <span className="mono" style={{ fontSize: 10.5, letterSpacing: 1, color: "#a8b2c2", fontWeight: 700, marginLeft: 6 }}>SEVERITY</span>
            <div className="clk" onClick={() => setState({ vulnFilterSeverities: [] })} style={{ font: "600 12px Inter,sans-serif", padding: "6px 12px", borderRadius: 20, cursor: "pointer", ...vfPill(vfSev.length === 0) }}>All</div>
            {(["critical", "high", "medium", "low", "info"] as Severity[]).map((s) => (
              <div key={s} className="clk" onClick={() => setState((st) => ({ vulnFilterSeverities: toggleIn(st.vulnFilterSeverities, s) }))} style={{ font: "600 12px Inter,sans-serif", padding: "6px 12px", borderRadius: 20, cursor: "pointer", ...vfPill(vfSev.includes(s)) }}>{cap(s)}</div>
            ))}
            <input placeholder="Filter by host…" value={state.vulnFilterHost} onChange={(e) => setState({ vulnFilterHost: e.target.value })} style={{ font: "600 12px Inter,sans-serif", padding: "6px 10px", borderRadius: 20, background: "#fff", color: "#5A6B84", border: "1px solid #dbe1ec", width: 150 }} />
          </div>
        </div>
        <div style={{ ...CARD, overflow: "hidden" }}>
          <div style={{ display: "grid", gridTemplateColumns: "48px minmax(0,1.8fr) minmax(0,1fr) 140px 110px 130px 120px 64px", gap: 10, padding: "13px 20px", borderBottom: "1px solid #eef1f7", font: "700 11px Inter,sans-serif", letterSpacing: ".5px", color: "#a0abbd", textTransform: "uppercase" }}>
            <div>#</div><div>Title</div><div>Asset</div><div>Status</div><div>Severity</div><div>Author</div><div>Updated</div><div />
          </div>
          {vulns.map((v) => (
            <div key={v.num} className="prow clk" onClick={v.onOpen} style={{ display: "grid", gridTemplateColumns: "48px minmax(0,1.8fr) minmax(0,1fr) 140px 110px 130px 120px 64px", alignItems: "center", gap: 10, padding: "14px 20px", borderBottom: "1px solid #f2f4f9" }}>
              <div className="mono" style={{ fontSize: 13, color: "#b3bccd", fontWeight: 600 }}>{String(v.num).padStart(2, "0")}</div>
              <div style={{ font: "600 14px Inter,sans-serif", color: "#0F1B2D", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{v.title}</div>
              <div className="mono" style={{ fontSize: 12, color: "#8A97AB", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{v.host}</div>
              <div style={{ display: "flex", alignItems: "center", gap: 7, font: "600 12px Inter,sans-serif", color: VSTATUS[v.status] ?? "#6b7a90" }}><span style={{ width: 7, height: 7, flex: "none", borderRadius: "50%", background: VSTATUS[v.status] ?? "#6b7a90" }} />{VSTATUS_LABEL[v.status] ?? v.status}</div>
              <span style={{ justifySelf: "start", font: "700 10.5px Inter,sans-serif", textTransform: "uppercase", letterSpacing: ".5px", borderRadius: 7, padding: "4px 9px", background: SEV[v.sev].bg, color: SEV[v.sev].color }}>{v.sev}</span>
              <div className="mono" style={{ fontSize: 12, color: "#5A6B84", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{v.author}</div>
              <div className="mono" style={{ fontSize: 11.5, color: "#a0abbd" }}>{v.updated}</div>
              <div style={{ display: "flex", justifyContent: "flex-end", gap: 2 }}>
                <div className="actbtn" onClick={v.onEdit}><Icon name="edit" size={15} /></div>
                <div className="actbtn del" onClick={v.onDelete}><Icon name="trash" size={15} /></div>
              </div>
            </div>
          ))}
          {vulns.length === 0 && <div style={{ padding: 52, textAlign: "center", color: "#9aa6b8", fontSize: 14 }}>No findings match these filters.</div>}
        </div>
      </div>
    );
  };

  const renderVulnDetail = () => {
    // openVulnId is a backend id, not a list index — look the finding up by id.
    const original = state.openVulnId != null ? d.vulns.find((v) => v.id === state.openVulnId) : undefined;
    return (
      <div style={{ width: "100%" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, marginBottom: 18 }}>
          <span className="clk" onClick={closeVulnDetail} style={{ display: "inline-flex", alignItems: "center", gap: 6, font: "600 12.5px Inter,sans-serif", color: "#5A6B84", background: "#fff", border: "1px solid #e9edf4", borderRadius: 20, padding: "7px 13px", cursor: "pointer" }}>
            <Icon name="chevron-left" size={15} />All findings
          </span>
          <button className="addbtn clk" onClick={() => openEditor("vuln", "add", -1)} style={{ height: 38, flex: "none" }}>
            <Icon name="plus" size={15} color="#fff" sw={2.6} />Add issue
          </button>
        </div>
        <div style={{ ...CARD, padding: "26px 28px" }}>
          <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 16, marginBottom: 20 }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <label className="flabel">Title</label>
              <input className="finp" value={vd.title || ""} onChange={(e) => updateVulnDetailForm("title", e.target.value)} style={{ font: "800 18px Inter,sans-serif" }} />
            </div>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 14 }}>
            <div><label className="flabel">Affected host</label><input className="finp" value={vd.host || ""} onChange={(e) => updateVulnDetailForm("host", e.target.value)} /></div>
            <div><label className="flabel">CWE ID</label><input className="finp mono" placeholder="e.g. CWE-89" value={vd.cwe || ""} onChange={(e) => updateVulnDetailForm("cwe", e.target.value)} /></div>
          </div>
          <div style={{ marginBottom: 18 }}>
            <div style={{ display: "flex", alignItems: "flex-end", gap: 14 }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <label className="flabel">CVSS 4.0 vector</label>
                <input className="finp mono" placeholder="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" value={vd.vector || ""} onChange={(e) => updateVulnDetailForm("vector", e.target.value)} style={{ width: "100%", fontSize: 12.5 }} />
              </div>
              <div style={{ flex: "none", width: 150 }}>
                <label className="flabel">Severity</label>
                <div className="finp" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, cursor: "default" }}>
                  <span style={{ font: "700 11px Inter,sans-serif", textTransform: "uppercase", letterSpacing: ".5px", borderRadius: 6, padding: "3px 8px", background: SEV[vdSev].bg, color: SEV[vdSev].color }}>{vdSev}</span>
                  <span className="mono" style={{ fontSize: 12.5, color: "#5A6B84" }}>{vdScore}</span>
                </div>
              </div>
              <div style={{ flex: "none", width: 170 }}>
                <label className="flabel">Status</label>
                <select className="finp" value={vd.status || "open"} onChange={(e) => updateVulnDetailForm("status", e.target.value as VStatus)}>
                  {VSTATUS_ORDER.map((s) => <option key={s} value={s}>{VSTATUS_LABEL[s]}</option>)}
                </select>
              </div>
            </div>
          </div>
          <div style={{ marginBottom: 18 }}>
            <label className="flabel">Steps to reproduce</label>
            <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 6 }}>
              {(vd.stepsList ?? []).map((s, i) => {
                const imgs = (vd.stepImages ?? {})[i] ?? [];
                return (
                  <div key={i} style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                      <span className="mono" style={{ flex: "none", width: 26, height: 26, borderRadius: 8, background: "#EAF0FC", color: "#2E5FBF", fontWeight: 700, fontSize: 12, display: "flex", alignItems: "center", justifyContent: "center" }}>{i + 1}</span>
                      <input className="finp" placeholder="Describe this step… (paste a screenshot to attach)" value={s} onChange={(e) => updateVdStep(i, e.target.value)} onPaste={(e) => pasteVdStepImage(i, e)} style={{ flex: 1, fontFamily: "ui-monospace,Menlo,monospace", fontSize: 12.5 }} />
                      <div className="actbtn del" onClick={() => removeVdStep(i)}><Icon name="trash" size={15} /></div>
                    </div>
                    {imgs.length > 0 && (
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginLeft: 36 }}>
                        {imgs.map((src, ii) => (
                          <div key={ii} style={{ position: "relative" }}>
                            <img src={src} alt={`Step ${i + 1} screenshot ${ii + 1}`} title="Click to view" onClick={() => setState({ lightboxSrc: src })} style={{ height: 78, borderRadius: 9, border: "1px solid #e3e8f0", display: "block", cursor: "zoom-in" }} />
                            <div className="clk" onClick={() => removeVdStepImage(i, ii)} style={{ position: "absolute", top: -7, right: -7, width: 20, height: 20, borderRadius: "50%", background: "#C0455B", color: "#fff", display: "flex", alignItems: "center", justifyContent: "center", font: "700 13px Inter,sans-serif", lineHeight: 1, cursor: "pointer", border: "2px solid #fff" }}>×</div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
            <button className="clk" onClick={addVdStep} style={{ marginTop: 10, display: "inline-flex", alignItems: "center", gap: 6, height: 36, padding: "0 14px", border: "1px dashed #dbe1ec", borderRadius: 10, background: "#fff", font: "700 12.5px Inter,sans-serif", color: "#5A6B84", cursor: "pointer" }}>
              <Icon name="plus" size={13} sw={2.4} />Add step
            </button>
          </div>
          <div style={{ marginBottom: 18 }}><label className="flabel">Impact</label><textarea className="finp" rows={2} placeholder="Business/security impact if exploited…" value={vd.impact || ""} onChange={(e) => updateVulnDetailForm("impact", e.target.value)} /></div>
          <div><label className="flabel">Remediation</label><textarea className="finp" rows={3} placeholder="How to fix or mitigate this vulnerability…" value={vd.remediation || ""} onChange={(e) => updateVulnDetailForm("remediation", e.target.value)} /></div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 22, fontSize: 12, color: "#a0abbd" }}>
            <span>Reported by <b style={{ color: "#7c8aa0" }}>{original?.author}</b> · {original?.updated}</span>
            <div style={{ display: "flex", gap: 10 }}>
              <button className="clk" onClick={closeVulnDetail} style={{ height: 40, padding: "0 18px", border: "1px solid #dbe1ec", borderRadius: 10, background: "#fff", font: "700 13px Inter,sans-serif", color: "#5A6B84" }}>Cancel</button>
              <button className="clk" onClick={saveVulnDetail} style={{ height: 40, padding: "0 20px", border: "none", borderRadius: 10, background: "#4C74C7", color: "#fff", font: "700 13px Inter,sans-serif" }}>Save changes</button>
            </div>
          </div>
        </div>
      </div>
    );
  };

  /** First non-empty line of the body, with Markdown syntax stripped — the card preview. */
  const notePreview = (md: string) => {
    const line = md.replace(/\r/g, "").split("\n").map((l) => l.trim()).find((l) => l && !/^[-*_]{3,}$/.test(l)) ?? "";
    return line
      .replace(/^#{1,6}\s+/, "")
      .replace(/^\s*[-*]\s+/, "")
      .replace(/\*\*([^*]+)\*\*/g, "$1")
      .replace(/\*([^*]+)\*/g, "$1")
      .replace(/`([^`]+)`/g, "$1")
      .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1");
  };

  const renderNotes = () => (
    <div className="route" style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      {d.notes.map((n, idx) => {
        const mine = n.author === me;
        return (
          // Clicking a note always opens it rendered — your own notes included.
          <div key={n.id} className="statc clk" onClick={() => openNoteViewer(n.id)} style={{ ...CARD, padding: "18px 20px" }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
              <div style={{ font: "700 15px Inter,sans-serif", color: "#0F1B2D" }}>{n.title}</div>
              <div style={{ display: "flex", alignItems: "center", gap: 8, flex: "none" }}>
                {mine && (
                  <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                    <div className="actbtn" onClick={(e) => { e.stopPropagation(); openNoteEditor("edit", idx); }}><Icon name="edit" size={15} /></div>
                    <div className="actbtn del" onClick={(e) => { e.stopPropagation(); askDelete("note", idx, n.title); }}><Icon name="trash" size={15} /></div>
                  </div>
                )}
                <span className="mono" style={{ fontSize: 11.5, color: "#a0abbd" }}>{n.when}</span>
              </div>
            </div>
            <div style={{ fontSize: 13, color: "#6b7a90", marginTop: 6, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{notePreview(n.excerpt)}</div>
            <div className="mono" style={{ fontSize: 11.5, color: "#8A97AB", marginTop: 12 }}>{n.author}</div>
          </div>
        );
      })}
      {d.notes.length === 0 && <div style={{ ...CARD, padding: 52, textAlign: "center", color: "#9aa6b8", fontSize: 14 }}>No notes yet.</div>}
    </div>
  );

  /* The note deep link (/projects/{p}/notes/{n}) renders the body as Markdown.
     Your own notes get an Edit button here rather than opening raw on click. */
  const renderNoteViewer = () => {
    const idx = d.notes.findIndex((x) => x.id === state.openNoteId);
    const n = idx === -1 ? undefined : d.notes[idx];
    if (!n) {
      if (state.apiNotes === null) return <div className="route" style={{ ...CARD, padding: 48, textAlign: "center", color: "#9aa6b8", fontSize: 14 }}>Loading note…</div>;
      return renderNoAccess("Заметка не найдена.");
    }
    const mine = n.author === me;
    return (
      <div className="route" style={{ ...CARD, padding: 0, overflow: "hidden" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "16px 22px", borderBottom: "1px solid #eef1f7" }}>
          <span className="clk" onClick={closeNoteViewer} style={{ display: "flex", color: "#8A97AB", cursor: "pointer" }}><Icon name="chevron-left" size={20} /></span>
          <h2 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: "#0F1B2D" }}>{n.title}</h2>
          <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 10 }}>
            {mine ? (
              <button className="clk" onClick={() => openNoteEditor("edit", idx)} style={{ display: "inline-flex", alignItems: "center", gap: 7, height: 36, padding: "0 14px", border: "1px solid #dbe1ec", borderRadius: 10, background: "#fff", font: "700 12.5px Inter,sans-serif", color: "#5A6B84", cursor: "pointer" }}>
                <Icon name="edit" size={14} />Edit
              </button>
            ) : (
              <span style={{ display: "inline-flex", alignItems: "center", gap: 6, font: "600 11px Inter,sans-serif", color: "#8A97AB", background: "#f2f4f9", borderRadius: 20, padding: "5px 11px" }}>
                <Icon name="eye" size={12} />Read only
              </span>
            )}
          </div>
        </div>
        <div style={{ padding: "24px 22px" }}>
          <div style={{ maxWidth: 720 }}>{renderMarkdown(n.excerpt)}</div>
          <div className="mono" style={{ fontSize: 11.5, color: "#a0abbd", marginTop: 24, paddingTop: 16, borderTop: "1px solid #f0f2f7" }}>{n.author} · {n.when}</div>
        </div>
      </div>
    );
  };

  const renderNoteEditor = () => (
    <div className="route" style={{ ...CARD, padding: 0, overflow: "hidden" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, padding: "16px 22px", borderBottom: "1px solid #eef1f7" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span className="clk" onClick={closeNoteEditor} style={{ display: "flex", color: "#8A97AB", cursor: "pointer" }}><Icon name="chevron-left" size={20} /></span>
          <h2 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: "#0F1B2D" }}>{state.noteEditorMode === "add" ? "New note" : "Edit note"}</h2>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <button className="clk" onClick={closeNoteEditor} style={{ height: 38, padding: "0 16px", border: "1px solid #dbe1ec", borderRadius: 10, background: "#fff", font: "700 13px Inter,sans-serif", color: "#5A6B84", cursor: "pointer" }}>Cancel</button>
          <button className="clk" onClick={saveNote} style={{ height: 38, padding: "0 18px", border: "none", borderRadius: 10, background: "#4C74C7", color: "#fff", font: "700 13px Inter,sans-serif", cursor: "pointer" }}>Save note</button>
        </div>
      </div>
      <div style={{ padding: "22px 22px 8px" }}>
        <label className="flabel">Title</label>
        <input className="finp" placeholder="Give this note a title…" value={state.noteForm.title} onChange={(e) => updateNoteForm("title", e.target.value)} style={{ font: "700 16px Inter,sans-serif", height: 48, background: "#f7f9fc" }} />
      </div>
      {/* Markdown renders as you type (### + space → heading, right in the line) —
          the note is still stored as Markdown, so the viewer and the reports read
          exactly what was typed. */}
      <div style={{ padding: "14px 22px 24px" }}>
        <label className="flabel">Content</label>
        <Suspense fallback={<div className="stormmd" style={{ minHeight: 260, color: "#9aa6b8", font: "500 14px Inter,sans-serif" }}>Loading editor…</div>}>
          <StormMarkdownEditor
            value={state.noteForm.excerpt}
            onChange={(md) => updateNoteForm("excerpt", md)}
            placeholder="Write your note… «### » makes a heading, «- » a list"
          />
        </Suspense>
      </div>
    </div>
  );

  const renderMembers = () => {
    const mq = state.memberQuery.trim().toLowerCase();
    const filtered = d.members
      .map((m, idx) => ({ m, idx }))
      .filter(({ m }) => (state.memberRoles.length === 0 || state.memberRoles.includes(m.role)) && (!mq || m.name.toLowerCase().includes(mq)));
    return (
      <div className="route">
        {/* search + role filter */}
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16, flexWrap: "wrap" }}>
          <label className="fq" style={{ position: "relative", display: "flex", alignItems: "center", width: 280 }}>
            <svg style={{ position: "absolute", left: 13 }} width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#9aa6b8" strokeWidth="2" strokeLinecap="round"><circle cx="11" cy="11" r="7" /><path d="M21 21l-4-4" /></svg>
            <input placeholder="Search by username…" value={state.memberQuery} onChange={(e) => setState({ memberQuery: e.target.value })} />
          </label>
          <div style={{ flex: 1 }} />
          {/* Every pill toggles; an empty selection means "All". */}
          <span className="mono" style={{ fontSize: 10.5, letterSpacing: 1, color: "#a8b2c2", fontWeight: 700 }}>ROLE</span>
          <div className="clk" onClick={() => setState({ memberRoles: [] })} style={{ font: "600 12px Inter,sans-serif", padding: "6px 12px", borderRadius: 20, cursor: "pointer", ...vfPill(state.memberRoles.length === 0) }}>All</div>
          {([{ label: "Lead", v: "lead" as const }, { label: "Pentester", v: "pentester" as const }]).map((o) => (
            <div key={o.v} className="clk" onClick={() => setState((s) => ({ memberRoles: toggleIn(s.memberRoles, o.v) }))} style={{ font: "600 12px Inter,sans-serif", padding: "6px 12px", borderRadius: 20, cursor: "pointer", ...vfPill(state.memberRoles.includes(o.v)) }}>{o.label}</div>
          ))}
        </div>
        <div style={{ ...CARD, overflow: "hidden" }}>
          {filtered.map(({ m, idx }) => (
            <div key={m.name + idx} className="prow" style={{ display: "flex", alignItems: "center", gap: 13, padding: "15px 20px", borderBottom: "1px solid #f2f4f9" }}>
              <span className="mono" style={{ width: 38, height: 38, flex: "none", borderRadius: "50%", background: m.color, color: "#fff", display: "flex", alignItems: "center", justifyContent: "center", font: "700 13px 'JetBrains Mono',monospace" }}>{m.initials}</span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ font: "600 14px Inter,sans-serif", color: "#0F1B2D" }}>{m.name}</span>
                  <span style={{ font: "700 10px Inter,sans-serif", textTransform: "uppercase", letterSpacing: ".5px", borderRadius: 6, padding: "2px 8px", background: ROLE[m.role].bg, color: ROLE[m.role].color }}>{m.role}</span>
                </div>
                <div className="mono" style={{ fontSize: 12, color: "#a0abbd", marginTop: 2 }}>{m.email}</div>
              </div>
              {canManageMembers && (
                <div style={{ display: "flex", gap: 2 }}>
                  <div className="actbtn del" onClick={() => askDelete("member", idx, m.name)}><Icon name="trash" size={15} /></div>
                </div>
              )}
            </div>
          ))}
          {filtered.length === 0 && <div style={{ padding: 44, textAlign: "center", color: "#9aa6b8", fontSize: 14 }}>No members match.</div>}
        </div>
      </div>
    );
  };

  /* UPDATE/DELETE audit rows carry no details, so the feed resolves the entity's
     name from the project data already loaded rather than printing "#12". */
  const resolveActivityName: ActivityResolver = (type, id) => {
    if (id == null) return null;
    if (type === "host") return hosts.find((h) => h.id === id)?.host ?? null;
    if (type === "vulnerability") return d.vulns.find((v) => v.id === id)?.title ?? null;
    if (type === "project_note" || type === "note") return d.notes.find((n) => n.id === id)?.title ?? null;
    if (type === "project") return projRow?.id === id ? projRow.name : null;
    if (type === "endpoint") {
      for (const h of hosts) {
        const e = h.endpoints.find((x) => x.id === id);
        if (e) return `${e.m} ${e.p}`;
      }
    }
    return null;
  };

  /* Grouped up-front rather than inside renderActivity: the tab's counter must
     match what the feed actually lists (cards, ports already dropped), and it has
     to be right before the tab is opened. */
  const activityGroups = groupActivity(state.activity ?? [], resolveActivityName);

  /** One line of the dark event panel: + text [SEVERITY]. */
  const activityLineRow = (l: ActivityLine, tone: ActTone) => (
    <div key={l.key} style={{ display: "flex", alignItems: "center", gap: 9, whiteSpace: "nowrap" }}>
      <span className="mono" style={{ flex: "none", width: 10, textAlign: "center", font: "700 12.5px 'JetBrains Mono',monospace", color: tone.color }}>
        {tone.mark}
      </span>
      <span style={{ font: "600 12.5px 'JetBrains Mono',monospace", color: "#C8D3E4", textOverflow: "ellipsis", overflow: "hidden" }}>{l.text}</span>
      {/* Severity sits in a chip filled with that severity's own colour. */}
      {l.severity && (
        <span
          className="mono"
          style={{ flex: "none", font: "700 9.5px 'JetBrains Mono',monospace", letterSpacing: ".4px", textTransform: "uppercase", borderRadius: 4, padding: "3px 6px", background: ACT_SEV[l.severity], color: "#fff" }}
        >
          {l.severity}
        </span>
      )}
    </div>
  );

  /* Project activity: /projects/{id}/activity, visible to every project member.
     One white card per action per entity type, each listing exactly *what* was
     touched inside a dark panel. Long lists collapse to ACT_LINE_LIMIT rows and
     open in full in a modal. */
  const renderActivity = () => {
    const logs = state.activity ?? [];
    if (state.activityLoading && logs.length === 0)
      return <div className="route" style={{ ...CARD, padding: 48, textAlign: "center", color: "#9aa6b8", fontSize: 14 }}>Loading activity…</div>;
    if (state.activityError) return renderNoAccess(state.activityError);
    const groups = activityGroups;
    if (groups.length === 0)
      return <div className="route" style={{ ...CARD, padding: 48, textAlign: "center", color: "#9aa6b8", fontSize: 14 }}>No activity yet.</div>;
    return (
      <div className="route" style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        {groups.map((g) => {
          const hidden = g.lines.length - ACT_LINE_LIMIT;
          const shown = hidden > 0 ? g.lines.slice(0, ACT_LINE_LIMIT) : g.lines;
          return (
            <div key={g.key} style={{ ...CARD, padding: "16px 18px", display: "flex", gap: 13 }}>
              <span
                className="mono"
                style={{ width: 32, height: 32, flex: "none", borderRadius: "50%", background: g.actor === "System" ? "#EEF3FC" : "#2E5FBF", color: g.actor === "System" ? "#4C74C7" : "#fff", display: "flex", alignItems: "center", justifyContent: "center", font: "700 11px 'JetBrains Mono',monospace" }}
              >
                {g.actor === "System" ? <Icon name="clock2" size={15} /> : initialsOf(g.actor)}
              </span>
              <div style={{ flex: 1, minWidth: 0 }}>
                {/* The count reads inline — "admin added 3 IP addresses" — rather
                    than as a separate badge repeating what the list already shows. */}
                <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
                  <div style={{ fontSize: 13.5, color: "#3a4a60", lineHeight: 1.5, flex: 1, minWidth: 0 }}>
                    <b className="mono" style={{ color: "#0F1B2D" }}>{g.actor}</b> {g.verb} <b style={{ color: "#0F1B2D" }}>{g.subject}</b>
                  </div>
                  <span className="mono" style={{ flex: "none", fontSize: 11.5, color: "#a0abbd" }}>{g.time}</span>
                </div>
                <div style={{ marginTop: 11, background: "#111C2E", borderRadius: 10, padding: "11px 13px", display: "flex", flexDirection: "column", gap: 6, overflowX: "auto" }}>
                  {shown.map((l) => activityLineRow(l, g.tone))}
                  {hidden > 0 && (
                    <div
                      className="clk"
                      onClick={() => setState({ activityModalKey: g.key })}
                      style={{ marginTop: 3, font: "700 11.5px Inter,sans-serif", color: "#8FB4F5", cursor: "pointer" }}
                    >
                      Show more · ещё {hidden}
                    </div>
                  )}
                </div>
                {/* Findings link out from under the panel — the title itself is plain text. */}
                {g.vulnId != null && (
                  <div
                    className="clk"
                    onClick={() => openVulnDetail(g.vulnId as number)}
                    style={{ marginTop: 10, display: "inline-flex", alignItems: "center", gap: 5, font: "700 12px Inter,sans-serif", color: "#4C74C7", cursor: "pointer" }}
                  >
                    Show details<Icon name="chevron-right" size={13} sw={2.4} />
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    );
  };

  // ---------- Profile ----------
  const renderProfile = () => (
    <div className="route" style={{ padding: "40px 48px 36px", width: "100%" }}>
      {eyebrow([{ label: "Account", onClick: selProjects }, { label: "Profile settings", muted: true }])}
      <h1 style={{ margin: 0, fontSize: 30, fontWeight: 800, letterSpacing: "-.7px", color: "#0F1B2D" }}>Profile Settings</h1>
      <div style={{ fontSize: 13.5, color: "#8A97AB", marginTop: 6 }}>Signed in as <b style={{ color: "#5A6B84" }}>{me}</b> · manage your account, security, integrations &amp; automation</div>

      <div style={{ display: "grid", gridTemplateColumns: "260px 1fr", gap: 22, alignItems: "start", marginTop: 26 }}>
        <div style={{ ...CARD, padding: 8 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, padding: "14px 12px 16px" }}>
            <div style={{ width: 44, height: 44, flex: "none", borderRadius: "50%", background: "#2E5FBF", color: "#fff", display: "flex", alignItems: "center", justifyContent: "center", font: "700 17px 'JetBrains Mono',monospace" }}>{meInitials}</div>
            <div style={{ minWidth: 0 }}>
              <div style={{ font: "700 14px Inter,sans-serif", color: "#0F1B2D" }}>{meDisplay}</div>
              <div style={{ display: "flex", alignItems: "center", gap: 5, marginTop: 3, font: "600 11.5px Inter,sans-serif", color: "#2E8B57" }}><Icon name="shield-check" size={12} sw={2.2} />Active</div>
            </div>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
            <div className="clk" onClick={() => setState({ profileTab: "account" })} style={{ display: "flex", alignItems: "center", gap: 11, padding: "10px 12px", borderRadius: 10, cursor: "pointer", font: "600 13.5px Inter,sans-serif", ...pfNav("account") }}><Icon name="user1" size={17} />Account</div>
            <div className="clk" onClick={() => setState({ profileTab: "security" })} style={{ display: "flex", alignItems: "center", gap: 11, padding: "10px 12px", borderRadius: 10, cursor: "pointer", font: "600 13.5px Inter,sans-serif", ...pfNav("security") }}>
              <Icon name="lock" size={17} /><span style={{ flex: 1 }}>Security</span>
              {state.twoFAEnabled && <span className="mono" style={{ fontSize: 9.5, fontWeight: 700, letterSpacing: ".5px", color: "#2E8B57", background: "#E7F5EC", borderRadius: 6, padding: "2px 6px" }}>2FA</span>}
            </div>
            <div className="clk" onClick={() => setState({ profileTab: "api" })} style={{ display: "flex", alignItems: "center", gap: 11, padding: "10px 12px", borderRadius: 10, cursor: "pointer", font: "600 13.5px Inter,sans-serif", ...pfNav("api") }}><Icon name="plug" size={17} />API &amp; Automation</div>
          </div>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
          {state.profileTab === "account" && renderProfileAccount()}
          {state.profileTab === "security" && renderProfileSecurity()}
          {state.profileTab === "api" && renderProfileApi()}
        </div>
      </div>
    </div>
  );

  const cardHeader = (icon: Parameters<typeof Icon>[0]["name"], title: string, sub: string, right?: ReactNode) => (
    <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 14, marginBottom: 18 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <div style={{ width: 38, height: 38, flex: "none", borderRadius: 10, background: "#EAF0FC", color: "#2E5FBF", display: "flex", alignItems: "center", justifyContent: "center" }}><Icon name={icon} size={19} /></div>
        <div><div style={{ font: "700 15px Inter,sans-serif", color: "#0F1B2D" }}>{title}</div><div style={{ fontSize: 12.5, color: "#8A97AB", marginTop: 2 }}>{sub}</div></div>
      </div>
      {right}
    </div>
  );

  const renderProfileAccount = () => (
    <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
      <div style={{ ...CARD, padding: "22px 24px" }}>
        {cardHeader("image", "Profile Picture", "Shown next to your name across the workspace")}
        <div style={{ display: "flex", alignItems: "center", gap: 28 }}>
          <div style={{ width: 84, height: 84, flex: "none", borderRadius: "50%", background: "#2E5FBF", color: "#fff", display: "flex", alignItems: "center", justifyContent: "center", font: "700 30px 'JetBrains Mono',monospace" }}>{meInitials[0]}</div>
          <div style={{ flex: 1 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <input id="pfFileInput" type="file" accept="image/png,image/jpeg" style={{ display: "none" }} />
              <label htmlFor="pfFileInput" className="clk" style={{ display: "inline-flex", alignItems: "center", gap: 8, height: 42, padding: "0 18px", border: "1px solid #dbe1ec", borderRadius: 11, background: "#fff", font: "700 13px Inter,sans-serif", color: "#5A6B84", cursor: "pointer" }}><Icon name="image" size={15} />Choose file</label>
              <button className="clk" style={{ display: "inline-flex", alignItems: "center", gap: 8, height: 42, padding: "0 18px", border: "none", borderRadius: 11, background: "#2E5FBF", color: "#fff", font: "700 13px Inter,sans-serif", cursor: "pointer" }}><Icon name="upload" size={15} color="#fff" />Upload</button>
            </div>
            <div style={{ fontSize: 12.5, color: "#a0abbd", marginTop: 12 }}>JPEG / PNG only, up to <b style={{ color: "#7c8aa0" }}>1 MB</b>. Square images look best.</div>
          </div>
        </div>
      </div>

      <div style={{ ...CARD, padding: "22px 24px" }}>
        {cardHeader("idcard", "Account identity", "Read-only — managed by your administrator", <span style={{ font: "700 11px Inter,sans-serif", color: "#5A6B84", background: "#f1f4f9", border: "1px solid #e6eaf1", borderRadius: 8, padding: "5px 11px" }}>Active</span>)}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", border: "1px solid #eef1f7", borderRadius: 12, overflow: "hidden" }}>
          {[
            { label: "Username", value: me, mono: true, color: "#0F1B2D" },
            { label: "Email", value: meEmail, mono: true, color: "#0F1B2D", small: true },
            { label: "Role", value: meRoleLabel, mono: false, color: "#2E5FBF" },
            { label: "User ID", value: String(meId), mono: true, color: "#4C74C7", last: true },
          ].map((c, i) => (
            <div key={i} style={{ padding: "15px 18px", borderRight: c.last ? "none" : "1px solid #eef1f7" }}>
              <div className="mono" style={{ fontSize: 10, letterSpacing: ".8px", color: "#a8b2c2", fontWeight: 700, textTransform: "uppercase" }}>{c.label}</div>
              <div className={c.mono ? "mono" : undefined} style={{ fontSize: c.small ? 13 : 14, color: c.color, fontWeight: c.mono ? 600 : 700, marginTop: 7, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", ...(c.mono ? {} : { font: "700 13px Inter,sans-serif" }) }}>{c.value}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  const renderProfileSecurity = () => (
    <div style={{ ...CARD, padding: "22px 24px" }}>
      {cardHeader("lock", "Two-factor authentication", "Protect sign-in with a Google Authenticator code")}
      {state.twoFAEnabled ? (
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 14, border: "1px solid #e7f5ec", background: "#F3FAF6", borderRadius: 12, padding: "14px 16px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}><Icon name="check-circle" size={18} color="#2E8B57" sw={2.2} /><span style={{ font: "600 13.5px Inter,sans-serif", color: "#0F1B2D" }}>Enabled via Google Authenticator</span></div>
          <button className="clk" onClick={disableTwoFA} style={{ height: 38, padding: "0 16px", border: "1px solid #dbe1ec", borderRadius: 10, background: "#fff", font: "700 12.5px Inter,sans-serif", color: "#C0455B", cursor: "pointer" }}>Disable</button>
        </div>
      ) : state.twoFASetupOpen ? (
        <div style={{ border: "1px solid #eef1f7", borderRadius: 12, padding: 18 }}>
          <div style={{ font: "600 13px Inter,sans-serif", color: "#0F1B2D", marginBottom: 14 }}>1. Scan this QR in Google Authenticator</div>
          <div style={{ display: "flex", gap: 20, alignItems: "center", flexWrap: "wrap" }}>
            <div style={{ width: 120, height: 120, flex: "none", borderRadius: 10, background: "repeating-conic-gradient(#0F1B2D 0% 25%, #fff 0% 50%) 50% / 14px 14px", border: "1px solid #eef1f7" }} />
            <div>
              <div style={{ font: "600 13px Inter,sans-serif", color: "#0F1B2D", marginBottom: 6 }}>Or enter this key manually</div>
              <div className="mono" style={{ fontSize: 13, letterSpacing: 1, background: "#f6f8fc", border: "1px solid #eef1f7", borderRadius: 8, padding: "8px 12px", display: "inline-block" }}>JBSW Y3DP EHPK 3PXP</div>
            </div>
          </div>
          <div style={{ font: "600 13px Inter,sans-serif", color: "#0F1B2D", margin: "18px 0 10px" }}>2. Enter the 6-digit code</div>
          <div style={{ display: "flex", gap: 10 }}>
            <input className="finp" placeholder="000000" value={state.twoFACode} onChange={(e) => setState({ twoFACode: e.target.value })} style={{ maxWidth: 160, font: "700 16px 'JetBrains Mono',monospace", letterSpacing: 4, textAlign: "center" }} />
            <button className="clk" onClick={confirmTwoFA} style={{ height: 44, padding: "0 18px", border: "none", borderRadius: 11, background: "#2E5FBF", color: "#fff", font: "700 13px Inter,sans-serif", cursor: "pointer" }}>Verify &amp; enable</button>
            <button className="clk" onClick={cancelTwoFA} style={{ height: 44, padding: "0 16px", border: "1px solid #dbe1ec", borderRadius: 11, background: "#fff", font: "700 13px Inter,sans-serif", color: "#5A6B84", cursor: "pointer" }}>Cancel</button>
          </div>
        </div>
      ) : (
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 14, border: "1px solid #eef1f7", borderRadius: 12, padding: "14px 16px" }}>
          <span style={{ font: "600 13.5px Inter,sans-serif", color: "#5A6B84" }}>Two-factor authentication is currently disabled.</span>
          <button className="clk" onClick={startTwoFA} style={{ height: 38, padding: "0 16px", border: "none", borderRadius: 10, background: "#2E5FBF", color: "#fff", font: "700 12.5px Inter,sans-serif", cursor: "pointer" }}>Enable 2FA</button>
        </div>
      )}
    </div>
  );

  const renderProfileApi = () => (
    <div style={{ ...CARD, padding: "22px 24px" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
        <div><div style={{ font: "700 15px Inter,sans-serif", color: "#0F1B2D" }}>API keys</div><div style={{ fontSize: 12.5, color: "#8A97AB", marginTop: 2 }}>Scoped tokens for CI, bots and automation — no interactive login</div></div>
        <button className="clk" onClick={openApiKeyModal} style={{ display: "inline-flex", alignItems: "center", gap: 7, height: 40, padding: "0 16px", border: "none", borderRadius: 10, background: "#2E5FBF", color: "#fff", font: "700 13px Inter,sans-serif", cursor: "pointer" }}><Icon name="plus" size={14} color="#fff" sw={2.2} />Generate new key</button>
      </div>
      <div style={{ marginTop: 14, border: "1px solid #eef1f7", borderRadius: 12, overflow: "hidden" }}>
        {state.apiKeys.map((k) => (
          <div key={k.id} style={{ display: "flex", alignItems: "center", gap: 14, padding: "14px 16px", borderTop: "1px solid #f2f4f9" }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ font: "600 13.5px Inter,sans-serif", color: "#0F1B2D" }}>{k.name}</div>
              <div className="mono" style={{ fontSize: 12, color: "#8A97AB", marginTop: 4 }}>{k.key}</div>
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 5, maxWidth: 280, justifyContent: "flex-end" }}>
              {k.scopes.map((sc) => <span key={sc} className="mono" style={{ fontSize: 10, fontWeight: 700, color: "#2E5FBF", background: "#EAF0FC", borderRadius: 6, padding: "3px 8px" }}>{sc}</span>)}
            </div>
            <div className="mono" style={{ fontSize: 11.5, color: "#a0abbd", width: 80, textAlign: "right" }}>{k.created}</div>
            <div className="actbtn del" onClick={() => revokeApiKey(k.id)} style={{ flex: "none" }}><Icon name="trash" size={15} /></div>
          </div>
        ))}
        {state.apiKeys.length === 0 && <div style={{ padding: "22px 16px", textAlign: "center", color: "#9aa6b8", fontSize: 13 }}>No API keys yet.</div>}
      </div>
    </div>
  );

  // ---------- Modals ----------
  const modalShell = (open: boolean, onClose: () => void, zIndex: number, width: number, children: ReactNode, align: "center" | "flex-start" = "center", pad = "24px") => (
    <div className={`modalback ${open ? "open" : ""}`} onClick={onClose} style={{ position: "absolute", inset: 0, zIndex, background: "rgba(20,28,40,.42)", display: "flex", alignItems: align, justifyContent: "center", padding: pad, overflow: align === "flex-start" ? "auto" : undefined }}>
      <div className="modalcard" onClick={stop} style={{ width, maxWidth: "100%", background: "#fff", borderRadius: 20, boxShadow: "0 30px 80px rgba(15,27,45,.3)", padding: "28px 28px 24px" }}>
        {children}
      </div>
    </div>
  );

  const modalFooter = (onCancel: () => void, onSave: () => void, saveLabel: string, saveBg = "#4C74C7") => (
    <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, marginTop: 24 }}>
      <button className="clk" onClick={onCancel} style={{ height: 42, padding: "0 20px", border: "1px solid #dbe1ec", borderRadius: 11, background: "#fff", font: "700 13.5px Inter,sans-serif", color: "#5A6B84" }}>Cancel</button>
      <button className="clk" onClick={onSave} style={{ height: 42, padding: "0 22px", border: "none", borderRadius: 11, background: saveBg, color: "#fff", font: "700 13.5px Inter,sans-serif" }}>{saveLabel}</button>
    </div>
  );

  return (
    <div className="storm" style={{ height: "100vh", display: "flex", flexDirection: "column", overflow: "hidden", background: "#eef1f6", position: "relative" }}>
      {/* top app bar */}
      <header style={{ height: 58, flex: "none", display: "flex", alignItems: "center", gap: 14, padding: "0 22px", background: "#fff", borderBottom: "1px solid #e6eaf1", zIndex: 30 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <SberMark size={23} />
          <div style={{ fontWeight: 800, fontSize: 18, letterSpacing: "-.3px" }}><span style={{ color: "#1a2431" }}>Sber</span><span style={{ color: "#1F6FE5" }}>Tech</span></div>
          <div style={{ width: 1, height: 22, background: "#e2e6ee", margin: "0 4px" }} />
          <div className="mono" style={{ fontSize: 10.5, letterSpacing: 2, color: "#aeb7c6", fontWeight: 600 }}>OFFENSIVE RESEARCH &amp; MANAGEMENT</div>
        </div>
        <div style={{ flex: 1 }} />
        <div className="clk nav iconbtn" onClick={() => toggle("notifOpen")} style={{ width: 40, height: 40, borderRadius: 11, display: "flex", alignItems: "center", justifyContent: "center", position: "relative" }}>
          <Icon name="bell" size={19} color="#6b7a90" />
          {hasUnread && <span style={{ position: "absolute", top: 6, right: 7, width: 8, height: 8, borderRadius: "50%", background: "#EF5F73", border: "2px solid #fff" }} />}
        </div>
        <div className="clk" onClick={() => toggle("userMenuOpen")} style={{ display: "flex", alignItems: "center", gap: 9, padding: 4, borderRadius: 24 }}>
          <div style={{ width: 34, height: 34, flex: "none", borderRadius: "50%", background: "#2E5FBF", color: "#fff", display: "flex", alignItems: "center", justifyContent: "center", font: "700 12.5px 'JetBrains Mono',monospace" }}>{meInitials}</div>
          <Icon name="chevron-down" size={15} color="#9aa6b8" sw={2.2} style={{ transform: state.userMenuOpen ? "rotate(180deg)" : "none", transition: "transform .2s" }} />
        </div>
      </header>

      {/* user menu */}
      {state.userMenuOpen && <div onClick={() => setState({ userMenuOpen: false })} style={{ position: "absolute", inset: 0, zIndex: 40 }} />}
      <div className={`menu ${state.userMenuOpen ? "open" : ""}`} style={{ position: "absolute", top: 56, right: 16, width: 270, background: "#fff", border: "1px solid #e6eaf1", borderRadius: 16, boxShadow: "0 20px 54px rgba(15,27,45,.18)", zIndex: 50, overflow: "hidden" }}>
        <div style={{ padding: "22px 20px 16px", textAlign: "center", borderBottom: "1px solid #f0f2f7" }}>
          <div style={{ width: 60, height: 60, margin: "0 auto 12px", borderRadius: "50%", border: "1px solid #e6eaf1", display: "flex", alignItems: "center", justifyContent: "center", overflow: "hidden" }}><SberMark size={34} /></div>
          <div style={{ fontWeight: 700, fontSize: 16, color: "#0F1B2D" }}>{meDisplay}</div>
          <div className="mono" style={{ fontSize: 12, color: "#9aa6b8", marginTop: 3 }}>{meEmail}</div>
        </div>
        <div style={{ padding: 8 }}>
          <div className="nav clk" onClick={openProfile} style={{ display: "flex", alignItems: "center", gap: 12, padding: "11px 12px", borderRadius: 10, font: "600 13.5px Inter,sans-serif", color: "#334" }}><Icon name="user" size={18} color="#6b7a90" />Profile</div>
          <div style={{ height: 1, background: "#f0f2f7", margin: "6px 4px" }} />
          <div className="nav clk" onClick={() => { setState({ userMenuOpen: false }); void signOut(); }} style={{ display: "flex", alignItems: "center", gap: 12, padding: "11px 12px", borderRadius: 10, font: "600 13.5px Inter,sans-serif", color: "#D14B60" }}><Icon name="logout" size={18} color="currentColor" />Logout</div>
        </div>
      </div>

      <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
        {/* sidebar */}
        <aside className={`sb ${state.sidebarCollapsed ? "collapsed" : ""}`} style={{ width: sideW, flex: "none", background: "#fff", borderRight: "1px solid #e6eaf1", display: "flex", flexDirection: "column", overflow: "hidden" }}>
          <div className="sbhead" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "20px 14px 18px 18px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, overflow: "hidden" }}>
              <div className="lbl" style={{ fontWeight: 800, fontSize: 16, letterSpacing: 3, color: "#1a2431" }}>STORM</div>
            </div>
            <div className="clk nav iconbtn" onClick={() => toggle("sidebarCollapsed")} style={{ width: 26, height: 26, flex: "none", borderRadius: 7, display: "flex", alignItems: "center", justifyContent: "center", color: "#b3bccd" }}>
              <Icon name="chevrons-left" size={18} color="currentColor" sw={2.4} style={{ transform: state.sidebarCollapsed ? "rotate(180deg)" : "none", transition: "transform .26s ease" }} />
            </div>
          </div>
          <div className="lbl mono" style={{ padding: "0 20px 8px", fontSize: 10, letterSpacing: 1.5, color: "#b3bccd", fontWeight: 700 }}>WORKSPACE</div>
          <nav style={{ padding: "0 12px", display: "flex", flexDirection: "column", gap: 3 }}>
            {([
              { id: "projects" as const, icon: "folder" as const, label: "Projects", onClick: selProjects },
              { id: "tasks" as const, icon: "check-square" as const, label: "Tasks", onClick: () => setState({ nav: "tasks", view: "list" }) },
              { id: "mine" as const, icon: "user1" as const, label: "My Tasks", onClick: () => setState({ nav: "mine", view: "list" }) },
              { id: "docs" as const, icon: "doc" as const, label: "Docs", onClick: () => setState({ nav: "docs", view: "list" }) },
              ...(isAdmin ? [{ id: "members" as const, icon: "users" as const, label: "Members", onClick: selWSMembers }] : []),
            ]).map((it) => (
              <div key={it.id} className="nav clk" onClick={it.onClick} style={{ display: "flex", alignItems: "center", gap: 13, padding: "10px 12px", borderRadius: 11, font: "600 14px Inter,sans-serif", color: navColor(it.id), background: navBg(it.id) }}>
                <Icon name={it.icon} size={19} color="currentColor" style={{ flex: "none" }} />
                <span className="lbl">{it.label}</span>
              </div>
            ))}
          </nav>
        </aside>

        {/* main column */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0, overflow: "hidden" }}>
          <main style={{ flex: 1, overflow: "auto" }}>
            {isList && renderProjects()}
            {isStub && renderStub()}
            {/* /members is admin-only (GET /users is too) — say so rather than
                quietly showing the projects list instead. */}
            {state.view === "workspaceMembers" &&
              (isAdmin
                ? renderWorkspaceMembers()
                : renderNoAccessPage("Раздел «Members» доступен только администраторам — здесь заводят пользователей и назначают роли."))}
            {state.view === "detail" && (state.accessDenied ? renderNoAccessPage() : renderDetail())}
            {state.view === "profile" && renderProfile()}
          </main>
          <footer style={{ flex: "none", display: "flex", alignItems: "center", justifyContent: "center", gap: 8, padding: 16, background: "transparent", fontSize: 12.5, color: "#a0abbd", flexWrap: "wrap" }}>
            <span style={{ fontWeight: 700, color: "#7c8aa0" }}>STORM</span><span>·</span><span>Licensed to SberTech · Copyright © 2026. All rights reserved.</span>
          </footer>
        </div>
      </div>

      {/* ===== modals ===== */}
      {/* workspace user editor */}
      {modalShell(
        state.wsUserModalOpen,
        closeWSUserEditor,
        60,
        440,
        <>
          <h2 style={{ margin: 0, fontSize: 21, fontWeight: 800, color: "#0F1B2D", letterSpacing: "-.4px" }}>{state.wsUserMode === "add" ? "Add member" : "Edit member"}</h2>
          <div style={{ marginTop: 20 }}><label className="flabel">Username</label><input className="finp" placeholder="e.g. i.volkov" value={state.wsUserName} onChange={(e) => setState({ wsUserName: e.target.value })} /></div>
          <div style={{ marginTop: 16 }}><label className="flabel">Email</label><input className="finp" placeholder="user@sbertech.ru" value={state.wsUserEmail} onChange={(e) => setState({ wsUserEmail: e.target.value })} /></div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginTop: 16 }}>
            <div>
              <label className="flabel">Workspace role</label>
              <select className="esel" value={state.wsUserRole} onChange={(e) => setState({ wsUserRole: e.target.value as WsRole })}>
                <option value="user">User</option>
                <option value="admin">Admin</option>
              </select>
            </div>
            <div>
              <label className="flabel">Project role</label>
              <select className="esel" value={state.wsUserProjectRole} onChange={(e) => setState({ wsUserProjectRole: e.target.value as Role })}>
                <option value="lead">Lead</option>
                <option value="pentester">Pentester</option>
              </select>
            </div>
          </div>
          {modalFooter(closeWSUserEditor, saveWSUser, "Save", "#2E5FBF")}
        </>
      )}

      {/* generate API key */}
      {modalShell(
        state.apiKeyModalOpen,
        closeApiKeyModal,
        60,
        460,
        <>
          <h2 style={{ margin: 0, fontSize: 21, fontWeight: 800, color: "#0F1B2D", letterSpacing: "-.4px" }}>Generate API key</h2>
          <div style={{ fontSize: 13, color: "#8A97AB", marginTop: 6 }}>Choose a name and the permissions this key should have.</div>
          <div style={{ marginTop: 20 }}><label className="flabel">Key name</label><input className="finp" placeholder="e.g. CI pipeline" value={state.apiKeyName} onChange={(e) => setState({ apiKeyName: e.target.value })} /></div>
          <div style={{ marginTop: 16 }}>
            <label className="flabel">Permissions</label>
            <div style={{ display: "flex", flexDirection: "column", gap: 2, border: "1px solid #eef1f7", borderRadius: 11, overflow: "hidden", marginTop: 6 }}>
              {API_SCOPES.map((s) => {
                const checked = !!state.apiKeyScopes[s];
                return (
                  <div key={s} className="clk" onClick={() => toggleApiScope(s)} style={{ display: "flex", alignItems: "center", gap: 10, padding: "11px 14px", borderTop: "1px solid #f2f4f9", cursor: "pointer" }}>
                    <span style={{ width: 18, height: 18, flex: "none", borderRadius: 5, border: `1.5px solid ${checked ? "#2E5FBF" : "#dbe1ec"}`, background: checked ? "#2E5FBF" : "#fff", display: "flex", alignItems: "center", justifyContent: "center" }}>
                      {checked && <Icon name="check" size={12} color="#fff" sw={3} />}
                    </span>
                    <span className="mono" style={{ fontSize: 12.5, color: "#334" }}>{s}</span>
                  </div>
                );
              })}
            </div>
          </div>
          {modalFooter(closeApiKeyModal, createApiKey, "Generate key", "#2E5FBF")}
        </>
      )}

      {/* new project */}
      {modalShell(
        state.modalOpen,
        () => setState({ modalOpen: false, newName: "", newDesc: "", newStart: "", newEnd: "" }),
        60,
        480,
        <>
          <h2 style={{ margin: 0, fontSize: 22, fontWeight: 800, color: "#0F1B2D", letterSpacing: "-.4px" }}>New project</h2>
          <div style={{ fontSize: 13.5, color: "#8A97AB", marginTop: 6 }}>Create a project workspace for a new engagement.</div>
          <div style={{ marginTop: 22 }}><label className="flabel">Project name</label><input className="finp" placeholder="e.g. Acme Corp — External Perimeter" value={state.newName} onChange={(e) => setState({ newName: e.target.value })} /></div>
          <div style={{ marginTop: 16 }}><label className="flabel">Description</label><textarea className="finp" rows={3} placeholder="Short summary of the engagement scope…" value={state.newDesc} onChange={(e) => setState({ newDesc: e.target.value })} /></div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginTop: 16 }}>
            {/* min/max keep the pickers themselves from offering an inverted range. */}
            <div><label className="flabel">Start date</label><input className="finp" type="date" max={state.newEnd || undefined} value={state.newStart} onChange={(e) => setState({ newStart: e.target.value })} /></div>
            <div><label className="flabel">End date</label><input className="finp" type="date" min={state.newStart || undefined} value={state.newEnd} onChange={(e) => setState({ newEnd: e.target.value })} /></div>
          </div>
          {datesInvalid(state.newStart, state.newEnd) && (
            <div style={{ marginTop: 8, font: "600 12px Inter,sans-serif", color: "#C0455B" }}>{DATES_ERROR}</div>
          )}
          {modalFooter(() => setState({ modalOpen: false, newName: "", newDesc: "", newStart: "", newEnd: "" }), createProject, "Create project")}
        </>
      )}

      {/* edit project */}
      {modalShell(
        state.projEditOpen,
        closeProjEdit,
        60,
        480,
        <>
          <h2 style={{ margin: 0, fontSize: 22, fontWeight: 800, color: "#0F1B2D", letterSpacing: "-.4px" }}>Edit project</h2>
          <div style={{ marginTop: 20 }}><label className="flabel">Project name</label><input className="finp" value={state.projEditName} onChange={(e) => setState({ projEditName: e.target.value })} /></div>
          <div style={{ marginTop: 16 }}><label className="flabel">Description</label><textarea className="finp" rows={3} value={state.projEditDesc} onChange={(e) => setState({ projEditDesc: e.target.value })} /></div>
          <div style={{ marginTop: 16 }}>
            <label className="flabel">Status</label>
            <select className="finp" value={state.projEditStatus} onChange={(e) => setState({ projEditStatus: e.target.value as ProjectStatus })}>
              {PROJECT_STATUS_ORDER.map((s) => <option key={s} value={s}>{PROJ_STATUS[s]?.label ?? s}</option>)}
            </select>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginTop: 16 }}>
            <div><label className="flabel">Start date</label><input className="finp" type="date" max={state.projEditEnd || undefined} value={state.projEditStart} onChange={(e) => setState({ projEditStart: e.target.value })} /></div>
            <div><label className="flabel">End date</label><input className="finp" type="date" min={state.projEditStart || undefined} value={state.projEditEnd} onChange={(e) => setState({ projEditEnd: e.target.value })} /></div>
          </div>
          {datesInvalid(state.projEditStart, state.projEditEnd) && (
            <div style={{ marginTop: 8, font: "600 12px Inter,sans-serif", color: "#C0455B" }}>{DATES_ERROR}</div>
          )}
          {modalFooter(closeProjEdit, saveProjEdit, "Save")}
        </>
      )}

      {/* activity: the full list behind a card's "Show more" */}
      {(() => {
        const g = state.activityModalKey ? activityGroups.find((x) => x.key === state.activityModalKey) : undefined;
        const close = () => setState({ activityModalKey: null });
        return modalShell(
          !!g,
          close,
          60,
          620,
          <>
            <h2 style={{ margin: 0, fontSize: 20, fontWeight: 800, color: "#0F1B2D", letterSpacing: "-.4px" }}>
              {g ? `${g.actor} ${g.verb} ${g.subject}` : ""}
            </h2>
            {g && <div className="mono" style={{ marginTop: 6, fontSize: 11.5, color: "#a0abbd" }}>{g.time}</div>}
            <div style={{ marginTop: 16, background: "#111C2E", borderRadius: 10, padding: "12px 13px", display: "flex", flexDirection: "column", gap: 6, maxHeight: 420, overflow: "auto" }}>
              {g?.lines.map((l) => activityLineRow(l, g.tone))}
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 20 }}>
              <button className="clk" onClick={close} style={{ height: 40, padding: "0 20px", border: "1px solid #dbe1ec", borderRadius: 10, background: "#fff", font: "700 13px Inter,sans-serif", color: "#5A6B84", cursor: "pointer" }}>Закрыть</button>
            </div>
          </>
        );
      })()}

      {/* export: recon lists (hosts / IPs / endpoints), filtered exactly as on screen */}
      {modalShell(
        state.exportModalOpen && state.exportScope !== "report",
        closeExportModal,
        60,
        480,
        <>
          <h2 style={{ margin: 0, fontSize: 21, fontWeight: 800, color: "#0F1B2D", letterSpacing: "-.4px" }}>
            {state.exportScope === "hosts" ? "Экспорт хостов" : state.exportScope === "ips" ? "Экспорт IP-адресов" : "Экспорт эндпоинтов"}
          </h2>
          <div style={{ fontSize: 13, color: "#8A97AB", marginTop: 6, lineHeight: 1.6 }}>
            Выгружается то, что осталось после фильтров на странице — <b style={{ color: "#0F1B2D" }}>{exportCount}</b>{" "}
            {state.exportScope === "hosts" ? "хост(ов)" : state.exportScope === "ips" ? "адрес(ов)" : "эндпоинт(ов)"}. Чтобы выгрузить другое — измените фильтры и откройте экспорт снова.
          </div>
          {state.exportScope === "endpoints" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 10, marginTop: 18 }}>
              {([
                { k: "list" as const, title: "Список", desc: "Текстовый файл: по строке на эндпоинт — METHOD https://host/path." },
                { k: "openapi" as const, title: "Swagger (OpenAPI 3)", desc: "JSON-спецификация: путь на каждый эндпоинт, хост в servers." },
              ]).map((f) => {
                const on = state.exportFormat === f.k;
                return (
                  <div key={f.k} className="clk" onClick={() => setState({ exportFormat: f.k })} style={{ display: "flex", alignItems: "flex-start", gap: 12, padding: "14px 16px", borderRadius: 12, cursor: "pointer", border: `1.5px solid ${on ? "#4C74C7" : "#e6eaf1"}`, background: on ? "#f6f9ff" : "#fff" }}>
                    <span style={{ width: 18, height: 18, flex: "none", marginTop: 2, borderRadius: "50%", border: `1.5px solid ${on ? "#2E5FBF" : "#dbe1ec"}`, display: "flex", alignItems: "center", justifyContent: "center", background: on ? "#2E5FBF" : "#fff" }}>
                      {on && <span style={{ width: 7, height: 7, borderRadius: "50%", background: "#fff" }} />}
                    </span>
                    <div style={{ minWidth: 0 }}>
                      <div style={{ font: "700 13.5px Inter,sans-serif", color: "#0F1B2D" }}>{f.title}</div>
                      <div style={{ fontSize: 12.5, color: "#8A97AB", marginTop: 3, lineHeight: 1.5 }}>{f.desc}</div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
          <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, marginTop: 22 }}>
            <button className="clk" onClick={closeExportModal} style={{ height: 42, padding: "0 20px", border: "1px solid #dbe1ec", borderRadius: 11, background: "#fff", font: "700 13.5px Inter,sans-serif", color: "#5A6B84" }}>Отмена</button>
            <button className="clk" onClick={doReconExport} disabled={exportCount === 0} style={{ height: 42, padding: "0 22px", border: "none", borderRadius: 11, background: exportCount === 0 ? "#9db3de" : "#4C74C7", color: "#fff", font: "700 13.5px Inter,sans-serif", cursor: exportCount === 0 ? "default" : "pointer" }}>
              Скачать
            </button>
          </div>
        </>
      )}

      {/* export: Word report generation (backend templates szi / pp) */}
      {modalShell(
        state.exportModalOpen && state.exportScope === "report",
        closeExportModal,
        60,
        480,
        <>
          <h2 style={{ margin: 0, fontSize: 21, fontWeight: 800, color: "#0F1B2D", letterSpacing: "-.4px" }}>Экспорт отчёта</h2>
          <div style={{ display: "flex", flexDirection: "column", gap: 10, marginTop: 18 }}>
            {REPORT_KINDS.map((r) => {
              const on = state.exportKind === r.kind;
              return (
                <div
                  key={r.kind}
                  className="clk"
                  onClick={() => setState({ exportKind: r.kind })}
                  style={{ display: "flex", alignItems: "flex-start", gap: 12, padding: "14px 16px", borderRadius: 12, cursor: "pointer", border: `1.5px solid ${on ? "#4C74C7" : "#e6eaf1"}`, background: on ? "#f6f9ff" : "#fff" }}
                >
                  <span style={{ width: 18, height: 18, flex: "none", marginTop: 2, borderRadius: "50%", border: `1.5px solid ${on ? "#2E5FBF" : "#dbe1ec"}`, display: "flex", alignItems: "center", justifyContent: "center", background: on ? "#2E5FBF" : "#fff" }}>
                    {on && <span style={{ width: 7, height: 7, borderRadius: "50%", background: "#fff" }} />}
                  </span>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ font: "700 13.5px Inter,sans-serif", color: "#0F1B2D" }}>{r.title}</div>
                    <div style={{ fontSize: 12.5, color: "#8A97AB", marginTop: 3, lineHeight: 1.5 }}>{r.desc}</div>
                  </div>
                </div>
              );
            })}
          </div>
          <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, marginTop: 22 }}>
            <button className="clk" onClick={closeExportModal} style={{ height: 42, padding: "0 20px", border: "1px solid #dbe1ec", borderRadius: 11, background: "#fff", font: "700 13.5px Inter,sans-serif", color: "#5A6B84" }}>Отмена</button>
            <button className="clk" onClick={doExport} disabled={state.exportBusy} style={{ height: 42, padding: "0 22px", border: "none", borderRadius: 11, background: state.exportBusy ? "#9db3de" : "#4C74C7", color: "#fff", font: "700 13.5px Inter,sans-serif", cursor: state.exportBusy ? "default" : "pointer" }}>
              {state.exportBusy ? "Формируется…" : "Скачать .docx"}
            </button>
          </div>
        </>
      )}

      {/* entity editor */}
      {modalShell(
        state.editorOpen,
        closeEditor,
        60,
        480,
        <>
          <h2 style={{ margin: 0, fontSize: 21, fontWeight: 800, color: "#0F1B2D", letterSpacing: "-.4px", textTransform: "capitalize" }}>{(state.editorMode === "add" ? "Add " : "Edit ") + TYPELABEL[state.editorType]}</h2>
          <div style={{ display: "flex", flexDirection: "column", gap: 15, marginTop: 22 }}>
            {editorFields.map((f) => (
              <div key={f.key}>
                <label className="flabel">{f.label}</label>
                {f.isText && <input className="finp" placeholder={f.placeholder} value={f.value} onChange={f.onInput} />}
                {f.isTextarea && <textarea className="finp" rows={3} placeholder={f.placeholder} value={f.value} onChange={f.onInput} />}
                {f.isSelect && (
                  <select className="esel" value={f.value} onChange={f.onInput}>
                    {f.value === "" && <option value="" disabled>Select…</option>}
                    {f.options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                )}
                {/* Type-to-search over a long option list (hosts): a native datalist
                    filters as you type and still accepts free text. */}
                {f.isCombo && (
                  <>
                    <input className="finp" list={`dl-${f.key}`} placeholder={f.placeholder} value={f.value} onChange={f.onInput} autoComplete="off" />
                    <datalist id={`dl-${f.key}`}>
                      {f.options.map((o) => <option key={o.value} value={o.value}>{o.label !== o.value ? o.label : undefined}</option>)}
                    </datalist>
                  </>
                )}
                {f.isTags && (
                  <div>
                    {f.tags.length > 0 && (
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 8 }}>
                        {f.tags.map((t, ti) => (
                          <span key={ti} className="mono" style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 11.5, fontWeight: 600, color: "#5A6B84", background: "#f1f4f9", border: "1px solid #e9edf4", borderRadius: 7, padding: "4px 6px 4px 9px" }}>
                            {t.value}
                            <span className="clk" onClick={t.onRemove} style={{ display: "flex", color: "#a0abbd" }}><Icon name="close" size={12} sw={2.4} /></span>
                          </span>
                        ))}
                      </div>
                    )}
                    <input className="finp" placeholder={f.placeholder} value={f.tagDraft} onChange={f.onTagDraft} onKeyDown={f.onTagKeyDown} />
                  </div>
                )}
              </div>
            ))}
          </div>
          {modalFooter(closeEditor, saveEditor, state.editorMode === "add" ? "Create" : "Save changes")}
        </>
      )}

      {/* delete confirm */}
      {modalShell(
        state.confirmOpen,
        closeConfirm,
        65,
        420,
        <>
          <div style={{ display: "flex", alignItems: "center", gap: 13, marginBottom: 14 }}>
            <span style={{ width: 42, height: 42, flex: "none", borderRadius: "50%", background: "#fbeaee", color: "#C0455B", display: "flex", alignItems: "center", justifyContent: "center" }}><Icon name="trash" size={20} /></span>
            <h2 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: "#0F1B2D" }}>Confirm deletion</h2>
          </div>
          <div style={{ fontSize: 14, color: "#5A6B84", lineHeight: 1.55 }}>Are you sure you want to delete <b style={{ color: "#0F1B2D" }}>{state.confirmLabel}</b>? This action cannot be undone.</div>
          {modalFooter(closeConfirm, confirmDelete, "Delete", "#C0455B")}
        </>
      )}

      {/* endpoint detail */}
      <div className={`modalback ${state.epOpen ? "open" : ""}`} onClick={closeEndpoint} style={{ position: "absolute", inset: 0, zIndex: 66, background: "rgba(20,28,40,.42)", display: "flex", alignItems: "flex-start", justifyContent: "center", padding: "40px 24px", overflow: "auto" }}>
        <div className="modalcard" onClick={stop} style={{ width: 820, maxWidth: "100%", background: "#fff", borderRadius: 20, boxShadow: "0 30px 80px rgba(15,27,45,.3)", padding: "24px 26px 22px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 20 }}>
            <span className="mono" style={{ fontWeight: 700, borderRadius: 6, padding: "3px 10px", fontSize: 12, background: (METHOD[state.epData.method] ?? PORT.closed).bg, color: (METHOD[state.epData.method] ?? PORT.closed).color }}>{state.epData.method}</span>
            <span className="mono" style={{ font: "700 15px 'JetBrains Mono',monospace", color: "#0F1B2D" }}>{state.epData.path}</span>
            <span className="mono" style={{ fontSize: 12, color: "#8A97AB", background: "#f1f4f9", borderRadius: 6, padding: "3px 9px" }}>{state.epData.host}</span>
            <div style={{ flex: 1 }} />
            <div className="clk actbtn" onClick={closeEndpoint}><Icon name="close" size={18} /></div>
          </div>
          {/* Both boxes are editable. The request is stored on the endpoint; the
              response is a local scratchpad — the backend has nowhere to keep it,
              so the label says so rather than pretending it saves. */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 18 }}>
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                <div className="mono" style={{ fontSize: 10.5, letterSpacing: 1, color: "#a8b2c2", fontWeight: 700 }}>REQUEST</div>
                <div style={{ flex: 1 }} />
                <span className="clk" onClick={() => copyText(state.epRequest, "Запрос")} style={{ display: "inline-flex", alignItems: "center", gap: 5, font: "700 11.5px Inter,sans-serif", color: "#4C74C7", cursor: "pointer" }}>
                  <Icon name="copy" size={13} />Copy request
                </span>
              </div>
              <textarea className="finp mono" rows={9} style={{ fontSize: 12, lineHeight: 1.6, resize: "vertical" }} value={state.epRequest} onChange={(e) => setState({ epRequest: e.target.value })} placeholder={`${state.epData.method} ${state.epData.path} HTTP/1.1`} />
            </div>
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                <div className="mono" style={{ fontSize: 10.5, letterSpacing: 1, color: "#a8b2c2", fontWeight: 700 }}>RESPONSE</div>
                <span className="mono" style={{ fontSize: 9.5, color: "#c3ccdb" }}>не сохраняется</span>
                <div style={{ flex: 1 }} />
                <span className="clk" onClick={() => copyText(state.epResponse, "Ответ")} style={{ display: "inline-flex", alignItems: "center", gap: 5, font: "700 11.5px Inter,sans-serif", color: "#4C74C7", cursor: "pointer" }}>
                  <Icon name="copy" size={13} />Copy response
                </span>
              </div>
              <textarea className="finp mono" rows={9} style={{ fontSize: 12, lineHeight: 1.6, resize: "vertical" }} value={state.epResponse} onChange={(e) => setState({ epResponse: e.target.value })} placeholder="HTTP/1.1 200 OK" />
            </div>
          </div>
          <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 14 }}>
            <button className="clk" onClick={saveEndpointRequest} disabled={state.epSaving} style={{ display: "flex", alignItems: "center", gap: 8, height: 40, padding: "0 18px", border: "none", borderRadius: 10, background: state.epSaving ? "#9db3de" : "#4C74C7", color: "#fff", font: "700 13px Inter,sans-serif", cursor: state.epSaving ? "default" : "pointer" }}>
              <Icon name="save" size={15} color="#fff" />{state.epSaving ? "Сохраняется…" : "Save request"}
            </button>
          </div>
          <div style={{ height: 1, background: "#eef1f7", margin: "22px 0 18px" }} />
          <div className="mono" style={{ fontSize: 10.5, letterSpacing: 1, color: "#a8b2c2", fontWeight: 700, marginBottom: 10 }}>DISCUSSION</div>
          <div style={{ background: "#f6f8fc", border: "1px solid #eef1f7", borderRadius: 12, padding: 16, fontSize: 13, color: "#8A97AB", marginBottom: 12 }}>No comments yet — start the discussion.</div>
          <textarea className="finp" rows={3} placeholder="Share progress, blockers, or review notes…" />
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 12 }}>
            <span style={{ fontSize: 11.5, color: "#a0abbd" }}>Use comments to coordinate review, blockers, and follow-ups.</span>
            <button className="clk" onClick={closeEndpoint} style={{ height: 40, padding: "0 18px", border: "none", borderRadius: 10, background: "#4C74C7", color: "#fff", font: "700 13px Inter,sans-serif" }}>Post comment</button>
          </div>
        </div>
      </div>

      {/* notifications panel */}
      <div className={`notifback ${state.notifOpen ? "open" : ""}`} onClick={() => setState({ notifOpen: false })} style={{ position: "absolute", inset: 0, zIndex: 60, background: "rgba(20,28,40,.3)", display: "flex", justifyContent: "flex-end" }}>
        <div className="notifpanel" onClick={stop} style={{ width: 390, maxWidth: "90%", height: "100%", background: "#fff", boxShadow: "-20px 0 60px rgba(15,27,45,.2)", display: "flex", flexDirection: "column" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 11, padding: "22px 24px 18px", borderBottom: "1px solid #eef1f7" }}>
            <div style={{ fontWeight: 800, fontSize: 18, color: "#0F1B2D" }}>Notifications</div>
            <span className="mono" style={{ padding: "3px 9px", borderRadius: 8, background: "#E9F0FC", color: "#2E5FBF", fontSize: 11, fontWeight: 700 }}>{newCount} new</span>
            <div style={{ flex: 1 }} />
            <div className="clk" onClick={markAllNotifsRead} style={{ font: "600 13px Inter,sans-serif", color: "#3d6fd6" }}>Mark all read</div>
          </div>
          <div style={{ flex: 1, overflow: "auto", padding: 6 }}>
            {notifs.map((n) => (
              <div key={n.key} className="notifitem clk" onClick={n.onClick} style={{ display: "flex", gap: 13, padding: "14px 16px", borderRadius: 12, alignItems: "flex-start" }}>
                <div style={{ width: 36, height: 36, flex: "none", borderRadius: "50%", background: n.avBg, color: "#fff", display: "flex", alignItems: "center", justifyContent: "center", font: "700 12px 'JetBrains Mono',monospace" }}>{n.initials}</div>
                <div style={{ minWidth: 0, flex: 1 }}>
                  <div style={{ fontSize: 13.5, color: "#334", lineHeight: 1.45 }}>
                    <span className="mono" style={{ color: "#2E5FBF", fontWeight: 600 }}>{n.user}</span> {n.action}{" "}
                    <span style={{ fontWeight: 700, color: "#0F1B2D" }}>{n.where}</span>
                  </div>
                  <div className="mono" style={{ fontSize: 11, color: "#a0abbd", marginTop: 5 }}>{n.meta}</div>
                </div>
                {n.unread && <span style={{ width: 8, height: 8, flex: "none", borderRadius: "50%", background: "#3d6fd6", marginTop: 5 }} />}
              </div>
            ))}
            {notifs.length === 0 && <div style={{ padding: 48, textAlign: "center", color: "#9aa6b8", fontSize: 13.5 }}>No notifications.</div>}
          </div>
        </div>
      </div>

      {/* image lightbox — click a step screenshot to view it full-size */}
      {state.lightboxSrc && (
        <div onClick={() => setState({ lightboxSrc: null })} style={{ position: "fixed", inset: 0, zIndex: 90, background: "rgba(10,16,26,.82)", display: "flex", alignItems: "center", justifyContent: "center", padding: 40, cursor: "zoom-out", animation: "storm-fade .18s ease both" }}>
          <img src={state.lightboxSrc} alt="Step screenshot" onClick={stop} style={{ maxWidth: "100%", maxHeight: "100%", borderRadius: 12, boxShadow: "0 30px 80px rgba(0,0,0,.5)", display: "block", cursor: "default" }} />
          <div className="clk" onClick={() => setState({ lightboxSrc: null })} style={{ position: "fixed", top: 22, right: 24, width: 40, height: 40, borderRadius: "50%", background: "rgba(255,255,255,.12)", color: "#fff", display: "flex", alignItems: "center", justifyContent: "center", cursor: "pointer" }}>
            <Icon name="close" size={20} color="#fff" />
          </div>
        </div>
      )}
    </div>
  );
}
