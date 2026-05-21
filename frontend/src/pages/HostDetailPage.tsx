import DeleteIcon from "@mui/icons-material/Delete";
import DeleteOutlineIcon from "@mui/icons-material/DeleteOutline";
import EditIcon from "@mui/icons-material/Edit";
import AddIcon from "@mui/icons-material/Add";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import DownloadIcon from "@mui/icons-material/Download";
import MoreVertIcon from "@mui/icons-material/MoreVert";
import UploadFileIcon from "@mui/icons-material/UploadFile";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import {
  Alert,
  Avatar,
  Box,
  Button,
  Card,
  CardContent,
  Checkbox,
  Chip,
  Collapse,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  FormControl,
  Grid2 as Grid,
  IconButton,
  InputLabel,
  LinearProgress,
  List,
  ListItem,
  Menu,
  MenuItem,
  Paper,
  Select,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import { Fragment, useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import ReactMarkdown from "react-markdown";
import { useLocation, useNavigate, useParams } from "react-router-dom";
import { MarkdownEditor } from "../components/MarkdownEditor";
import { MarkdownImage } from "../components/MarkdownImage";
import { MarkdownOutlinedReadonlyField } from "../components/MarkdownOutlinedReadonlyField";
import { markdownUrlTransform, normalizeMarkdownForRender } from "../markdownUrlTransform";
import {
  createHost,
  createProjectNote,
  createVulnerabilityComment,
  createEndpoint,
  createPort,
  createService,
  createVulnerability,
  deleteVulnerabilityComment,
  deleteEndpoint,
  deleteHost,
  deletePort,
  deleteService,
  deleteVulnerability,
  getVulnerability,
  getApiErrorMessage,
  getServices,
  getHost,
  getHosts,
  getHostVulnerabilities,
  exportOpenApiFile,
  importOpenApiFile,
  listProjectNotes,
  listVulnerabilityComments,
  moveProjectNote,
  reorderProjectNotes,
  updateEndpoint,
  updateHost,
  updatePort,
  updateService,
  updateVulnerabilityComment,
  updateVulnerability,
  uploadVulnerabilityFile,
} from "../api";
import { calculateCvssScore, severityFromCvssScore } from "../cvss";
import { HostOsIcon } from "../components/HostOsIcon";
import { ProjectTreeNav, type DetailSection } from "../components/ProjectTreeNav";
import { VulnerabilityStagesEditor } from "../components/VulnerabilityStagesEditor";
import { useAuthStore } from "../store";
import type {
  Endpoint,
  EndpointQueryParam,
  EndpointRequestHeader,
  Host,
  HostDetails,
  HostIpAddress,
  HostTreeStats,
  OsType,
  Port,
  ProjectNote,
  Service,
  Vulnerability,
  VulnerabilityComment,
  VulnerabilityDetails,
} from "../types";
import { OS_TYPE_OPTIONS } from "../types";
import { useErrorToast, useToastMessage } from "../useErrorToast";

/** Swagger UI–style colors for HTTP methods */
const SWAGGER_METHOD_COLORS: Record<string, { main: string; contrast: string }> = {
  GET: { main: "#61affe", contrast: "#fff" },
  POST: { main: "#49cc90", contrast: "#fff" },
  PUT: { main: "#fca130", contrast: "#fff" },
  PATCH: { main: "#50e3c2", contrast: "#0d1b12" },
  DELETE: { main: "#f93e3e", contrast: "#fff" },
  HEAD: { main: "#9012fe", contrast: "#fff" },
  OPTIONS: { main: "#0d5aa7", contrast: "#fff" },
};
const CVSS_VERSION = "4.0" as const;
const UUID_PATH_SEGMENT_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ENDPOINT_TABLE_NAME_COLUMN_WIDTH = "32%";

type HostIpDraft = Pick<HostIpAddress, "ip_address" | "is_primary"> & {
  id: string;
  label: string;
};

function swaggerMethodColors(method: string | null | undefined): { main: string; contrast: string } {
  const key = (method || "GET").toUpperCase();
  return SWAGGER_METHOD_COLORS[key] ?? { main: "rgba(100,116,139,0.85)", contrast: "#fff" };
}

function formatRequestBodyPreview(body: string | null | undefined): string {
  if (!body?.trim()) {
    return "";
  }
  try {
    return JSON.stringify(JSON.parse(body), null, 2);
  } catch {
    return body;
  }
}

function normalizeEndpointQueryParams(params: EndpointQueryParam[]): EndpointQueryParam[] {
  return params
    .map((param) => ({
      name: param.name.trim(),
      value: (param.value || "").trim() || null,
      required: Boolean(param.required),
      description: (param.description || "").trim() || null,
    }))
    .filter((param) => param.name);
}

/** Parse `a=b&c=d` or line-based query string into structured params */
function queryStringToQueryParams(raw: string): EndpointQueryParam[] {
  const t = raw.trim();
  if (!t) {
    return [];
  }
  const parts = t
    .split(/[&\n\r]+/)
    .map((p) => p.trim())
    .filter(Boolean);
  const out: EndpointQueryParam[] = [];
  for (const part of parts) {
    const eq = part.indexOf("=");
    if (eq === -1) {
      out.push({ name: part, value: "", required: false, description: "" });
    } else {
      const name = part.slice(0, eq).trim();
      if (name) {
        out.push({
          name,
          value: part.slice(eq + 1).trim(),
          required: false,
          description: "",
        });
      }
    }
  }
  return out;
}

function queryParamsToQueryString(params: EndpointQueryParam[] | null | undefined): string {
  if (!params?.length) {
    return "";
  }
  return normalizeEndpointQueryParams(params)
    .map((p) => `${p.name}=${p.value ?? ""}`)
    .join("&");
}

const HTTP_HEADER_DROP = new Set([
  "referer",
  "referrer",
  "connection",
  "accept-encoding",
  "accept-language",
  "sec-fetch-dest",
  "sec-fetch-mode",
  "sec-fetch-site",
  "sec-fetch-user",
  "sec-ch-ua",
  "sec-ch-ua-mobile",
  "sec-ch-ua-platform",
  "user-agent",
  "host",
]);

function methodSupportsRequestBody(method: Exclude<Endpoint["method"], null>): boolean {
  return method === "POST" || method === "PUT" || method === "PATCH";
}

function methodShowsQueryString(method: Exclude<Endpoint["method"], null>): boolean {
  return method !== "POST";
}

function normalizeHostForCompare(value: string): string {
  return value.trim().toLowerCase().replace(/:\d+$/, "");
}

function hostTokensMismatch(sourceHost: string | null | undefined, assetHost: string | null | undefined): boolean {
  if (!sourceHost?.trim() || !assetHost?.trim()) {
    return false;
  }
  return normalizeHostForCompare(sourceHost) !== normalizeHostForCompare(assetHost);
}

function parsePathAndQueryFromToken(pathToken: string): { path: string; queryParams: EndpointQueryParam[] } {
  const t = pathToken.trim();
  const toParams = (searchParams: URLSearchParams): EndpointQueryParam[] => {
    const params: EndpointQueryParam[] = [];
    searchParams.forEach((value, name) => {
      params.push({
        name,
        value,
        required: false,
        description: "",
      });
    });
    return params;
  };
  if (t.startsWith("http://") || t.startsWith("https://")) {
    const u = new URL(t);
    return { path: normalizeUriPathForTree(u.pathname || "/"), queryParams: toParams(u.searchParams) };
  }
  const fake = `http://stub.local${t.startsWith("/") ? t : `/${t}`}`;
  const u = new URL(fake);
  return { path: normalizeUriPathForTree(u.pathname || "/"), queryParams: toParams(u.searchParams) };
}

function sanitizeEndpointHeaderPairs(pairs: { name: string; value: string }[]): EndpointRequestHeader[] {
  const out: EndpointRequestHeader[] = [];
  let hadCookie = false;
  for (const { name, value } of pairs) {
    const ln = name.trim().toLowerCase();
    if (HTTP_HEADER_DROP.has(ln)) {
      continue;
    }
    if (ln === "cookie") {
      hadCookie = true;
      continue;
    }
    if (ln === "authorization") {
      out.push({ name: "Authorization", value: "{YOUR_CREDENTIALS_HERE}" });
      continue;
    }
    if (ln === "content-type") {
      continue;
    }
    out.push({ name: name.trim(), value: value.trim() });
  }
  if (hadCookie) {
    out.push({ name: "Cookie", value: "{YOUR_TOKENS_HERE}" });
  }
  return out;
}

function parseHeaderTextToPairs(text: string): { name: string; value: string }[] {
  const out: { name: string; value: string }[] = [];
  for (const line of text.split("\n")) {
    const t = line.replace(/\r$/, "");
    const idx = t.indexOf(":");
    if (idx === -1 || !t.slice(0, idx).trim()) {
      continue;
    }
    out.push({ name: t.slice(0, idx).trim(), value: t.slice(idx + 1).trim() });
  }
  return out;
}

function parseHeaderTextToSanitizedList(text: string): EndpointRequestHeader[] {
  return sanitizeEndpointHeaderPairs(parseHeaderTextToPairs(text));
}

function headersArrayToText(headers: EndpointRequestHeader[] | null | undefined): string {
  if (!headers?.length) {
    return "";
  }
  return headers.map((h) => `${h.name}: ${h.value}`).join("\n");
}

function escapeForCurlDoubleQuotes(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\r?\n/g, "\\n");
}

function buildDraftCurlLine({
  method,
  path,
  queryString,
  requestBody,
  requestContentType,
  requestHeaders,
  hostTarget,
}: {
  method: Exclude<Endpoint["method"], null>;
  path: string;
  queryString: string;
  requestBody: string;
  requestContentType: string;
  requestHeaders: EndpointRequestHeader[];
  hostTarget: string;
}): string {
  const params = method === "POST" ? [] : normalizeEndpointQueryParams(queryStringToQueryParams(queryString));
  const qs = new URLSearchParams();
  for (const p of params) {
    qs.append(p.name, p.value || "");
  }
  const pathOnly = (path.trim() || "/").split("?")[0];
  const queryPart = qs.toString();
  const url = `http://${hostTarget}${pathOnly}${queryPart ? `?${queryPart}` : ""}`;
  const body = methodSupportsRequestBody(method) ? requestBody.trim() : "";
  const ct = requestContentType.trim() || "application/json";
  let curl = `curl -X ${method}`;
  for (const h of requestHeaders) {
    curl += ` -H "${escapeForCurlDoubleQuotes(h.name)}: ${escapeForCurlDoubleQuotes(h.value)}"`;
  }
  if (body) {
    curl += ` -H "Content-Type: ${escapeForCurlDoubleQuotes(ct)}" -d "${escapeForCurlDoubleQuotes(body)}"`;
  }
  curl += ` "${url}"`;
  return curl;
}

type ParsedRawHttpResult = {
  method: Exclude<Endpoint["method"], null>;
  path: string;
  queryParams: EndpointQueryParam[];
  requestBody: string;
  requestContentType: string;
  headerPairsRaw: { name: string; value: string }[];
  sanitizedHeaders: EndpointRequestHeader[];
  hostHeaderRaw: string | null;
};

function parseRawHttpRequest(rawRequest: string): ParsedRawHttpResult | null {
  const normalized = rawRequest.replace(/\r/g, "");
  const sep = normalized.indexOf("\n\n");
  const headerBlock = sep === -1 ? normalized : normalized.slice(0, sep);
  const body = sep === -1 ? "" : normalized.slice(sep + 2);
  const lines = headerBlock.split("\n").filter((line) => line.length > 0);
  if (!lines.length) {
    return null;
  }
  const requestLineMatch = lines[0].match(/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP\/\d(?:\.\d)?$/i);
  if (!requestLineMatch) {
    return null;
  }
  const method = requestLineMatch[1].toUpperCase() as Exclude<Endpoint["method"], null>;
  const { path, queryParams } = parsePathAndQueryFromToken(requestLineMatch[2]);
  const headerPairsRaw: { name: string; value: string }[] = [];
  let requestContentType = "application/json";
  let hostHeaderRaw: string | null = null;
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    const idx = line.indexOf(":");
    if (idx === -1) {
      continue;
    }
    const name = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    headerPairsRaw.push({ name, value });
    const ln = name.toLowerCase();
    if (ln === "content-type") {
      requestContentType = value || "application/json";
    }
    if (ln === "host") {
      hostHeaderRaw = value;
    }
  }
  let requestBody = body;
  if (!methodSupportsRequestBody(method)) {
    requestBody = "";
  }
  const sanitizedHeaders = sanitizeEndpointHeaderPairs(headerPairsRaw);
  return {
    method,
    path,
    queryParams,
    requestBody,
    requestContentType,
    headerPairsRaw,
    sanitizedHeaders,
    hostHeaderRaw,
  };
}

/** Дерево путей эндпоинтов (как в Swagger): сегменты — «папки», лист — операции. */
type EndpointPathTreeNode = {
  segment: string;
  pathKey: string;
  children: EndpointPathTreeNode[];
  endpointsAtNode: Endpoint[];
};

function normalizeUriPathForTree(p: string): string {
  const raw = (p || "/").trim().replace(/\/+/g, "/");
  if (!raw || raw === "/") {
    return "/";
  }
  const withSlash = raw.startsWith("/") ? raw : `/${raw}`;
  const trimmed = withSlash.length > 1 && withSlash.endsWith("/") ? withSlash.slice(0, -1) || "/" : withSlash;
  const normalizedSegments = trimmed
    .split("/")
    .filter(Boolean)
    .map((segment) => (UUID_PATH_SEGMENT_RE.test(segment) ? "{UUID}" : segment));
  return normalizedSegments.length ? `/${normalizedSegments.join("/")}` : "/";
}

function endpointPathToSegments(p: string): string[] {
  const n = normalizeUriPathForTree(p);
  if (n === "/") {
    return [];
  }
  return n.slice(1).split("/").filter(Boolean);
}

function mergeEndpointForDisplay(base: Endpoint, next: Endpoint): Endpoint {
  return {
    ...base,
    description: base.description || next.description,
    query_params: base.query_params?.length ? base.query_params : next.query_params,
    request_body: base.request_body || next.request_body,
    request_content_type: base.request_content_type || next.request_content_type,
    request_headers: base.request_headers?.length ? base.request_headers : next.request_headers,
    path: normalizeUriPathForTree(base.path || next.path),
  };
}

function dedupeEndpointsByNormalizedPath(endpoints: Endpoint[]): Endpoint[] {
  const deduped = new Map<string, Endpoint>();
  for (const endpoint of endpoints) {
    const normalizedPath = normalizeUriPathForTree(endpoint.path);
    const key = `${(endpoint.method || "GET").toUpperCase()} ${normalizedPath}`;
    const candidate = { ...endpoint, path: normalizedPath };
    const existing = deduped.get(key);
    deduped.set(key, existing ? mergeEndpointForDisplay(existing, candidate) : candidate);
  }
  return Array.from(deduped.values());
}

function buildEndpointPathTree(endpoints: Endpoint[]): EndpointPathTreeNode {
  const root: EndpointPathTreeNode = { segment: "", pathKey: "", children: [], endpointsAtNode: [] };
  for (const ep of endpoints) {
    const segs = endpointPathToSegments(ep.path);
    if (segs.length === 0) {
      root.endpointsAtNode.push(ep);
      continue;
    }
    let node = root;
    let accum = "";
    for (const seg of segs) {
      accum = `${accum}/${seg}`;
      let child = node.children.find((c) => c.segment === seg);
      if (!child) {
        child = { segment: seg, pathKey: accum, children: [], endpointsAtNode: [] };
        node.children.push(child);
      }
      node = child;
    }
    node.endpointsAtNode.push(ep);
  }
  const sortRecursive = (n: EndpointPathTreeNode) => {
    n.children.sort((a, b) => a.segment.localeCompare(b.segment, undefined, { sensitivity: "base" }));
    n.endpointsAtNode.sort((a, b) => {
      const cm = (a.method || "GET").localeCompare(b.method || "GET");
      if (cm !== 0) {
        return cm;
      }
      return a.path.localeCompare(b.path);
    });
    n.children.forEach(sortRecursive);
  };
  sortRecursive(root);
  return root;
}

function collectExpandableFolderKeys(node: EndpointPathTreeNode): string[] {
  const keys: string[] = [];
  if (node.pathKey && node.children.length > 0) {
    keys.push(node.pathKey);
  }
  for (const c of node.children) {
    keys.push(...collectExpandableFolderKeys(c));
  }
  return keys;
}

function postEndpointDeleteModeDebugLog(_location: string, _message: string, _data: Record<string, unknown>, _hypothesisId: string): void {}

function postHostDetailReloadDebugLog(_location: string, _message: string, _data: Record<string, unknown>, _hypothesisId: string): void {}

export function HostDetailPage() {
  const { projectId, hostId, vulnerabilityId } = useParams<{ projectId: string; hostId: string; vulnerabilityId?: string }>();
  const location = useLocation();
  const navigate = useNavigate();
  const user = useAuthStore((s) => s.user);
  const storagePrefix = projectId && hostId ? `host-detail:${projectId}:${hostId}` : null;
  const highlightedCommentId = new URLSearchParams(location.search).get("comment");
  const isVulnerabilityRoute = Boolean(vulnerabilityId);

  const [host, setHost] = useState<HostDetails | null>(null);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [projectNotes, setProjectNotes] = useState<ProjectNote[]>([]);
  // Платформенный диалог ввода названия новой страницы/подстраницы (вместо window.prompt).
  const [noteCreateDialogOpen, setNoteCreateDialogOpen] = useState(false);
  const [noteCreateParentId, setNoteCreateParentId] = useState<string | null>(null);
  const [noteCreateTitle, setNoteCreateTitle] = useState("");
  const [noteCreateBusy, setNoteCreateBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [infoMessage, setInfoMessage] = useState<string | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [selectedSection, setSelectedSection] = useState<DetailSection>(isVulnerabilityRoute ? "vulns" : "overview");
  const [isSidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [hostStatsById, setHostStatsById] = useState<Record<string, HostTreeStats>>({});
  const [isEditPortOpen, setEditPortOpen] = useState(false);
  const [editingPortId, setEditingPortId] = useState<string | null>(null);
  const [editingPortNumber, setEditingPortNumber] = useState("1");
  const [editingPortProtocol, setEditingPortProtocol] = useState<Port["protocol"]>("tcp");
  const [editingPortState, setEditingPortState] = useState<Port["state"]>("open");
  const [editingPortServiceId, setEditingPortServiceId] = useState<string | null>(null);
  const [editingPortServiceName, setEditingPortServiceName] = useState("");
  const [editingPortServiceVersion, setEditingPortServiceVersion] = useState("");
  const [servicesByPortId, setServicesByPortId] = useState<Record<string, Service[]>>({});
  const [isCreateServiceOpen, setCreateServiceOpen] = useState(false);
  const [createServicePortId, setCreateServicePortId] = useState<string | null>(null);
  const [creatingServiceName, setCreatingServiceName] = useState("");
  const [creatingServiceVersion, setCreatingServiceVersion] = useState("");
  const [isEditServiceOpen, setEditServiceOpen] = useState(false);
  const [editServicePortId, setEditServicePortId] = useState<string | null>(null);
  const [editingServiceId, setEditingServiceId] = useState<string | null>(null);
  const [editingServiceName, setEditingServiceName] = useState("");
  const [editingServiceVersion, setEditingServiceVersion] = useState("");
  const [isEditEndpointOpen, setEditEndpointOpen] = useState(false);
  const [editingEndpointId, setEditingEndpointId] = useState<string | null>(null);
  const [editingEndpointPath, setEditingEndpointPath] = useState("");
  const [editingEndpointMethod, setEditingEndpointMethod] = useState<Exclude<Endpoint["method"], null>>("GET");
  const [editingEndpointImportRaw, setEditingEndpointImportRaw] = useState("");
  const [editingEndpointQueryString, setEditingEndpointQueryString] = useState("");
  const [editingEndpointHeadersText, setEditingEndpointHeadersText] = useState("");
  const [editingEndpointImportHostWarn, setEditingEndpointImportHostWarn] = useState(false);
  const [editingEndpointRequestBody, setEditingEndpointRequestBody] = useState("");
  const [editingEndpointRequestContentType, setEditingEndpointRequestContentType] = useState("application/json");
  const [isEditVulnerabilityOpen, setEditVulnerabilityOpen] = useState(false);
  const [editingVulnerabilityId, setEditingVulnerabilityId] = useState<string | null>(null);
  const [editingVulnerabilityTitle, setEditingVulnerabilityTitle] = useState("");
  const [editingVulnerabilityDescription, setEditingVulnerabilityDescription] = useState("");
  const [editingVulnerabilitySeverity, setEditingVulnerabilitySeverity] = useState<Vulnerability["severity"]>("medium");
  const [editingVulnerabilityStatus, setEditingVulnerabilityStatus] = useState<Vulnerability["status"]>("open");
  const [isCreatePortOpen, setCreatePortOpen] = useState(false);
  const [creatingPortIpId, setCreatingPortIpId] = useState<string>("");
  const [creatingPortNumber, setCreatingPortNumber] = useState("443");
  const [creatingPortProtocol, setCreatingPortProtocol] = useState<Port["protocol"]>("tcp");
  const [creatingPortState, setCreatingPortState] = useState<Port["state"]>("open");
  const [creatingPortServiceName, setCreatingPortServiceName] = useState("");
  const [creatingPortServiceVersion, setCreatingPortServiceVersion] = useState("");
  const [isCreateEndpointOpen, setCreateEndpointOpen] = useState(false);
  const [creatingEndpointPath, setCreatingEndpointPath] = useState("");
  const [creatingEndpointMethod, setCreatingEndpointMethod] = useState<Exclude<Endpoint["method"], null>>("GET");
  const [creatingEndpointImportRaw, setCreatingEndpointImportRaw] = useState("");
  const [creatingEndpointQueryString, setCreatingEndpointQueryString] = useState("");
  const [creatingEndpointHeadersText, setCreatingEndpointHeadersText] = useState("");
  const [creatingEndpointImportHostWarn, setCreatingEndpointImportHostWarn] = useState(false);
  const [creatingEndpointRequestBody, setCreatingEndpointRequestBody] = useState("");
  const [creatingEndpointRequestContentType, setCreatingEndpointRequestContentType] = useState("application/json");
  const [swaggerImporting, setSwaggerImporting] = useState(false);
  const [swaggerExporting, setSwaggerExporting] = useState(false);
  const [endpointsMenuAnchorEl, setEndpointsMenuAnchorEl] = useState<HTMLElement | null>(null);
  const endpointsMenuOpen = Boolean(endpointsMenuAnchorEl);
  const swaggerImportInputRef = useRef<HTMLInputElement | null>(null);
  const closeEndpointsMenu = () => setEndpointsMenuAnchorEl(null);
  const [nmapImporting, setNmapImporting] = useState(false);
  const [isNmapImportOpen, setNmapImportOpen] = useState(false);
  const [nmapImportIpId, setNmapImportIpId] = useState<string>("");
  const [isCreateVulnerabilityOpen, setCreateVulnerabilityOpen] = useState(false);
  const [creatingVulnerabilityTitle, setCreatingVulnerabilityTitle] = useState("");
  const [creatingVulnerabilitySeverity, setCreatingVulnerabilitySeverity] = useState<Vulnerability["severity"]>("info");
  const [creatingVulnerabilityStatus, setCreatingVulnerabilityStatus] = useState<Vulnerability["status"]>("open");
  const [creatingVulnerabilityCvssScore, setCreatingVulnerabilityCvssScore] = useState("");
  const [creatingVulnerabilityCvssVector, setCreatingVulnerabilityCvssVector] = useState("");
  const [creatingVulnerabilityCweId, setCreatingVulnerabilityCweId] = useState("");
  const [creatingVulnerabilityStages, setCreatingVulnerabilityStages] = useState<VulnerabilityDetails["workflow_steps"]>([]);
  const [creatingVulnerabilityImpact, setCreatingVulnerabilityImpact] = useState("");
  const [creatingVulnerabilityRecommendations, setCreatingVulnerabilityRecommendations] = useState("");
  const [hostActionsAnchorEl, setHostActionsAnchorEl] = useState<HTMLElement | null>(null);
  const [isEditHostOpen, setEditHostOpen] = useState(false);
  const [editingHostIps, setEditingHostIps] = useState<HostIpDraft[]>([]);
  const [editingHostName, setEditingHostName] = useState("");
  const [editingHostNotes, setEditingHostNotes] = useState("");
  const [hostNotesEditOpen, setHostNotesEditOpen] = useState(false);
  const [hostNotesSaving, setHostNotesSaving] = useState(false);
  const [editingHostOsType, setEditingHostOsType] = useState<OsType>("unknown");
  const [ipActionsAnchorEl, setIpActionsAnchorEl] = useState<HTMLElement | null>(null);
  const [addIpDraft, setAddIpDraft] = useState<string | null>(null);
  const [editIpDraftId, setEditIpDraftId] = useState<string | null>(null);
  const [editIpDraft, setEditIpDraft] = useState<{ ip: string; label: string }>({ ip: "", label: "" });
  const ipCsvInputRef = useRef<HTMLInputElement | null>(null);
  const [ipBulkDeleteMode, setIpBulkDeleteMode] = useState(false);
  const [selectedIpIds, setSelectedIpIds] = useState<Set<string>>(() => new Set());
  const [bulkDeletingIps, setBulkDeletingIps] = useState(false);
  const [portActionsAnchorEl, setPortActionsAnchorEl] = useState<HTMLElement | null>(null);
  const [activePort, setActivePort] = useState<Port | null>(null);
  const [portsSectionMenuAnchorEl, setPortsSectionMenuAnchorEl] = useState<HTMLElement | null>(null);
  const portsSectionMenuOpen = Boolean(portsSectionMenuAnchorEl);
  const closePortsSectionMenu = () => setPortsSectionMenuAnchorEl(null);
  const nmapImportFileInputRef = useRef<HTMLInputElement | null>(null);
  const [selectedPortIds, setSelectedPortIds] = useState<Set<string>>(() => new Set());
  const [bulkDeletingPorts, setBulkDeletingPorts] = useState(false);
  const [portBulkDeleteMode, setPortBulkDeleteMode] = useState(false);
  const [serviceBulkDeletePortId, setServiceBulkDeletePortId] = useState<string | null>(null);
  const [selectedServiceIdsForDelete, setSelectedServiceIdsForDelete] = useState<Set<string>>(() => new Set());
  const [bulkDeletingServices, setBulkDeletingServices] = useState(false);
  const [endpointActionsAnchorEl, setEndpointActionsAnchorEl] = useState<HTMLElement | null>(null);
  const [activeEndpoint, setActiveEndpoint] = useState<Endpoint | null>(null);
  const [selectedEndpointIds, setSelectedEndpointIds] = useState<Set<string>>(() => new Set());
  const [bulkDeletingEndpoints, setBulkDeletingEndpoints] = useState(false);
  const [endpointBulkDeleteMode, setEndpointBulkDeleteMode] = useState(false);
  const [vulnerabilitiesSectionMenuAnchorEl, setVulnerabilitiesSectionMenuAnchorEl] = useState<HTMLElement | null>(null);
  const vulnerabilitiesSectionMenuOpen = Boolean(vulnerabilitiesSectionMenuAnchorEl);
  const closeVulnerabilitiesSectionMenu = () => setVulnerabilitiesSectionMenuAnchorEl(null);
  const [selectedVulnerabilityIds, setSelectedVulnerabilityIds] = useState<Set<string>>(() => new Set());
  const [bulkDeletingVulnerabilities, setBulkDeletingVulnerabilities] = useState(false);
  const [vulnerabilityBulkDeleteMode, setVulnerabilityBulkDeleteMode] = useState(false);
  const [expandedPortIds, setExpandedPortIds] = useState<string[]>([]);
  const [expandedIpIds, setExpandedIpIds] = useState<string[]>([]);
  const [expandedEndpointIds, setExpandedEndpointIds] = useState<string[]>([]);
  const [expandedVulnerabilityIds, setExpandedVulnerabilityIds] = useState<string[]>([]);
  const normalizedHostEndpoints = useMemo(() => dedupeEndpointsByNormalizedPath(host?.endpoints ?? []), [host?.endpoints]);
  const endpointPathTree = useMemo(() => buildEndpointPathTree(normalizedHostEndpoints), [normalizedHostEndpoints]);

  useEffect(() => {
    setSelectedEndpointIds((prev) => {
      if (prev.size === 0) {
        return prev;
      }
      const valid = new Set(normalizedHostEndpoints.map((ep) => ep.id));
      const next = new Set<string>();
      prev.forEach((id) => {
        if (valid.has(id)) {
          next.add(id);
        }
      });
      return next.size === prev.size ? prev : next;
    });
  }, [normalizedHostEndpoints]);

  useEffect(() => {
    setSelectedVulnerabilityIds((prev) => {
      const valid = new Set(vulnerabilities.map((v) => v.id));
      const next = new Set<string>();
      prev.forEach((id) => {
        if (valid.has(id)) {
          next.add(id);
        }
      });
      return next.size === prev.size ? prev : next;
    });
  }, [vulnerabilities]);

  useEffect(() => {
    if (selectedSection !== "endpoints") {
      setEndpointBulkDeleteMode(false);
      setSelectedEndpointIds(new Set());
    }
    if (selectedSection !== "ports") {
      setPortBulkDeleteMode(false);
      setSelectedPortIds(new Set());
      setServiceBulkDeletePortId(null);
      setSelectedServiceIdsForDelete(new Set());
    }
    if (selectedSection !== "vulns") {
      setVulnerabilityBulkDeleteMode(false);
      setSelectedVulnerabilityIds(new Set());
    }
  }, [selectedSection]);

  useEffect(() => {
    setEndpointBulkDeleteMode(false);
    setSelectedEndpointIds(new Set());
    setPortBulkDeleteMode(false);
    setSelectedPortIds(new Set());
    setServiceBulkDeletePortId(null);
    setSelectedServiceIdsForDelete(new Set());
    setVulnerabilityBulkDeleteMode(false);
    setSelectedVulnerabilityIds(new Set());
  }, [hostId]);

  useEffect(() => {
    // #region agent log
    postHostDetailReloadDebugLog(
      "frontend/src/pages/HostDetailPage.tsx:mount",
      "Host detail mounted",
      { hostId, projectId, path: location.pathname, section: selectedSection },
      "R1"
    );
    // #endregion
    return () => {
      // #region agent log
      postHostDetailReloadDebugLog(
        "frontend/src/pages/HostDetailPage.tsx:unmount",
        "Host detail unmounted",
        { hostId, projectId, path: location.pathname, section: selectedSection },
        "R1"
      );
      // #endregion
    };
  }, [hostId, location.pathname, projectId, selectedSection]);
  useEffect(() => {
    if (selectedSection !== "endpoints") {
      return;
    }
    const timer = window.setTimeout(() => {
      const visibleDeleteCheckboxes = document.querySelectorAll('[data-endpoint-delete-checkbox="true"]').length;
      const visibleBulkDeleteButtons = document.querySelectorAll('[data-endpoint-bulk-delete="true"]').length;
      // #region agent log
      postEndpointDeleteModeDebugLog(
        "frontend/src/pages/HostDetailPage.tsx:endpoints_view",
        "Endpoints section rendered",
        {
          endpointCount: normalizedHostEndpoints.length,
          selectedCount: selectedEndpointIds.size,
          visibleDeleteCheckboxes,
          visibleBulkDeleteButtons,
        },
        "H1"
      );
      // #endregion
    }, 0);
    return () => window.clearTimeout(timer);
  }, [endpointBulkDeleteMode, normalizedHostEndpoints.length, selectedEndpointIds.size, selectedSection]);
  useEffect(() => {
    if (!endpointsMenuOpen) {
      return;
    }
    const timer = window.setTimeout(() => {
      const deleteModeMenuItems = document.querySelectorAll('[data-endpoint-delete-mode-item="true"]').length;
      // #region agent log
      postEndpointDeleteModeDebugLog(
        "frontend/src/pages/HostDetailPage.tsx:endpoints_menu",
        "Endpoints actions menu opened",
        {
          selectedCount: selectedEndpointIds.size,
          deleteModeMenuItems,
        },
        "H3"
      );
      // #endregion
    }, 0);
    return () => window.clearTimeout(timer);
  }, [endpointsMenuOpen, selectedEndpointIds.size]);
  const [endpointTreeExpandedKeys, setEndpointTreeExpandedKeys] = useState<Set<string>>(() => new Set());
  const [vulnDetailOpen, setVulnDetailOpen] = useState(false);
  const [activeVulnDetails, setActiveVulnDetails] = useState<VulnerabilityDetails | null>(null);
  const [vulnComments, setVulnComments] = useState<VulnerabilityComment[]>([]);
  const [newComment, setNewComment] = useState("");
  const [vulnBusy, setVulnBusy] = useState(false);
  const [vulnEditMode, setVulnEditMode] = useState(false);
  const [editCommentOpen, setEditCommentOpen] = useState(false);
  const [editingCommentId, setEditingCommentId] = useState<string | null>(null);
  const [editingCommentContent, setEditingCommentContent] = useState("");
  const [commentActionsAnchorEl, setCommentActionsAnchorEl] = useState<HTMLElement | null>(null);
  const [activeComment, setActiveComment] = useState<VulnerabilityComment | null>(null);
  const pendingSection = (location.state as { section?: DetailSection } | null)?.section;

  useErrorToast(error);
  useToastMessage(infoMessage, "success");

  const openHostSection = useCallback(
    (section: DetailSection) => {
      if (!projectId || !hostId) {
        return;
      }
      // Секции «hosts» и «notes» относятся к проекту, а не к конкретному хосту,
      // поэтому при клике на эти разделы в дереве уводим юзера обратно в проект,
      // чтобы он увидел сводные данные (диаграммы по уязвимостям, журнал заметок).
      if (section === "hosts") {
        navigate(`/projects/${projectId}/hosts`);
        return;
      }
      if (section === "notes") {
        navigate(`/projects/${projectId}/notes`);
        return;
      }
      if (isVulnerabilityRoute) {
        navigate(`/projects/${projectId}/hosts/${hostId}`, { state: { section } });
        return;
      }
      setSelectedSection(section);
    },
    [hostId, isVulnerabilityRoute, navigate, projectId]
  );

  const openVulnerabilityPage = useCallback(
    (targetVulnerabilityId: string, commentId?: string | null) => {
      if (!projectId || !hostId) {
        return;
      }
      const query = commentId ? `?comment=${commentId}` : "";
      navigate(`/projects/${projectId}/hosts/${hostId}/vulnerabilities/${targetVulnerabilityId}${query}`, {
        state: { section: "vulns" satisfies DetailSection },
      });
    },
    [hostId, navigate, projectId]
  );

  const loadHost = useCallback(async (options?: { silent?: boolean }) => {
    if (!projectId || !hostId) {
      return;
    }
    const silent = Boolean(options?.silent);
    // #region agent log
    postHostDetailReloadDebugLog(
      "frontend/src/pages/HostDetailPage.tsx:loadHost:start",
      "loadHost started",
      { hostId, projectId, path: location.pathname, section: selectedSection, silent },
      "R2"
    );
    // #endregion
    if (!silent) {
      setLoading(true);
    }
    setError(null);
    try {
      const [hostResponse, hostsResponse, hostVulnsResponse, notesResponse] = await Promise.all([
        getHost(projectId, hostId),
        getHosts(projectId),
        getHostVulnerabilities(projectId, hostId),
        listProjectNotes(projectId).catch(() => [] as ProjectNote[]),
      ]);
      setHost(hostResponse);
      setHosts(hostsResponse.items);
      setVulnerabilities(hostVulnsResponse.items);
      setProjectNotes(notesResponse);
      const statsEntries = await Promise.allSettled(
        hostsResponse.items.map(async (listedHost) => {
          if (listedHost.id === hostId) {
            return [
              listedHost.id,
              {
                portsCount: hostResponse.ip_addresses.reduce((acc, ip) => acc + ip.ports.length, 0),
                ipAddressesCount: hostResponse.ip_addresses.length,
                endpointsCount: hostResponse.endpoints.length,
                vulnerabilitiesCount: hostVulnsResponse.items.length,
              },
            ] as const;
          }
          const [hostDetails, hostVulns] = await Promise.all([
            getHost(projectId, listedHost.id),
            getHostVulnerabilities(projectId, listedHost.id),
          ]);
          return [
            listedHost.id,
            {
              portsCount: hostDetails.ip_addresses.reduce((acc, ip) => acc + ip.ports.length, 0),
              ipAddressesCount: hostDetails.ip_addresses.length,
              endpointsCount: hostDetails.endpoints.length,
              vulnerabilitiesCount: hostVulns.items.length,
            },
          ] as const;
        })
      );
      const mappedStats: Record<string, HostTreeStats> = {};
      statsEntries.forEach((result) => {
        if (result.status === "fulfilled") {
          const [key, value] = result.value;
          mappedStats[key] = value;
        }
      });
      setHostStatsById(mappedStats);
      // #region agent log
      postHostDetailReloadDebugLog(
        "frontend/src/pages/HostDetailPage.tsx:loadHost:success",
        "loadHost finished",
        {
          hostId,
          projectId,
          path: location.pathname,
          section: selectedSection,
          endpointCount: hostResponse.endpoints.length,
          hostCount: hostsResponse.items.length,
        },
        "R2"
      );
      // #endregion
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось загрузить страницу хоста."));
    } finally {
      if (!silent) {
        setLoading(false);
      }
    }
    // Host payload does not depend on sidebar section or vulnerability deep-link path; including those
    // values forced a full reload + loading screen on every section switch.
  }, [hostId, projectId]);

  const applyRemovedEndpointsLocally = useCallback(
    (removedIds: Set<string>) => {
      if (!hostId || removedIds.size === 0) {
        return;
      }
      setExpandedEndpointIds((prev) => prev.filter((id) => !removedIds.has(id)));
      setHost((prev) => {
        if (!prev) {
          return prev;
        }
        const nextEndpoints = prev.endpoints.filter((ep) => !removedIds.has(ep.id));
        setHostStatsById((stats) => {
          const entry = stats[hostId];
          if (!entry) {
            return stats;
          }
          return {
            ...stats,
            [hostId]: { ...entry, endpointsCount: nextEndpoints.length },
          };
        });
        return { ...prev, endpoints: nextEndpoints };
      });
    },
    [hostId]
  );

  useEffect(() => {
    void loadHost();
  }, [loadHost]);

  useEffect(() => {
    if (!projectId) {
      return;
    }
    const protocol = window.location.protocol === "https:" ? "wss" : "ws";
    const socket = new WebSocket(`${protocol}://${window.location.host}/ws/projects/${projectId}`);
    socket.onmessage = () => {
      void loadHost({ silent: true });
    };
    return () => {
      socket.close();
    };
  }, [loadHost, projectId]);

  useEffect(() => {
    if (!storagePrefix) {
      return;
    }
    if (isVulnerabilityRoute) {
      setSelectedSection("vulns");
      return;
    }
    if (pendingSection) {
      setSelectedSection(pendingSection);
      return;
    }
    const storedSection = window.localStorage.getItem(`${storagePrefix}:selectedSection`) as DetailSection | null;
    const storedCollapsed = window.localStorage.getItem(`${storagePrefix}:sidebarCollapsed`);
    if (storedSection) {
      setSelectedSection(storedSection);
    }
    if (storedCollapsed) {
      setSidebarCollapsed(storedCollapsed === "1");
    }
  }, [isVulnerabilityRoute, pendingSection, storagePrefix]);

  useEffect(() => {
    if (!storagePrefix) {
      return;
    }
    window.localStorage.setItem(`${storagePrefix}:selectedSection`, selectedSection);
  }, [selectedSection, storagePrefix]);

  useEffect(() => {
    if (!storagePrefix) {
      return;
    }
    window.localStorage.setItem(`${storagePrefix}:sidebarCollapsed`, isSidebarCollapsed ? "1" : "0");
  }, [isSidebarCollapsed, storagePrefix]);

  useEffect(() => {
    const loadServices = async () => {
      const ports = host?.ip_addresses.flatMap((ip) => ip.ports) ?? [];
      if (!projectId || !hostId || !ports.length) {
        setServicesByPortId({});
        return;
      }
      const entries = await Promise.allSettled(
        ports.map(async (port) => {
          const services = await getServices(projectId, hostId, port.id);
          return [port.id, services] as const;
        })
      );
      const mapped: Record<string, Service[]> = {};
      entries.forEach((result) => {
        if (result.status === "fulfilled") {
          const [portId, services] = result.value;
          mapped[portId] = services;
        }
      });
      setServicesByPortId(mapped);
    };
    void loadServices();
  }, [host?.ip_addresses, hostId, projectId]);

  const hostActionsOpen = Boolean(hostActionsAnchorEl);
  const portActionsOpen = Boolean(portActionsAnchorEl);
  const endpointActionsOpen = Boolean(endpointActionsAnchorEl);

  const openHostActionsMenu = (event: React.MouseEvent<HTMLElement>) => {
    setHostActionsAnchorEl(event.currentTarget);
  };

  const closeHostActionsMenu = () => {
    setHostActionsAnchorEl(null);
  };

  const openPortActions = (event: React.MouseEvent<HTMLElement>, port: Port) => {
    event.stopPropagation();
    setPortActionsAnchorEl(event.currentTarget);
    setActivePort(port);
  };

  const closePortActions = () => {
    setPortActionsAnchorEl(null);
    setActivePort(null);
  };

  const buildHostIpDrafts = (source: HostDetails): HostIpDraft[] => {
    const items =
      source.ip_addresses?.length > 0
        ? source.ip_addresses
        : source.ip_address
          ? [{ id: "primary", ip_address: source.ip_address, label: null, is_primary: true }]
          : [];
    return items.map((item) => ({
      id: item.id || crypto.randomUUID(),
      ip_address: item.ip_address,
      label: item.label ?? "",
      is_primary: item.is_primary,
    }));
  };

  const updateHostIpDraft = (draftId: string, patch: Partial<HostIpDraft>) => {
    setEditingHostIps((prev) => prev.map((item) => (item.id === draftId ? { ...item, ...patch } : item)));
  };

  const addHostIpDraft = () => {
    setEditingHostIps((prev) => [...prev, { id: crypto.randomUUID(), ip_address: "", label: "", is_primary: prev.length === 0 }]);
  };

  const removeHostIpDraft = (draftId: string) => {
    setEditingHostIps((prev) => {
      const next = prev.filter((item) => item.id !== draftId);
      if (next.length > 0 && !next.some((item) => item.is_primary)) {
        return next.map((item, index) => ({ ...item, is_primary: index === 0 }));
      }
      return next;
    });
  };

  const markHostIpPrimary = (draftId: string) => {
    setEditingHostIps((prev) => prev.map((item) => ({ ...item, is_primary: item.id === draftId })));
  };

  const normalizedEditingHostIps = editingHostIps
    .map((item) => ({ ...item, ip_address: item.ip_address.trim(), label: item.label.trim() }))
    .filter((item) => item.ip_address);

  const openHostEdit = () => {
    if (!host) {
      return;
    }
    setEditingHostIps(buildHostIpDrafts(host));
    setEditingHostName(host.hostname ?? "");
    setEditingHostNotes(host.notes ?? "");
    setEditingHostOsType(host.os_type ?? "unknown");
    closeHostActionsMenu();
    setEditHostOpen(true);
  };

  const startHostNotesEdit = () => {
    if (!host) {
      return;
    }
    setError(null);
    setEditingHostNotes(host.notes ?? "");
    setHostNotesEditOpen(true);
  };

  const cancelHostNotesEdit = () => {
    setEditingHostNotes(host?.notes ?? "");
    setHostNotesEditOpen(false);
  };

  const submitHostNotes = async () => {
    if (!projectId || !hostId) {
      return;
    }
    setHostNotesSaving(true);
    setError(null);
    try {
      const updatedHost = await updateHost(projectId, hostId, {
        notes: editingHostNotes.trim() || null,
      });
      setHost((prev) => (prev ? { ...prev, notes: updatedHost.notes } : prev));
      setHostNotesEditOpen(false);
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось обновить описание хоста"));
    } finally {
      setHostNotesSaving(false);
    }
  };

  const saveHostInfo = async () => {
    if (!projectId || !hostId) {
      return;
    }
    setError(null);
    try {
      // В упрощённой форме редактируем только hostname и os_type.
      // IP-адреса и описание управляются отдельными UI-фрагментами
      // на самой странице хоста, в этот диалог не выносим.
      const updatedHost = await updateHost(projectId, hostId, {
        hostname: editingHostName.trim() || undefined,
        os_type: editingHostOsType,
      });
      setHost((prev) =>
        prev
          ? {
              ...prev,
              hostname: updatedHost.hostname,
              status: updatedHost.status,
              os_type: updatedHost.os_type,
            }
          : prev
      );
      setEditHostOpen(false);
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось обновить информацию о хосте."));
    }
  };

  /** Сохраняет переданный список IP в БД и обновляет state хоста на месте. */
  const persistHostIps = async (next: Array<{ ip_address: string; label: string | null; is_primary: boolean }>): Promise<void> => {
    if (!projectId || !hostId) return;
    setError(null);
    try {
      const updated = await updateHost(projectId, hostId, {
        ip_address: next.find((it) => it.is_primary)?.ip_address || next[0]?.ip_address,
        ip_addresses: next,
      });
      setHost((prev) =>
        prev ? { ...prev, ip_address: updated.ip_address, ip_addresses: updated.ip_addresses } : prev,
      );
    } catch (err) {
      setError(getApiErrorMessage(err, "Не удалось обновить IP-адреса хоста."));
    }
  };

  const sanitizeIpv4Input = (raw: string): string => {
    const cleaned = raw.replace(/[^0-9.]/g, "").replace(/\.{2,}/g, ".");
    const parts = cleaned.split(".").slice(0, 4);
    return parts
      .map((part) => {
        if (part === "") return "";
        const trimmed = part.replace(/^0+(?=\d)/, "").slice(0, 3) || part.slice(0, 3);
        const n = parseInt(trimmed, 10);
        if (Number.isNaN(n)) return "";
        return n > 255 ? "255" : String(n);
      })
      .join(".");
  };

  const isValidIpv4 = (value: string): boolean => {
    const parts = value.split(".");
    if (parts.length !== 4) return false;
    return parts.every((p) => /^(0|[1-9]\d?|1\d{2}|2[0-4]\d|25[0-5])$/.test(p));
  };

  const handleAddIp = async (ip: string) => {
    const trimmed = ip.trim();
    if (!trimmed) return;
    if (!isValidIpv4(trimmed)) {
      setError("Некорректный IPv4-адрес");
      return;
    }
    const current = (host?.ip_addresses ?? []).map((row) => ({
      ip_address: row.ip_address,
      label: row.label,
      is_primary: row.is_primary,
    }));
    if (current.some((row) => row.ip_address === trimmed)) {
      setError("IP-адрес уже добавлен");
      return;
    }
    current.push({ ip_address: trimmed, label: null, is_primary: current.length === 0 });
    await persistHostIps(current);
  };

  const handleRemoveIp = async (id: string) => {
    const current = host?.ip_addresses ?? [];
    if (current.length <= 1 && !host?.hostname) {
      setError("Нельзя удалить единственный IP-адрес без указанного hostname");
      return;
    }
    const next = current
      .filter((row) => row.id !== id)
      .map((row, idx) => ({ ip_address: row.ip_address, label: row.label, is_primary: idx === 0 }));
    await persistHostIps(next);
  };

  const removeSelectedIps = async () => {
    const current = host?.ip_addresses ?? [];
    if (selectedIpIds.size === 0) return;
    if (current.length - selectedIpIds.size < 1 && !host?.hostname) {
      setError("Нельзя удалить все IP-адреса без указанного hostname");
      return;
    }
    if (!window.confirm(`Удалить выбранные IP-адреса (${selectedIpIds.size})?`)) return;
    setBulkDeletingIps(true);
    setError(null);
    try {
      const next = current
        .filter((row) => !selectedIpIds.has(row.id))
        .map((row, idx) => ({ ip_address: row.ip_address, label: row.label, is_primary: idx === 0 }));
      await persistHostIps(next);
      setSelectedIpIds(new Set());
      setIpBulkDeleteMode(false);
    } finally {
      setBulkDeletingIps(false);
    }
  };

  const toggleIpSelection = (id: string) => {
    setSelectedIpIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleSaveIpEdit = async (id: string, ip: string, label: string) => {
    const trimmed = ip.trim();
    if (!trimmed) return;
    const current = host?.ip_addresses ?? [];
    if (current.some((row) => row.ip_address === trimmed && row.id !== id)) {
      setError("IP-адрес уже существует в списке");
      return;
    }
    const next = current.map((row) =>
      row.id === id ? { ip_address: trimmed, label: label.trim() || null, is_primary: row.is_primary } : { ip_address: row.ip_address, label: row.label, is_primary: row.is_primary },
    );
    await persistHostIps(next);
  };

  const handleImportIpsCsv = async (file: File) => {
    const text = await file.text();
    const parsed: Array<{ ip: string; label: string }> = [];
    text.split(/\r?\n/).forEach((rawLine) => {
      const line = rawLine.trim();
      if (!line || line.startsWith("#")) return;
      const [ip, ...rest] = line.split(",");
      const candidate = (ip || "").trim();
      if (!candidate) return;
      parsed.push({ ip: candidate, label: rest.join(",").trim() });
    });
    if (parsed.length === 0) {
      setError("В CSV-файле не найдено валидных IP-адресов");
      return;
    }
    const existing = host?.ip_addresses ?? [];
    const seen = new Set(existing.map((row) => row.ip_address));
    const next = [
      ...existing.map((row) => ({ ip_address: row.ip_address, label: row.label, is_primary: row.is_primary })),
    ];
    parsed.forEach(({ ip, label }) => {
      if (seen.has(ip)) return;
      seen.add(ip);
      next.push({ ip_address: ip, label: label || null, is_primary: next.length === 0 });
    });
    await persistHostIps(next);
  };

  const removeHost = async () => {
    if (!projectId || !hostId) {
      return;
    }
    if (!window.confirm("Удалить этот хост?")) {
      return;
    }
    await deleteHost(projectId, hostId);
    navigate(`/projects/${projectId}`);
  };

  const submitNewNote = async () => {
    if (!projectId) return;
    const title = noteCreateTitle.trim();
    if (!title) return;
    setNoteCreateBusy(true);
    try {
      await createProjectNote(projectId, { title, parent_id: noteCreateParentId });
      setProjectNotes(await listProjectNotes(projectId));
      setNoteCreateDialogOpen(false);
    } catch (err) {
      setError(getApiErrorMessage(err, "Не удалось создать заметку"));
    } finally {
      setNoteCreateBusy(false);
    }
  };

  const openEndpointActions = (event: React.MouseEvent<HTMLElement>, endpoint: Endpoint) => {
    event.stopPropagation();
    setEndpointActionsAnchorEl(event.currentTarget);
    setActiveEndpoint(endpoint);
  };

  const closeEndpointActions = () => {
    setEndpointActionsAnchorEl(null);
    setActiveEndpoint(null);
  };

  const toggleExpandedId = (id: string, setExpanded: React.Dispatch<React.SetStateAction<string[]>>) => {
    setExpanded((current) => (current.includes(id) ? current.filter((itemId) => itemId !== id) : [...current, id]));
  };

  const toggleEndpointTreeFolder = useCallback((folderPathKey: string) => {
    setEndpointTreeExpandedKeys((prev) => {
      const next = new Set(prev);
      if (next.has(folderPathKey)) {
        next.delete(folderPathKey);
      } else {
        next.add(folderPathKey);
      }
      return next;
    });
  }, []);

  useEffect(() => {
    setEndpointTreeExpandedKeys(new Set(collectExpandableFolderKeys(endpointPathTree)));
  }, [endpointPathTree]);

  const buildEndpointRawRequestFromEndpoint = (endpoint: Endpoint) => {
    const method = endpoint.method ?? "GET";
    const hostHeader = host?.hostname || host?.ip_address || "example.local";
    const query = new URLSearchParams();
    for (const param of endpoint.query_params || []) {
      if (param.name) {
        query.append(param.name, param.value || "");
      }
    }
    const requestTarget = query.toString() ? `${endpoint.path}?${query.toString()}` : endpoint.path;
    const lines = [`${method} ${requestTarget} HTTP/1.1`, `Host: ${hostHeader}`];
    for (const h of endpoint.request_headers || []) {
      const ln = h.name.trim().toLowerCase();
      if (ln === "host" || ln === "content-type") {
        continue;
      }
      lines.push(`${h.name}: ${h.value}`);
    }
    const requestBody = methodSupportsRequestBody(method as Exclude<Endpoint["method"], null>) ? (endpoint.request_body || "") : "";
    if (requestBody.trim()) {
      lines.push(`Content-Type: ${endpoint.request_content_type || "application/json"}`);
    }
    return `${lines.join("\n")}\n\n${requestBody}`.trimEnd();
  };

  const buildEndpointCurl = (endpoint: Endpoint) => {
    const hostTarget = host?.hostname || host?.ip_address || "example.local";
    return buildDraftCurlLine({
      method: (endpoint.method || "GET") as Exclude<Endpoint["method"], null>,
      path: endpoint.path,
      queryString: queryParamsToQueryString(endpoint.query_params),
      requestBody: endpoint.request_body || "",
      requestContentType: endpoint.request_content_type || "application/json",
      requestHeaders: endpoint.request_headers || [],
      hostTarget,
    });
  };

  const copyEndpointRequest = async (format: "curl" | "raw") => {
    if (!activeEndpoint) {
      return;
    }
    try {
      const text = format === "curl" ? buildEndpointCurl(activeEndpoint) : buildEndpointRawRequestFromEndpoint(activeEndpoint);
      await navigator.clipboard.writeText(text);
      setInfoMessage(format === "curl" ? "cURL запрос скопирован." : "Raw HTTP запрос скопирован.");
      closeEndpointActions();
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось скопировать запрос в буфер обмена."));
    }
  };

  const openPortEdit = (port: Port) => {
    setEditingPortId(port.id);
    setEditingPortNumber(String(port.port_number));
    setEditingPortProtocol(port.protocol);
    setEditingPortState(port.state);
    const portService = servicesByPortId[port.id]?.[0] ?? null;
    setEditingPortServiceId(portService?.id ?? null);
    setEditingPortServiceName(portService?.name ?? "");
    setEditingPortServiceVersion(portService?.version ?? "");
    setEditPortOpen(true);
  };

  const savePortEdit = async () => {
    if (!projectId || !hostId || !editingPortId) {
      return;
    }
    try {
      await updatePort(projectId, hostId, editingPortId, {
        port_number: Number(editingPortNumber),
        protocol: editingPortProtocol,
        state: editingPortState,
      });
      const nextName = editingPortServiceName.trim();
      const nextVersion = editingPortServiceVersion.trim();
      if (editingPortServiceId) {
        if (!nextName) {
          await deleteService(projectId, hostId, editingPortId, editingPortServiceId);
        } else {
          await updateService(projectId, hostId, editingPortId, editingPortServiceId, {
            name: nextName,
            version: nextVersion || null,
          });
        }
      } else if (nextName) {
        await createService(projectId, hostId, editingPortId, {
          name: nextName,
          version: nextVersion || undefined,
        });
      }
      setEditPortOpen(false);
      await loadHost();
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось сохранить порт."));
    }
  };

  const createHostPort = async () => {
    if (!projectId || !hostId || !creatingPortIpId) {
      return;
    }
    try {
      const port = await createPort(projectId, hostId, {
        ip_address_id: creatingPortIpId,
        port_number: Number(creatingPortNumber),
        protocol: creatingPortProtocol,
        state: creatingPortState,
      });
      const serviceName = creatingPortServiceName.trim();
      if (serviceName) {
        try {
          await createService(projectId, hostId, port.id, {
            name: serviceName,
            version: creatingPortServiceVersion.trim() || undefined,
          });
        } catch (serviceError) {
          setError(getApiErrorMessage(serviceError, "Порт создан, но не удалось сохранить сервис."));
        }
      }
      setCreatePortOpen(false);
      setCreatingPortIpId("");
      setCreatingPortNumber("443");
      setCreatingPortProtocol("tcp");
      setCreatingPortState("open");
      setCreatingPortServiceName("");
      setCreatingPortServiceVersion("");
      await loadHost();
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось создать порт."));
    }
  };

  const openCreatePortDialogForIp = (ipAddressId: string) => {
    setCreatingPortIpId(ipAddressId);
    setCreatingPortNumber("443");
    setCreatingPortProtocol("tcp");
    setCreatingPortState("open");
    setCreatingPortServiceName("");
    setCreatingPortServiceVersion("");
    setCreatePortOpen(true);
  };

  const removeSinglePort = async (port: Port) => {
    if (!projectId || !hostId) {
      return;
    }
    if (!window.confirm(`Удалить порт ${port.port_number}/${port.protocol}?`)) {
      return;
    }
    try {
      await deletePort(projectId, hostId, port.id);
      await loadHost();
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось удалить порт."));
    }
  };

  const normalizeImportedPortState = (value: string): Port["state"] => {
    const normalized = value.trim().toLowerCase();
    if (normalized === "open") {
      return "open";
    }
    if (normalized === "closed") {
      return "closed";
    }
    if (normalized === "filtered") {
      return "filtered";
    }
    if (normalized.includes("open")) {
      return "open";
    }
    if (normalized.includes("closed")) {
      return "closed";
    }
    return "filtered";
  };

  const parseNmapPortsFromText = (rawText: string): Array<{ port_number: number; protocol: Port["protocol"]; state: Port["state"] }> => {
    const entries = new Map<string, { port_number: number; protocol: Port["protocol"]; state: Port["state"] }>();
    const lines = rawText.replace(/\r/g, "").split("\n");

    const addEntry = (portNumber: number, protocol: Port["protocol"], stateRaw: string) => {
      if (!Number.isInteger(portNumber) || portNumber < 1 || portNumber > 65535) {
        return;
      }
      const key = `${portNumber}/${protocol}`;
      entries.set(key, {
        port_number: portNumber,
        protocol,
        state: normalizeImportedPortState(stateRaw),
      });
    };

    // Regular Nmap output lines: "22/tcp open ssh"
    lines.forEach((line) => {
      const match = line.match(/^\s*(\d{1,5})\/(tcp|udp)\s+([a-zA-Z|_-]+)\b/i);
      if (!match) {
        return;
      }
      addEntry(Number(match[1]), match[2].toLowerCase() as Port["protocol"], match[3]);
    });

    // Grepable output fragments: "Ports: 22/open/tcp//ssh///, 53/open/udp//domain///"
    lines.forEach((line) => {
      const portsMatch = line.match(/Ports:\s*(.+)$/i);
      if (!portsMatch) {
        return;
      }
      const fragments = portsMatch[1].split(",").map((item) => item.trim());
      fragments.forEach((fragment) => {
        const parts = fragment.split("/");
        if (parts.length < 3) {
          return;
        }
        const portNumber = Number(parts[0]);
        const stateRaw = parts[1] || "";
        const protocol = (parts[2] || "").toLowerCase();
        if (protocol !== "tcp" && protocol !== "udp") {
          return;
        }
        addEntry(portNumber, protocol, stateRaw);
      });
    });

    // XML output fragments: <port protocol="tcp" portid="443"> ... <state state="open"/>
    const xmlPortRegex = /<port[^>]*protocol="(tcp|udp)"[^>]*portid="(\d{1,5})"[\s\S]*?<state[^>]*state="([^"]+)"/gi;
    let xmlMatch: RegExpExecArray | null;
    while ((xmlMatch = xmlPortRegex.exec(rawText)) !== null) {
      addEntry(Number(xmlMatch[2]), xmlMatch[1].toLowerCase() as Port["protocol"], xmlMatch[3]);
    }

    return Array.from(entries.values()).sort((left, right) => left.port_number - right.port_number);
  };

  const importPortsFromNmapFile = async (file: File | null, ipAddressId: string) => {
    if (!file || !projectId || !hostId || !ipAddressId) {
      return;
    }
    setNmapImporting(true);
    setError(null);
    setInfoMessage(null);
    try {
      const rawText = await file.text();
      const parsedPorts = parseNmapPortsFromText(rawText);
      if (!parsedPorts.length) {
        throw new Error("В Nmap файле не найдено портов для импорта.");
      }
      const targetIp = host?.ip_addresses.find((ip) => ip.id === ipAddressId);
      const existingKeys = new Set((targetIp?.ports ?? []).map((item) => `${item.port_number}/${item.protocol}`));
      let created = 0;
      let skipped = 0;
      let failed = 0;
      for (const entry of parsedPorts) {
        const key = `${entry.port_number}/${entry.protocol}`;
        if (existingKeys.has(key)) {
          skipped += 1;
          continue;
        }
        try {
          await createPort(projectId, hostId, { ...entry, ip_address_id: ipAddressId });
          existingKeys.add(key);
          created += 1;
        } catch {
          failed += 1;
        }
      }
      await loadHost();
      setInfoMessage(`Nmap импорт завершен: добавлено ${created}, пропущено ${skipped}, ошибок ${failed}.`);
    } catch (importError) {
      setError(getApiErrorMessage(importError, "Не удалось импортировать порты из Nmap."));
    } finally {
      setNmapImporting(false);
    }
  };

  const openCreateServiceDialog = (portId: string) => {
    setCreateServicePortId(portId);
    setCreatingServiceName("");
    setCreatingServiceVersion("");
    setCreateServiceOpen(true);
  };

  const createPortService = async () => {
    if (!projectId || !hostId || !createServicePortId) {
      return;
    }
    await createService(projectId, hostId, createServicePortId, {
      name: creatingServiceName.trim(),
      version: creatingServiceVersion.trim() || undefined,
    });
    setCreateServiceOpen(false);
    await loadHost();
  };

  const openEditServiceDialog = (portId: string, service: Service) => {
    setEditServicePortId(portId);
    setEditingServiceId(service.id);
    setEditingServiceName(service.name);
    setEditingServiceVersion(service.version || "");
    setEditServiceOpen(true);
  };

  const cancelServiceBulkDelete = () => {
    setServiceBulkDeletePortId(null);
    setSelectedServiceIdsForDelete(new Set());
  };

  const toggleServiceSelectionForDelete = (serviceId: string) => {
    setSelectedServiceIdsForDelete((prev) => {
      const next = new Set(prev);
      if (next.has(serviceId)) {
        next.delete(serviceId);
      } else {
        next.add(serviceId);
      }
      return next;
    });
  };

  const removeSelectedServicesFromPort = async (portId: string) => {
    if (!projectId || !hostId || selectedServiceIdsForDelete.size === 0) {
      return;
    }
    if (!window.confirm(`Удалить выбранные сервисы (${selectedServiceIdsForDelete.size})?`)) {
      return;
    }
    setBulkDeletingServices(true);
    setError(null);
    const failures: string[] = [];
    try {
      for (const serviceId of Array.from(selectedServiceIdsForDelete)) {
        try {
          await deleteService(projectId, hostId, portId, serviceId);
        } catch (deleteError) {
          failures.push(getApiErrorMessage(deleteError, "Не удалось удалить сервис."));
        }
      }
      cancelServiceBulkDelete();
      await loadHost();
      if (failures.length) {
        setError(failures.join("\n"));
      }
    } finally {
      setBulkDeletingServices(false);
    }
  };

  const saveServiceEdit = async () => {
    if (!projectId || !hostId || !editServicePortId || !editingServiceId) {
      return;
    }
    await updateService(projectId, hostId, editServicePortId, editingServiceId, {
      name: editingServiceName.trim() || undefined,
      version: editingServiceVersion.trim() || undefined,
    });
    setEditServiceOpen(false);
    await loadHost();
  };

  const buildEndpointRawRequestFromFields = ({
    method,
    path,
    queryParams,
    requestHeaders,
    requestBody,
    requestContentType,
    hostLine,
  }: {
    method: Exclude<Endpoint["method"], null>;
    path: string;
    queryParams: EndpointQueryParam[];
    requestHeaders: EndpointRequestHeader[];
    requestBody: string;
    requestContentType: string;
    hostLine: string;
  }) => {
    const normalizedPath = path.trim() || "/";
    const query = new URLSearchParams();
    for (const param of normalizeEndpointQueryParams(queryParams)) {
      query.append(param.name, param.value || "");
    }
    const requestTarget = query.toString() ? `${normalizedPath}?${query.toString()}` : normalizedPath;
    const lines = [`${method} ${requestTarget} HTTP/1.1`, `Host: ${hostLine}`];
    for (const h of requestHeaders) {
      const ln = h.name.trim().toLowerCase();
      if (ln === "host" || ln === "content-type") {
        continue;
      }
      lines.push(`${h.name}: ${h.value}`);
    }
    const body = methodSupportsRequestBody(method) ? requestBody.trim() : "";
    if (body) {
      lines.push(`Content-Type: ${requestContentType.trim() || "application/json"}`);
    }
    return `${lines.join("\n")}\n\n${body}`.trimEnd();
  };

  const editingEndpointResolvedQueryParams = useMemo(
    () =>
      editingEndpointMethod === "POST"
        ? []
        : normalizeEndpointQueryParams(queryStringToQueryParams(editingEndpointQueryString)),
    [editingEndpointMethod, editingEndpointQueryString]
  );

  const creatingEndpointResolvedQueryParams = useMemo(
    () =>
      creatingEndpointMethod === "POST"
        ? []
        : normalizeEndpointQueryParams(queryStringToQueryParams(creatingEndpointQueryString)),
    [creatingEndpointMethod, creatingEndpointQueryString]
  );

  const endpointFormHostLine = host?.hostname || host?.ip_address || "example.local";

  const creatingEndpointSanitizedHeaders = useMemo(
    () => parseHeaderTextToSanitizedList(creatingEndpointHeadersText),
    [creatingEndpointHeadersText]
  );

  const editingEndpointSanitizedHeaders = useMemo(
    () => parseHeaderTextToSanitizedList(editingEndpointHeadersText),
    [editingEndpointHeadersText]
  );

  const applyParsedRequestToCreateEndpoint = (rawRequest: string) => {
    const parsed = parseRawHttpRequest(rawRequest);
    if (!parsed) {
      setCreatingEndpointImportHostWarn(false);
      return;
    }
    setCreatingEndpointMethod(parsed.method);
    setCreatingEndpointPath(parsed.path);
    setCreatingEndpointRequestBody(parsed.requestBody);
    setCreatingEndpointRequestContentType(parsed.requestContentType);
    setCreatingEndpointHeadersText(headersArrayToText(parsed.sanitizedHeaders));
    const assetHost = host?.hostname || host?.ip_address || "";
    setCreatingEndpointImportHostWarn(hostTokensMismatch(parsed.hostHeaderRaw, assetHost));
    if (parsed.method === "POST") {
      setCreatingEndpointQueryString("");
    } else {
      setCreatingEndpointQueryString(queryParamsToQueryString(parsed.queryParams));
    }
  };

  const applyParsedRequestToEditEndpoint = (rawRequest: string) => {
    const parsed = parseRawHttpRequest(rawRequest);
    if (!parsed) {
      setEditingEndpointImportHostWarn(false);
      return;
    }
    setEditingEndpointMethod(parsed.method);
    setEditingEndpointPath(parsed.path);
    setEditingEndpointRequestBody(parsed.requestBody);
    setEditingEndpointRequestContentType(parsed.requestContentType);
    setEditingEndpointHeadersText(headersArrayToText(parsed.sanitizedHeaders));
    const assetHost = host?.hostname || host?.ip_address || "";
    setEditingEndpointImportHostWarn(hostTokensMismatch(parsed.hostHeaderRaw, assetHost));
    if (parsed.method === "POST") {
      setEditingEndpointQueryString("");
    } else {
      setEditingEndpointQueryString(queryParamsToQueryString(parsed.queryParams));
    }
  };

  useEffect(() => {
    const rawRequest = creatingEndpointImportRaw.trim();
    if (!rawRequest) {
      setCreatingEndpointImportHostWarn(false);
      return;
    }
    applyParsedRequestToCreateEndpoint(creatingEndpointImportRaw);
  }, [creatingEndpointImportRaw, host?.hostname, host?.ip_address]);

  useEffect(() => {
    const rawRequest = editingEndpointImportRaw.trim();
    if (!rawRequest) {
      setEditingEndpointImportHostWarn(false);
      return;
    }
    applyParsedRequestToEditEndpoint(editingEndpointImportRaw);
  }, [editingEndpointImportRaw, host?.hostname, host?.ip_address]);

  const editingEndpointPreviewRequest = useMemo(
    () =>
      buildEndpointRawRequestFromFields({
        method: editingEndpointMethod,
        path: editingEndpointPath,
        queryParams: editingEndpointResolvedQueryParams,
        requestHeaders: editingEndpointSanitizedHeaders,
        requestBody: editingEndpointRequestBody,
        requestContentType: editingEndpointRequestContentType,
        hostLine: endpointFormHostLine,
      }),
    [
      editingEndpointMethod,
      editingEndpointPath,
      editingEndpointResolvedQueryParams,
      editingEndpointSanitizedHeaders,
      editingEndpointRequestBody,
      editingEndpointRequestContentType,
      endpointFormHostLine,
    ]
  );

  const creatingEndpointPreviewRequest = useMemo(
    () =>
      buildEndpointRawRequestFromFields({
        method: creatingEndpointMethod,
        path: creatingEndpointPath,
        queryParams: creatingEndpointResolvedQueryParams,
        requestHeaders: creatingEndpointSanitizedHeaders,
        requestBody: creatingEndpointRequestBody,
        requestContentType: creatingEndpointRequestContentType,
        hostLine: endpointFormHostLine,
      }),
    [
      creatingEndpointMethod,
      creatingEndpointPath,
      creatingEndpointResolvedQueryParams,
      creatingEndpointSanitizedHeaders,
      creatingEndpointRequestBody,
      creatingEndpointRequestContentType,
      endpointFormHostLine,
    ]
  );

  const copyCreatingEndpointDraft = async (format: "curl" | "raw") => {
    const hostTarget = host?.hostname || host?.ip_address || "example.local";
    try {
      const text =
        format === "raw"
          ? creatingEndpointPreviewRequest
          : buildDraftCurlLine({
              method: creatingEndpointMethod,
              path: creatingEndpointPath,
              queryString: creatingEndpointQueryString,
              requestBody: creatingEndpointRequestBody,
              requestContentType: creatingEndpointRequestContentType,
              requestHeaders: creatingEndpointSanitizedHeaders,
              hostTarget,
            });
      await navigator.clipboard.writeText(text);
      setInfoMessage(format === "curl" ? "cURL скопирован в буфер обмена." : "Raw HTTP скопирован в буфер обмена.");
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось скопировать в буфер обмена."));
    }
  };

  const copyEditingEndpointDraft = async (format: "curl" | "raw") => {
    const hostTarget = host?.hostname || host?.ip_address || "example.local";
    try {
      const text =
        format === "raw"
          ? editingEndpointPreviewRequest
          : buildDraftCurlLine({
              method: editingEndpointMethod,
              path: editingEndpointPath,
              queryString: editingEndpointQueryString,
              requestBody: editingEndpointRequestBody,
              requestContentType: editingEndpointRequestContentType,
              requestHeaders: editingEndpointSanitizedHeaders,
              hostTarget,
            });
      await navigator.clipboard.writeText(text);
      setInfoMessage(format === "curl" ? "cURL скопирован в буфер обмена." : "Raw HTTP скопирован в буфер обмена.");
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось скопировать в буфер обмена."));
    }
  };

  const openCreateEndpointDialog = () => {
    setCreatingEndpointPath("");
    setCreatingEndpointMethod("GET");
    setCreatingEndpointImportRaw("");
    setCreatingEndpointQueryString("");
    setCreatingEndpointHeadersText("");
    setCreatingEndpointImportHostWarn(false);
    setCreatingEndpointRequestBody("");
    setCreatingEndpointRequestContentType("application/json");
    setCreateEndpointOpen(true);
  };

  const openEndpointEdit = (endpoint: Endpoint) => {
    setEditingEndpointId(endpoint.id);
    setEditingEndpointPath(endpoint.path);
    setEditingEndpointMethod(endpoint.method || "GET");
    setEditingEndpointQueryString(queryParamsToQueryString(endpoint.query_params));
    setEditingEndpointHeadersText(headersArrayToText(endpoint.request_headers));
    setEditingEndpointImportHostWarn(false);
    setEditingEndpointRequestBody(endpoint.request_body || "");
    setEditingEndpointRequestContentType(endpoint.request_content_type || "application/json");
    setEditingEndpointImportRaw("");
    setEditEndpointOpen(true);
  };

  const saveEndpointEdit = async () => {
    if (!projectId || !hostId || !editingEndpointId) {
      return;
    }
    const headers = parseHeaderTextToSanitizedList(editingEndpointHeadersText);
    const bodyAllowed = methodSupportsRequestBody(editingEndpointMethod);
    await updateEndpoint(projectId, hostId, editingEndpointId, {
      path: editingEndpointPath,
      method: editingEndpointMethod,
      description: null,
      query_params:
        editingEndpointMethod === "POST" ? [] : normalizeEndpointQueryParams(queryStringToQueryParams(editingEndpointQueryString)),
      request_headers: headers,
      request_body: bodyAllowed && editingEndpointRequestBody.trim() ? editingEndpointRequestBody.trim() : null,
      request_content_type:
        bodyAllowed && editingEndpointRequestBody.trim() ? editingEndpointRequestContentType.trim() || "application/json" : null,
    });
    setEditEndpointOpen(false);
    setEditingEndpointImportRaw("");
    await loadHost();
  };

  const removeEndpoint = async (endpointId: string) => {
    if (!projectId || !hostId) {
      return;
    }
    if (!window.confirm("Удалить эндпоинт?")) {
      return;
    }
    // #region agent log
    postHostDetailReloadDebugLog(
      "frontend/src/pages/HostDetailPage.tsx:removeEndpoint:start",
      "Endpoint deletion requested",
      { hostId, projectId, endpointId, selectedCount: selectedEndpointIds.size, path: location.pathname },
      "R3"
    );
    // #endregion
    try {
      await deleteEndpoint(projectId, hostId, endpointId);
      applyRemovedEndpointsLocally(new Set([endpointId]));
      setEndpointBulkDeleteMode(false);
      setSelectedEndpointIds(new Set());
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось удалить эндпоинт."));
    }
  };

  const collectEndpointIdsInTreeNode = useCallback((node: EndpointPathTreeNode): string[] => {
    const ids: string[] = node.endpointsAtNode.map((ep) => ep.id);
    for (const child of node.children) {
      ids.push(...collectEndpointIdsInTreeNode(child));
    }
    return ids;
  }, []);

  const getNodeSelectionState = useCallback(
    (node: EndpointPathTreeNode): { checked: boolean; indeterminate: boolean; total: number } => {
      const ids = collectEndpointIdsInTreeNode(node);
      if (ids.length === 0) {
        return { checked: false, indeterminate: false, total: 0 };
      }
      let selected = 0;
      for (const id of ids) {
        if (selectedEndpointIds.has(id)) {
          selected += 1;
        }
      }
      return { checked: selected === ids.length, indeterminate: selected > 0 && selected < ids.length, total: ids.length };
    },
    [collectEndpointIdsInTreeNode, selectedEndpointIds]
  );

  const toggleEndpointSelection = useCallback((endpointId: string) => {
    setSelectedEndpointIds((prev) => {
      const next = new Set(prev);
      if (next.has(endpointId)) {
        next.delete(endpointId);
      } else {
        next.add(endpointId);
      }
      // #region agent log
      postEndpointDeleteModeDebugLog(
        "frontend/src/pages/HostDetailPage.tsx:toggle_endpoint_selection",
        "Endpoint selection toggled",
        {
          endpointId,
          nextSelectedCount: next.size,
        },
        "H2"
      );
      // #endregion
      return next;
    });
  }, []);

  const setNodeSelectionChecked = useCallback(
    (node: EndpointPathTreeNode, checked: boolean) => {
      const ids = collectEndpointIdsInTreeNode(node);
      setSelectedEndpointIds((prev) => {
        const next = new Set(prev);
        for (const id of ids) {
          if (checked) {
            next.add(id);
          } else {
            next.delete(id);
          }
        }
        return next;
      });
    },
    [collectEndpointIdsInTreeNode]
  );

  const removeSelectedEndpoints = async () => {
    if (!projectId || !hostId || selectedEndpointIds.size === 0) {
      return;
    }
    if (!window.confirm(`Удалить выбранные эндпоинты (${selectedEndpointIds.size})?`)) {
      return;
    }
    setBulkDeletingEndpoints(true);
    setError(null);
    const failures: string[] = [];
    const removedOk = new Set<string>();
    try {
      for (const endpointId of Array.from(selectedEndpointIds)) {
        try {
          await deleteEndpoint(projectId, hostId, endpointId);
          removedOk.add(endpointId);
        } catch (deleteError) {
          failures.push(getApiErrorMessage(deleteError, "Не удалось удалить эндпоинт."));
        }
      }
      setSelectedEndpointIds(new Set());
      applyRemovedEndpointsLocally(removedOk);
      setEndpointBulkDeleteMode(false);
      if (failures.length) {
        setError(failures.join("\n"));
      } else {
        setInfoMessage("Выбранные эндпоинты удалены.");
      }
    } finally {
      setBulkDeletingEndpoints(false);
    }
  };

  const createHostEndpoint = async () => {
    if (!projectId || !hostId) {
      return;
    }
    const headers = parseHeaderTextToSanitizedList(creatingEndpointHeadersText);
    const bodyAllowed = methodSupportsRequestBody(creatingEndpointMethod);
    await createEndpoint(projectId, hostId, {
      path: creatingEndpointPath.trim() || undefined,
      method: creatingEndpointMethod,
      description: null,
      query_params:
        creatingEndpointMethod === "POST" ? [] : normalizeEndpointQueryParams(queryStringToQueryParams(creatingEndpointQueryString)),
      request_headers: headers,
      request_body: bodyAllowed && creatingEndpointRequestBody.trim() ? creatingEndpointRequestBody.trim() : null,
      request_content_type:
        bodyAllowed && creatingEndpointRequestBody.trim() ? creatingEndpointRequestContentType.trim() || "application/json" : null,
    });
    setCreateEndpointOpen(false);
    setCreatingEndpointPath("");
    setCreatingEndpointMethod("GET");
    setCreatingEndpointImportRaw("");
    setCreatingEndpointQueryString("");
    setCreatingEndpointHeadersText("");
    setCreatingEndpointImportHostWarn(false);
    setCreatingEndpointRequestBody("");
    setCreatingEndpointRequestContentType("application/json");
    await loadHost();
  };

  const importEndpointsFromSwaggerFile = async (file: File | null) => {
    if (!file || !projectId || !hostId) {
      return;
    }
    setSwaggerImporting(true);
    setError(null);
    setInfoMessage(null);
    try {
      const result = await importOpenApiFile(projectId, hostId, file);
      await loadHost();
      setInfoMessage(
        `Swagger импорт завершен: добавлено ${result.endpoints_created}, пропущено ${result.endpoints_skipped}, предупреждений ${result.errors.length}.`
      );
      if (result.errors.length) {
        setError(result.errors.join("\n"));
      }
    } catch (importError) {
      setError(getApiErrorMessage(importError, "Не удалось импортировать Swagger/OpenAPI."));
    } finally {
      setSwaggerImporting(false);
    }
  };

  const exportEndpointsToSwaggerFile = async () => {
    if (!projectId || !hostId) {
      return;
    }
    setSwaggerExporting(true);
    setError(null);
    try {
      const blob = await exportOpenApiFile(projectId, hostId);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      const safeHost = (host?.hostname || host?.ip_address || hostId).replace(/[^a-zA-Z0-9._-]+/g, "_");
      link.download = `swagger-${safeHost}.json`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      setInfoMessage("Swagger экспортирован.");
    } catch (exportError) {
      setError(getApiErrorMessage(exportError, "Не удалось экспортировать Swagger/OpenAPI."));
    } finally {
      setSwaggerExporting(false);
    }
  };

  const openVulnerabilityEdit = (vulnerability: Vulnerability) => {
    setEditingVulnerabilityId(vulnerability.id);
    setEditingVulnerabilityTitle(vulnerability.title);
    setEditingVulnerabilityDescription(vulnerability.description || "");
    setEditingVulnerabilitySeverity(vulnerability.severity);
    setEditingVulnerabilityStatus(vulnerability.status);
    setEditVulnerabilityOpen(true);
  };

  const saveVulnerabilityEdit = async () => {
    if (!projectId || !editingVulnerabilityId) {
      return;
    }
    await updateVulnerability(projectId, editingVulnerabilityId, {
      title: editingVulnerabilityTitle,
      description: editingVulnerabilityDescription || undefined,
      severity: editingVulnerabilitySeverity,
      status: editingVulnerabilityStatus,
    });
    setEditVulnerabilityOpen(false);
    await loadHost();
  };

  const toggleVulnerabilitySelection = useCallback((vulnerabilityId: string) => {
    setSelectedVulnerabilityIds((prev) => {
      const next = new Set(prev);
      if (next.has(vulnerabilityId)) {
        next.delete(vulnerabilityId);
      } else {
        next.add(vulnerabilityId);
      }
      return next;
    });
  }, []);

  const removeSelectedVulnerabilities = async () => {
    if (!projectId || selectedVulnerabilityIds.size === 0) {
      return;
    }
    if (!window.confirm(`Удалить выбранные уязвимости (${selectedVulnerabilityIds.size})?`)) {
      return;
    }
    setBulkDeletingVulnerabilities(true);
    setError(null);
    const failures: string[] = [];
    try {
      for (const vulnerabilityId of Array.from(selectedVulnerabilityIds)) {
        try {
          await deleteVulnerability(projectId, vulnerabilityId);
        } catch (deleteError) {
          failures.push(getApiErrorMessage(deleteError, "Не удалось удалить уязвимость."));
        }
      }
      setSelectedVulnerabilityIds(new Set());
      setVulnerabilityBulkDeleteMode(false);
      await loadHost();
      if (failures.length) {
        setError(failures.join("\n"));
      } else {
        setInfoMessage("Выбранные уязвимости удалены.");
      }
    } finally {
      setBulkDeletingVulnerabilities(false);
    }
  };

  const createHostVulnerability = async () => {
    if (!projectId || !hostId || !creatingVulnerabilityTitle.trim()) {
      return;
    }
    setError(null);
    try {
      const created = await createVulnerability(projectId, {
        host_id: hostId,
        title: creatingVulnerabilityTitle.trim(),
        description: null,
        severity: "info",
        status: "open",
        cvss_version: null,
        cvss_score: null,
        cvss_vector: null,
        cwe_id: null,
        workflow_steps: [],
        impact: null,
        recommendations: null,
        steps_to_reproduce: null,
      });
      setCreateVulnerabilityOpen(false);
      setCreatingVulnerabilityTitle("");
      setCreatingVulnerabilitySeverity("info");
      setCreatingVulnerabilityStatus("open");
      setCreatingVulnerabilityCvssScore("");
      setCreatingVulnerabilityCvssVector("");
      setCreatingVulnerabilityCweId("");
      setCreatingVulnerabilityStages([]);
      setCreatingVulnerabilityImpact("");
      setCreatingVulnerabilityRecommendations("");
      navigate(`/projects/${projectId}/hosts/${hostId}/vulnerabilities/${created.id}`, {
        replace: true,
        state: { section: "vulns", startVulnEdit: true },
      });
      void loadHost();
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось создать уязвимость."));
    }
  };

  useEffect(() => {
    setSelectedPortIds((prev) => {
      const valid = new Set((host?.ip_addresses ?? []).flatMap((ip) => ip.ports.map((p) => p.id)));
      const next = new Set<string>();
      prev.forEach((id) => {
        if (valid.has(id)) {
          next.add(id);
        }
      });
      return next.size === prev.size ? prev : next;
    });
  }, [host?.ip_addresses]);

  useEffect(() => {
    if (!host?.ip_addresses?.length) {
      return;
    }
    setExpandedIpIds((prev) => {
      const validIds = new Set(host.ip_addresses.map((ip) => ip.id));
      const kept = prev.filter((id) => validIds.has(id));
      return kept.length === prev.length ? prev : kept;
    });
  }, [host?.ip_addresses]);

  useEffect(() => {
    if (selectedSection === "ports") {
      setExpandedIpIds([]);
    }
  }, [selectedSection]);

  useEffect(() => {
    if (ipBulkDeleteMode) {
      setExpandedIpIds([]);
    }
  }, [ipBulkDeleteMode]);

  const togglePortSelection = useCallback((portId: string) => {
    setSelectedPortIds((prev) => {
      const next = new Set(prev);
      if (next.has(portId)) {
        next.delete(portId);
      } else {
        next.add(portId);
      }
      return next;
    });
  }, []);

  const removeSelectedPorts = async () => {
    if (!projectId || !hostId || selectedPortIds.size === 0) {
      return;
    }
    if (!window.confirm(`Удалить выбранные порты (${selectedPortIds.size})?`)) {
      return;
    }
    setBulkDeletingPorts(true);
    setError(null);
    const failures: string[] = [];
    try {
      for (const portId of Array.from(selectedPortIds)) {
        try {
          await deletePort(projectId, hostId, portId);
        } catch (deleteError) {
          failures.push(getApiErrorMessage(deleteError, "Не удалось удалить порт."));
        }
      }
      setSelectedPortIds(new Set());
      setPortBulkDeleteMode(false);
      await loadHost();
      if (failures.length) {
        setError(failures.join("\n"));
      } else {
        setInfoMessage("Выбранные порты удалены.");
      }
    } finally {
      setBulkDeletingPorts(false);
    }
  };

  const buildAutoCvssFields = (vector: string | null) => {
    const normalizedVersion = vector?.trim() ? CVSS_VERSION : null;
    const { score } = calculateCvssScore(normalizedVersion, vector);
    return {
      severity: severityFromCvssScore(score),
      cvss_version: normalizedVersion,
      cvss_vector: vector,
      cvss_score: score,
    };
  };

  const loadVulnerabilityDetails = useCallback(
    async (vulnerabilityId: string, options?: { startVulnEdit?: boolean }) => {
      if (!projectId) {
        return;
      }
      setVulnBusy(true);
      setError(null);
      try {
        const [vulnDetail, commentsPage] = await Promise.all([
          getVulnerability(projectId, vulnerabilityId),
          listVulnerabilityComments(projectId, vulnerabilityId),
        ]);
        setActiveVulnDetails(vulnDetail);
        setVulnComments(commentsPage.items);
        if (options?.startVulnEdit) {
          setVulnEditMode(true);
          navigate(".", { replace: true, state: { section: "vulns" } });
        }
        setVulnDetailOpen(true);
      } catch (error) {
        setError(getApiErrorMessage(error, "Не удалось загрузить карточку уязвимости."));
      } finally {
        setVulnBusy(false);
      }
    },
    [projectId, navigate],
  );

  useEffect(() => {
    if (!vulnerabilityId) {
      setVulnDetailOpen(false);
      setActiveVulnDetails(null);
      setVulnComments([]);
      setVulnEditMode(false);
      return;
    }
    setSelectedSection("vulns");
    const st = location.state as { startVulnEdit?: boolean } | null;
    const shouldStartEdit = Boolean(st?.startVulnEdit);
    if (!shouldStartEdit) {
      setVulnEditMode(false);
    }
    void loadVulnerabilityDetails(vulnerabilityId, { startVulnEdit: shouldStartEdit });
  }, [loadVulnerabilityDetails, vulnerabilityId]);

  const [mentionHighlightActive, setMentionHighlightActive] = useState(false);

  const vulnCommentIdsKey = useMemo(
    () =>
      vulnComments
        .map((comment) => comment.id)
        .sort()
        .join("\n"),
    [vulnComments]
  );

  useEffect(() => {
    if (!highlightedCommentId || !activeVulnDetails?.id) {
      setMentionHighlightActive(false);
      return;
    }
    const commentInList = vulnCommentIdsKey.split("\n").filter(Boolean).includes(highlightedCommentId);
    if (!commentInList) {
      setMentionHighlightActive(false);
      return;
    }
    if (vulnEditMode) {
      setMentionHighlightActive(false);
      return;
    }
    const element = document.getElementById(`comment-${highlightedCommentId}`);
    if (!element) {
      return;
    }
    window.setTimeout(() => {
      element.scrollIntoView({ behavior: "smooth", block: "center" });
    }, 0);
    setMentionHighlightActive(true);
    const timer = window.setTimeout(() => {
      setMentionHighlightActive(false);
    }, 3000);
    return () => {
      window.clearTimeout(timer);
    };
  }, [activeVulnDetails?.id, highlightedCommentId, vulnCommentIdsKey, vulnEditMode]);

  const saveActiveVulnerability = async () => {
    if (!projectId || !activeVulnDetails) {
      return;
    }
    const workflowSteps = activeVulnDetails.workflow_steps || [];
    setVulnBusy(true);
    setError(null);
    try {
      const updated = await updateVulnerability(projectId, activeVulnDetails.id, {
        title: activeVulnDetails.title,
        description: activeVulnDetails.description || null,
        severity: activeVulnDetails.severity,
        status: activeVulnDetails.status,
        cvss_version: activeVulnDetails.cvss_vector?.trim() ? CVSS_VERSION : null,
        cvss_score: activeVulnDetails.cvss_score,
        cvss_vector: activeVulnDetails.cvss_vector,
        cwe_id: activeVulnDetails.cwe_id,
        workflow_steps: workflowSteps,
        steps_to_reproduce: activeVulnDetails.steps_to_reproduce || null,
        impact: activeVulnDetails.impact || null,
        recommendations: activeVulnDetails.recommendations || null,
      });
      setActiveVulnDetails((prev) => (prev ? { ...prev, ...updated } : prev));
      await loadHost();
      setVulnEditMode(false);
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось сохранить уязвимость."));
    } finally {
      setVulnBusy(false);
    }
  };

  const addCommentToActiveVuln = async () => {
    if (!projectId || !activeVulnDetails || !newComment.trim()) {
      return;
    }
    setVulnBusy(true);
    try {
      const created = await createVulnerabilityComment(projectId, activeVulnDetails.id, newComment.trim());
      setVulnComments((prev) => [...prev, created]);
      setNewComment("");
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось добавить комментарий."));
    } finally {
      setVulnBusy(false);
    }
  };

  const removeCommentFromActiveVuln = async (commentId: string) => {
    if (!projectId || !activeVulnDetails) {
      return;
    }
    setVulnBusy(true);
    try {
      await deleteVulnerabilityComment(projectId, activeVulnDetails.id, commentId);
      setVulnComments((prev) => prev.filter((comment) => comment.id !== commentId));
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось удалить комментарий."));
    } finally {
      setVulnBusy(false);
    }
  };

  const openCommentEdit = (comment: VulnerabilityComment) => {
    setEditingCommentId(comment.id);
    setEditingCommentContent(comment.content);
    setEditCommentOpen(true);
  };

  const saveCommentEdit = async () => {
    if (!projectId || !activeVulnDetails || !editingCommentId || !editingCommentContent.trim()) {
      return;
    }
    setVulnBusy(true);
    try {
      const updated = await updateVulnerabilityComment(projectId, activeVulnDetails.id, editingCommentId, editingCommentContent.trim());
      setVulnComments((prev) => prev.map((comment) => (comment.id === updated.id ? updated : comment)));
      setEditCommentOpen(false);
      setEditingCommentId(null);
      setEditingCommentContent("");
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось обновить комментарий."));
    } finally {
      setVulnBusy(false);
    }
  };

  const hostTitle = host?.hostname || host?.ip_address || "unknown-host";
  const allHostPorts = useMemo<Port[]>(
    () => host?.ip_addresses.flatMap((ip) => ip.ports) ?? [],
    [host?.ip_addresses]
  );
  const portsCount = allHostPorts.length;
  const endpointsCount = normalizedHostEndpoints.length;
  const vulnerabilitiesCount = vulnerabilities.length;
  const severityChipSx: Record<Vulnerability["severity"], object> = {
    critical: { bgcolor: "rgba(244,67,54,0.18)", color: "#ff8a80", border: "1px solid rgba(244,67,54,0.4)" },
    high: { bgcolor: "rgba(255,152,0,0.18)", color: "#ffcc80", border: "1px solid rgba(255,152,0,0.4)" },
    medium: { bgcolor: "rgba(255,235,59,0.14)", color: "#fff59d", border: "1px solid rgba(255,235,59,0.35)" },
    low: { bgcolor: "rgba(76,175,80,0.16)", color: "#a5d6a7", border: "1px solid rgba(76,175,80,0.38)" },
    info: { bgcolor: "rgba(33,150,243,0.18)", color: "#90caf9", border: "1px solid rgba(33,150,243,0.38)" },
  };
  const vulnerabilityStatusChipSx: Record<Vulnerability["status"], object> = {
    open: { bgcolor: "rgba(244,67,54,0.18)", color: "#ff8a80", border: "1px solid rgba(244,67,54,0.4)" },
    in_progress: { bgcolor: "rgba(255,152,0,0.18)", color: "#ffcc80", border: "1px solid rgba(255,152,0,0.4)" },
    fixed: { bgcolor: "rgba(76,175,80,0.16)", color: "#a5d6a7", border: "1px solid rgba(76,175,80,0.38)" },
    wont_fix: { bgcolor: "rgba(156,39,176,0.16)", color: "#ce93d8", border: "1px solid rgba(156,39,176,0.38)" },
    accepted_risk: { bgcolor: "rgba(96,125,139,0.2)", color: "#b0bec5", border: "1px solid rgba(96,125,139,0.38)" },
  };

  const renderEndpointPaper = (endpoint: Endpoint): ReactNode => {
    const methodColors = swaggerMethodColors(endpoint.method);
    const expanded = expandedEndpointIds.includes(endpoint.id);
    const segs = endpointPathToSegments(endpoint.path);
    const shortTitle = segs.length ? segs[segs.length - 1]! : "/";
    const fullPathDisplay = normalizeUriPathForTree(endpoint.path);
    const hasParams = !!endpoint.query_params?.length;
    const hasBody = !!(endpoint.request_body && endpoint.request_body.trim());
    const showBodySection = methodSupportsRequestBody((endpoint.method || "GET") as Exclude<Endpoint["method"], null>);
    const hasSavedHeaders = !!(endpoint.request_headers && endpoint.request_headers.length > 0);
    return (
      <Paper
        key={endpoint.id}
        variant="outlined"
        sx={{
          borderRadius: 1,
          overflow: "hidden",
          borderColor: "rgba(126,224,255,0.16)",
          borderLeft: `4px solid ${methodColors.main}`,
          backgroundColor: "rgba(8,17,31,0.35)",
          "& .endpoint-actions": {
            opacity: 0,
            pointerEvents: "none",
            transition: "opacity 0.15s ease-in-out",
          },
          "&:hover .endpoint-actions": {
            opacity: 1,
            pointerEvents: "auto",
          },
        }}
      >
        <Stack
          direction="row"
          alignItems="center"
          spacing={1}
          onClick={() => toggleExpandedId(endpoint.id, setExpandedEndpointIds)}
          sx={{
            px: 1.5,
            py: 1.1,
            cursor: "pointer",
            flexWrap: "wrap",
            rowGap: 0.5,
            backgroundColor: expanded ? "rgba(126,224,255,0.06)" : "transparent",
          }}
        >
          {endpointBulkDeleteMode ? (
            <Checkbox
              size="small"
              inputProps={{ "data-endpoint-delete-checkbox": "true" }}
              checked={selectedEndpointIds.has(endpoint.id)}
              onClick={(event) => event.stopPropagation()}
              onChange={() => toggleEndpointSelection(endpoint.id)}
              sx={{ p: 0.25, mr: -0.5 }}
            />
          ) : null}
          <Chip
            size="small"
            label={(endpoint.method || "GET").toUpperCase()}
            sx={{
              fontWeight: 800,
              fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
              letterSpacing: 0.4,
              bgcolor: methodColors.main,
              color: methodColors.contrast,
              borderRadius: 0.75,
              height: 26,
            }}
          />
          <Stack spacing={0.15} sx={{ minWidth: 0 }}>
            <Typography
              component="span"
              sx={{
                fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
                fontWeight: 700,
                fontSize: "0.95rem",
                lineHeight: 1.2,
              }}
            >
              {shortTitle}
            </Typography>
            <Typography
              variant="caption"
              color="text.secondary"
              sx={{ fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace", wordBreak: "break-all", lineHeight: 1.2 }}
            >
              {fullPathDisplay}
            </Typography>
          </Stack>
          <Box sx={{ flex: "1 1 40px" }} />
          <Stack direction="row" spacing={0.25} alignItems="center" className="endpoint-actions" onClick={(e) => e.stopPropagation()}>
            <Tooltip title="Действия">
              <IconButton size="small" onClick={(event) => openEndpointActions(event, endpoint)}>
                <MoreVertIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          </Stack>
          <ExpandMoreIcon
            fontSize="small"
            sx={{
              color: "text.secondary",
              transform: expanded ? "rotate(180deg)" : "rotate(0deg)",
              transition: "transform 0.2s ease",
            }}
          />
        </Stack>

        <Collapse in={expanded} timeout="auto" unmountOnExit>
          <Box sx={{ px: 2, pb: 2, pt: 0, borderTop: "1px solid rgba(126,224,255,0.1)" }}>
            {hasParams ? (
              <>
                <Typography variant="subtitle2" fontWeight={700} sx={{ mt: 1.25, mb: 1 }}>
                  Параметры
                </Typography>
              <TableContainer
                component={Paper}
                variant="outlined"
                sx={{ borderColor: "rgba(126,224,255,0.14)", backgroundColor: "rgba(8,17,31,0.45)" }}
              >
                <Table size="small" sx={{ tableLayout: "fixed" }}>
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ fontWeight: 700, width: ENDPOINT_TABLE_NAME_COLUMN_WIDTH, borderColor: "rgba(126,224,255,0.12)" }}>Имя</TableCell>
                      <TableCell sx={{ fontWeight: 700, borderColor: "rgba(126,224,255,0.12)" }}>Описание</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {endpoint.query_params!.map((param, index) => (
                      <TableRow key={`${endpoint.id}-${param.name}-${index}`}>
                        <TableCell
                          sx={{
                            verticalAlign: "top",
                            borderColor: "rgba(126,224,255,0.1)",
                            fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
                          }}
                        >
                          <Box component="span" fontWeight={700}>
                            {param.name}
                            {param.required ? (
                              <Box component="span" sx={{ color: "error.main", ml: 0.25 }}>
                                *
                              </Box>
                            ) : null}
                          </Box>
                        </TableCell>
                        <TableCell sx={{ verticalAlign: "top", borderColor: "rgba(126,224,255,0.1)" }}>
                          {param.description ? (
                            <Typography variant="body2" color="text.secondary" sx={{ mb: param.value ? 0.5 : 0 }}>
                              {param.description}
                            </Typography>
                          ) : null}
                          {param.value ? (
                            <Typography variant="body2" component="div" sx={{ fontFamily: "ui-monospace, monospace", wordBreak: "break-all" }}>
                              {param.value}
                            </Typography>
                          ) : null}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
              </>
            ) : null}

            {hasSavedHeaders && (
              <>
                <Typography variant="subtitle2" fontWeight={700} sx={{ mt: 2.5, mb: 1 }}>
                  Заголовки
                </Typography>
                <TableContainer
                  component={Paper}
                  variant="outlined"
                  sx={{ borderColor: "rgba(126,224,255,0.14)", backgroundColor: "rgba(8,17,31,0.45)" }}
                >
                  <Table size="small" sx={{ tableLayout: "fixed" }}>
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ fontWeight: 700, width: ENDPOINT_TABLE_NAME_COLUMN_WIDTH, borderColor: "rgba(126,224,255,0.12)" }}>Имя</TableCell>
                        <TableCell sx={{ fontWeight: 700, borderColor: "rgba(126,224,255,0.12)" }}>Значение</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {endpoint.request_headers!.map((h, index) => (
                        <TableRow key={`${endpoint.id}-hdr-${index}`}>
                          <TableCell
                            sx={{
                              verticalAlign: "top",
                              borderColor: "rgba(126,224,255,0.1)",
                              fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
                            }}
                          >
                            {h.name}
                          </TableCell>
                          <TableCell
                            sx={{
                              verticalAlign: "top",
                              borderColor: "rgba(126,224,255,0.1)",
                              wordBreak: "break-word",
                              fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
                              fontSize: "0.8125rem",
                            }}
                          >
                            {h.value}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </>
            )}

            {showBodySection && (hasBody || endpoint.request_content_type) && (
              <>
                <Typography variant="subtitle2" fontWeight={700} sx={{ mt: 2.5, mb: 1 }}>
                  Тело запроса
                </Typography>
                {endpoint.request_content_type && (
                  <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 1 }}>
                    <Typography variant="caption" color="text.secondary">
                      Тип содержимого
                    </Typography>
                    <Chip
                      size="small"
                      variant="outlined"
                      label={endpoint.request_content_type}
                      sx={{ fontFamily: "ui-monospace, monospace", borderColor: "rgba(126,224,255,0.25)" }}
                    />
                  </Stack>
                )}
                {hasBody ? (
                  <>
                    <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 0.75 }}>
                      Пример значения
                    </Typography>
                    <Paper
                      variant="outlined"
                      sx={{
                        m: 0,
                        p: 1.5,
                        borderColor: "rgba(126,224,255,0.14)",
                        backgroundColor: "rgba(15,23,42,0.92)",
                        overflowX: "auto",
                      }}
                    >
                      <Box
                        component="pre"
                        sx={{
                          m: 0,
                          fontSize: "0.8125rem",
                          lineHeight: 1.55,
                          fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
                          whiteSpace: "pre-wrap",
                          wordBreak: "break-word",
                          color: "#e2e8f0",
                        }}
                      >
                        {formatRequestBodyPreview(endpoint.request_body)}
                      </Box>
                    </Paper>
                  </>
                ) : (
                  <Typography variant="body2" color="text.disabled" fontStyle="italic">
                    Тело запроса не задано (указан только тип содержимого)
                  </Typography>
                )}
              </>
            )}
          </Box>
        </Collapse>
      </Paper>
    );
  };

  const renderEndpointPathTree = (root: EndpointPathTreeNode): ReactNode => {
    const walk = (node: EndpointPathTreeNode, depth: number): ReactNode => {
      const isRoot = node.pathKey === "";
      const papers = node.endpointsAtNode.map((ep) => renderEndpointPaper(ep));
      if (isRoot) {
        return (
          <Stack spacing={1.25} key="ep-tree-root">
            {papers}
            {node.children.map((child) => (
              <Box key={child.pathKey}>{walk(child, 1)}</Box>
            ))}
          </Stack>
        );
      }
      if (node.children.length === 0) {
        return (
          <Stack key={node.pathKey} spacing={1.25}>
            {papers}
          </Stack>
        );
      }
      const expanded = endpointTreeExpandedKeys.has(node.pathKey);
      const selectionState = getNodeSelectionState(node);
      return (
        <Box key={node.pathKey}>
          <Stack
            direction="row"
            alignItems="center"
            spacing={0.75}
            onClick={() => toggleEndpointTreeFolder(node.pathKey)}
            sx={{
              cursor: "pointer",
              py: 0.65,
              px: 0.5,
              borderRadius: 0.75,
              pl: Math.min(depth, 6) * 1.25,
              "&:hover": { backgroundColor: "rgba(126,224,255,0.06)" },
            }}
          >
            {endpointBulkDeleteMode ? (
              <Checkbox
                size="small"
                inputProps={{ "data-endpoint-delete-checkbox": "true" }}
                checked={selectionState.checked}
                indeterminate={selectionState.indeterminate}
                disabled={selectionState.total === 0}
                onClick={(event) => event.stopPropagation()}
                onChange={(event) => setNodeSelectionChecked(node, event.target.checked)}
                sx={{ p: 0.25 }}
              />
            ) : null}
            <ExpandMoreIcon
              fontSize="small"
              sx={{
                color: "text.secondary",
                transform: expanded ? "rotate(0deg)" : "rotate(-90deg)",
                transition: "transform 0.2s ease",
              }}
            />
            <Typography fontWeight={700} sx={{ fontFamily: "ui-monospace, monospace", fontSize: "0.9rem" }}>
              {node.segment}
            </Typography>
          </Stack>
          <Collapse in={expanded} timeout="auto" unmountOnExit>
            <Stack
              spacing={1.25}
              sx={{
                pl: 1.5,
                ml: Math.min(depth, 6) * 1.25 + 0.75,
                borderLeft: "1px solid rgba(126,224,255,0.12)",
                mt: 0.5,
              }}
            >
              {papers}
              {node.children.map((child) => (
                <Box key={child.pathKey}>{walk(child, depth + 1)}</Box>
              ))}
            </Stack>
          </Collapse>
        </Box>
      );
    };
    return walk(root, 0);
  };

  const closeVulnerabilityView = () => {
    setVulnEditMode(false);
    if (projectId && hostId && isVulnerabilityRoute) {
      navigate(`/projects/${projectId}/hosts/${hostId}`, { state: { section: "vulns" } });
      return;
    }
    setVulnDetailOpen(false);
  };

  const openCommentActionsMenu = (event: React.MouseEvent<HTMLElement>, comment: VulnerabilityComment) => {
    setActiveComment(comment);
    setCommentActionsAnchorEl(event.currentTarget);
  };

  const closeCommentActionsMenu = () => {
    setCommentActionsAnchorEl(null);
    setActiveComment(null);
  };

  const formatCommentTimestamp = (value: string): string =>
    new Intl.DateTimeFormat("ru-RU", {
      day: "2-digit",
      month: "2-digit",
      year: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    }).format(new Date(value));

  const renderCommentsSection = (): ReactNode => (
    <Stack spacing={1.25}>
      <Typography variant="subtitle1" fontWeight={700}>
        Комментарии ({vulnComments.length})
      </Typography>
      <List dense disablePadding>
        {vulnComments.map((comment, commentIndex) => {
          const isHighlighted = highlightedCommentId === comment.id && mentionHighlightActive;
          const canManageComment = user?.id === comment.user_id;
          return (
            <Fragment key={comment.id}>
            <ListItem
              id={`comment-${comment.id}`}
              alignItems="flex-start"
              sx={{
                mb: 0,
                py: 1.25,
                border: "1px solid transparent",
                ...(isHighlighted
                  ? {
                      animation: "mentionHighlightFade 3s ease forwards",
                      "@keyframes mentionHighlightFade": {
                        "0%": {
                          backgroundColor: "rgba(76,175,80,0.28)",
                          borderColor: "rgba(76,175,80,0.75)",
                        },
                        "66%": {
                          backgroundColor: "rgba(76,175,80,0.28)",
                          borderColor: "rgba(76,175,80,0.75)",
                        },
                        "100%": {
                          backgroundColor: "transparent",
                          borderColor: "transparent",
                        },
                      },
                    }
                  : {}),
                scrollMarginTop: 96,
                ...(canManageComment
                  ? {
                      "&:hover .comment-row-actions, &:focus-within .comment-row-actions": {
                        opacity: 1,
                        pointerEvents: "auto",
                      },
                    }
                  : {}),
              }}
            >
              <Stack spacing={0.75} sx={{ width: "100%" }}>
                <Stack direction="row" justifyContent="space-between" alignItems="center" spacing={2}>
                  <Stack direction="row" alignItems="center" spacing={1.25} minWidth={0}>
                    <Avatar
                      src={comment.avatar_url || undefined}
                      alt={comment.username}
                      sx={{ width: 28, height: 28, fontSize: "0.8rem", bgcolor: "rgba(126,224,255,0.18)" }}
                    >
                      {comment.username.slice(0, 1).toUpperCase()}
                    </Avatar>
                    <Typography fontWeight={700} color="text.primary" noWrap>
                      {comment.username}
                    </Typography>
                  </Stack>
                  <Stack direction="row" alignItems="center" spacing={0} sx={{ flexShrink: 0 }}>
                    <Typography
                      variant="caption"
                      color="text.secondary"
                      sx={{ whiteSpace: "nowrap", textAlign: "right", minWidth: "7.75rem", pr: 0.5 }}
                    >
                      {formatCommentTimestamp(comment.created_at)}
                    </Typography>
                    <Box sx={{ width: 36, display: "flex", justifyContent: "flex-end", flexShrink: 0 }}>
                      {canManageComment ? (
                        <IconButton
                          className="comment-row-actions"
                          size="small"
                          onClick={(event) => openCommentActionsMenu(event, comment)}
                          sx={{
                            mr: -0.75,
                            opacity: 0,
                            pointerEvents: "none",
                            transition: "opacity 0.15s ease",
                            color: "rgba(148,163,184,0.85)",
                            "&:hover": {
                              color: "rgba(148,163,184,1)",
                              backgroundColor: "rgba(126,224,255,0.06)",
                            },
                          }}
                        >
                          <MoreVertIcon fontSize="small" />
                        </IconButton>
                      ) : null}
                    </Box>
                  </Stack>
                </Stack>
                <Typography variant="body2" color="rgba(235,245,255,0.92)" sx={{ whiteSpace: "pre-wrap", pr: 1 }}>
                  {comment.content}
                </Typography>
              </Stack>
            </ListItem>
            </Fragment>
          );
        })}
        {vulnComments.length === 0 && <Typography color="text.secondary">Комментариев пока нет.</Typography>}
      </List>
      <TextField
        label="Комментарий (@username только для участников проекта)"
        multiline
        minRows={3}
        value={newComment}
        onChange={(event) => setNewComment(event.target.value)}
      />
      <Stack direction="row" justifyContent="flex-end">
        <Button variant="contained" disabled={!newComment.trim() || vulnBusy} onClick={() => void addCommentToActiveVuln()}>
          Добавить комментарий
        </Button>
      </Stack>
      <Menu
        anchorEl={commentActionsAnchorEl}
        open={Boolean(commentActionsAnchorEl)}
        onClose={closeCommentActionsMenu}
        anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
        transformOrigin={{ vertical: "top", horizontal: "right" }}
      >
        <MenuItem
          onClick={() => {
            if (activeComment) {
              openCommentEdit(activeComment);
            }
            closeCommentActionsMenu();
          }}
        >
          <EditIcon fontSize="small" sx={{ mr: 1 }} />
          Редактировать
        </MenuItem>
        <MenuItem
          onClick={() => {
            if (activeComment) {
              void removeCommentFromActiveVuln(activeComment.id);
            }
            closeCommentActionsMenu();
          }}
        >
          <DeleteOutlineIcon fontSize="small" sx={{ mr: 1 }} />
          Удалить
        </MenuItem>
      </Menu>
    </Stack>
  );

  const renderMarkdownPreview = (value: string | null | undefined, emptyText: string, title?: string): ReactNode => {
    if (title) {
      const inputId =
        title === "Влияние"
          ? "host-detail-vuln-impact"
          : title === "Рекомендации"
            ? "host-detail-vuln-recommendations"
            : `host-detail-md-${title.replace(/\s+/g, "-").toLowerCase()}`;
      return <MarkdownOutlinedReadonlyField label={title} inputId={inputId} value={value} emptyText={emptyText} />;
    }
    return (
      <Box sx={{ border: "1px solid rgba(126,224,255,0.14)", p: 1.5, backgroundColor: "rgba(8,17,31,0.28)", "& p": { color: "#ffffff" }, "& li": { color: "#ffffff" }, "& a": { color: "rgba(255,255,255,0.92)" } }}>
        {value?.trim() ? (
          <ReactMarkdown urlTransform={markdownUrlTransform} components={{ img: MarkdownImage }}>
            {normalizeMarkdownForRender(value)}
          </ReactMarkdown>
        ) : (
          <Typography color="text.secondary">{emptyText}</Typography>
        )}
      </Box>
    );
  };

  const renderVulnerabilityDetailsContent = (): ReactNode => {
    if (!activeVulnDetails) {
      return <Typography color="text.secondary">Уязвимость не выбрана.</Typography>;
    }

    return (
      <Stack spacing={2} sx={{ mt: 0.5 }}>
        <Grid container spacing={2}>
          <Grid size={{ xs: 12, md: 7 }}>
            <TextField
              label="Название"
              fullWidth
              value={activeVulnDetails.title}
              onChange={(event) => setActiveVulnDetails((prev) => (prev ? { ...prev, title: event.target.value } : prev))}
              slotProps={{ input: { readOnly: !vulnEditMode } }}
            />
          </Grid>
          <Grid size={{ xs: 12, md: 3 }}>
            <TextField
              label="CWE ID"
              fullWidth
              value={activeVulnDetails.cwe_id || ""}
              onChange={(event) => setActiveVulnDetails((prev) => (prev ? { ...prev, cwe_id: event.target.value || null } : prev))}
              slotProps={{ input: { readOnly: !vulnEditMode } }}
            />
          </Grid>
          <Grid size={{ xs: 12, md: 2 }}>
            {vulnEditMode ? (
              <TextField
                select
                label="Статус"
                fullWidth
                value={activeVulnDetails.status}
                onChange={(event) =>
                  setActiveVulnDetails((prev) => (prev ? { ...prev, status: event.target.value as Vulnerability["status"] } : prev))
                }
              >
                <MenuItem value="open">open</MenuItem>
                <MenuItem value="in_progress">in_progress</MenuItem>
                <MenuItem value="fixed">fixed</MenuItem>
                <MenuItem value="wont_fix">wont_fix</MenuItem>
                <MenuItem value="accepted_risk">accepted_risk</MenuItem>
              </TextField>
            ) : (
              <TextField label="Статус" fullWidth value={activeVulnDetails.status} slotProps={{ input: { readOnly: true } }} />
            )}
          </Grid>
          <Grid size={{ xs: 12, md: 2 }}>
            <TextField label="CVSS score" type="number" fullWidth value={activeVulnDetails.cvss_score ?? ""} slotProps={{ input: { readOnly: true } }} />
          </Grid>
          <Grid size={{ xs: 12, md: 2 }}>
            <TextField label="Критичность" fullWidth value={activeVulnDetails.severity} slotProps={{ input: { readOnly: true } }} />
          </Grid>
          <Grid size={{ xs: 12, md: 8 }}>
            <TextField
              label="CVSS vector"
              fullWidth
              value={activeVulnDetails.cvss_vector || ""}
              onChange={(event) =>
                setActiveVulnDetails((prev) => (prev ? { ...prev, ...buildAutoCvssFields(event.target.value || null) } : prev))
              }
              slotProps={{ input: { readOnly: !vulnEditMode } }}
            />
          </Grid>
          <Grid size={{ xs: 12 }}>
            <VulnerabilityStagesEditor
              stages={activeVulnDetails.workflow_steps || []}
              endpoints={normalizedHostEndpoints}
              hostLabel={host?.hostname || host?.ip_address || undefined}
              busy={vulnBusy}
              editable={vulnEditMode}
              onChange={(nextStages) =>
                setActiveVulnDetails((prev) =>
                  prev
                    ? {
                        ...prev,
                        workflow_steps: nextStages,
                      }
                    : prev
                )
              }
              onUploadImage={async (stageId, file) => {
                if (!projectId || !activeVulnDetails) {
                  return null;
                }
                try {
                  const uploadedFile = await uploadVulnerabilityFile(projectId, activeVulnDetails.id, file);
                  setActiveVulnDetails((prev) =>
                    prev
                      ? {
                          ...prev,
                          files: [uploadedFile, ...prev.files.filter((fileMeta) => fileMeta.id !== uploadedFile.id)],
                        }
                      : prev
                  );
                  return `![${uploadedFile.original_name}](/api/v1/files/${uploadedFile.id}/download)`;
                } catch {
                  setError("Не удалось загрузить картинку этапа.");
                  return null;
                }
              }}
            />
          </Grid>
          <Grid size={{ xs: 12 }}>
            {vulnEditMode ? (
              <MarkdownEditor
                label="Влияние"
                minRows={2}
                value={activeVulnDetails.impact}
                onChange={(next) => setActiveVulnDetails((prev) => (prev ? { ...prev, impact: next } : prev))}
              />
            ) : (
              renderMarkdownPreview(activeVulnDetails.impact, "Влияние не указано.", "Влияние")
            )}
          </Grid>
          <Grid size={{ xs: 12 }}>
            {vulnEditMode ? (
              <MarkdownEditor
                label="Рекомендации"
                minRows={2}
                value={activeVulnDetails.recommendations}
                onChange={(next) =>
                  setActiveVulnDetails((prev) => (prev ? { ...prev, recommendations: next } : prev))
                }
              />
            ) : (
              renderMarkdownPreview(activeVulnDetails.recommendations, "Рекомендации не указаны.", "Рекомендации")
            )}
          </Grid>
          {vulnEditMode && (
            <Grid size={{ xs: 12 }}>
              <Stack direction={{ xs: "column", sm: "row" }} justifyContent="flex-end" spacing={1.5}>
                <Button variant="outlined" size="large" sx={{ minWidth: { sm: 180 } }} onClick={() => void loadVulnerabilityDetails(activeVulnDetails.id)}>
                  Отменить
                </Button>
                <Button
                  variant="contained"
                  size="large"
                  sx={{ minWidth: { sm: 200 } }}
                  onClick={() => void saveActiveVulnerability()}
                  disabled={!activeVulnDetails || vulnBusy}
                >
                  Сохранить изменения
                </Button>
              </Stack>
            </Grid>
          )}
        </Grid>

      </Stack>
    );
  };

  // Показываем full-screen спиннер только при первом заходе (когда host ещё не загружен).
  // При навигации между хостами host уже есть из предыдущего рендера — пользователь видит
  // прежний контент + узкий LinearProgress сверху, без "перезагрузки страницы".
  if (loading && !host) {
    return (
      <Box display="flex" justifyContent="center" py={6}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Stack spacing={2.5}>
      {loading && (
        <LinearProgress
          sx={{ height: 2, "& .MuiLinearProgress-bar": { backgroundColor: "rgba(126,224,255,0.6)" } }}
        />
      )}
      <Stack direction="row" justifyContent="space-between" alignItems="center" flexWrap="wrap" gap={1}>
        <Stack direction="row" alignItems="center" spacing={1.5}>
          <HostOsIcon os_type={host?.os_type ?? "unknown"} sx={{ fontSize: 36 }} />
          <Stack spacing={0.2}>
            <Typography variant="h4" fontWeight={700}>
              Хост: {hostTitle}
            </Typography>
          </Stack>
        </Stack>
        {/*
          Кнопка-троеточие в правом краю шапки — единый стиль с обзором проекта:
          контур, 42x42, тёмная заливка. В меню — «Редактировать хост» / «Удалить хост».
        */}
        <IconButton
          aria-label="Действия с хостом"
          onClick={openHostActionsMenu}
          sx={{
            border: "1px solid rgba(126,224,255,0.2)",
            width: 42,
            height: 42,
            backgroundColor: "rgba(15,27,45,0.72)",
          }}
        >
          <MoreVertIcon />
        </IconButton>
      </Stack>

      <Menu
        anchorEl={hostActionsAnchorEl}
        open={hostActionsOpen}
        onClose={closeHostActionsMenu}
        anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
        transformOrigin={{ vertical: "top", horizontal: "right" }}
      >
        <MenuItem onClick={openHostEdit}>
          <EditIcon fontSize="small" sx={{ mr: 1 }} />
          Редактировать хост
        </MenuItem>
        <MenuItem
          onClick={() => {
            closeHostActionsMenu();
            void removeHost();
          }}
        >
          <DeleteIcon fontSize="small" sx={{ mr: 1 }} />
          Удалить хост
        </MenuItem>
      </Menu>

      <Stack direction={{ xs: "column", md: "row" }} spacing={2} alignItems={{ md: "flex-start" }}>
        <ProjectTreeNav
          projectId={projectId}
          viewMode="host"
          hosts={hosts}
          selectedHostId={hostId ?? null}
          selectedSection={selectedSection}
          isCollapsed={isSidebarCollapsed}
          portsCount={portsCount}
          endpointsCount={endpointsCount}
          vulnerabilitiesCount={vulnerabilitiesCount}
          hostStatsById={hostStatsById}
          notesCount={projectNotes.length}
          notes={projectNotes}
          selectedNoteId={null}
          onToggleCollapsed={() => setSidebarCollapsed((v) => !v)}
          onSelectSection={openHostSection}
          onSelectProjectOverview={() => navigate(`/projects/${projectId}`)}
          onSelectNote={(noteId) => navigate(`/projects/${projectId}/notes/${noteId}`)}
          onSelectNotesLabel={() => navigate(`/projects/${projectId}/notes`)}
          onCreateNote={(parentId) => {
            // Открываем платформенный диалог — никаких window.prompt.
            setNoteCreateParentId(parentId);
            setNoteCreateTitle("");
            setNoteCreateDialogOpen(true);
          }}
          onMoveNote={async (noteId, newParentId) => {
            if (!projectId) return;
            try {
              await moveProjectNote(projectId, noteId, { parent_id: newParentId });
              setProjectNotes(await listProjectNotes(projectId));
            } catch (err) {
              setError(getApiErrorMessage(err, "Не удалось переместить заметку"));
            }
          }}
          onReorderNotes={async (parentId, orderedIds) => {
            if (!projectId) return;
            try {
              await reorderProjectNotes(projectId, {
                parent_id: parentId,
                items: orderedIds.map((id, idx) => ({ id, sort_order: idx + 1 })),
              });
              setProjectNotes(await listProjectNotes(projectId));
            } catch (err) {
              setError(getApiErrorMessage(err, "Не удалось обновить порядок заметок"));
            }
          }}
          onSelectHost={() => undefined}
          onOpenHost={(nextHostId, section) => {
            // #region agent log
            postHostDetailReloadDebugLog(
              "frontend/src/pages/HostDetailPage.tsx:onOpenHost",
              "Host navigation requested",
              { currentHostId: hostId, nextHostId, projectId, section, path: location.pathname },
              "R4"
            );
            // #endregion
            navigate(`/projects/${projectId}/hosts/${nextHostId}`, { state: { section } });
          }}
        />

        <Stack flex={1} spacing={2}>
          <Grid container spacing={2}>
            <Grid size={{ xs: 12, md: 4 }}>
              <Card
                onClick={() => openHostSection("ports")}
                sx={{
                  cursor: "pointer",
                  border: selectedSection === "ports" ? "1px solid rgba(126,224,255,0.45)" : "1px solid rgba(126,224,255,0.16)",
                  backgroundColor: selectedSection === "ports" ? "rgba(17,38,62,0.88)" : "rgba(15,27,45,0.82)",
                }}
              >
                <CardContent>
                  <Typography color="text.secondary">IP-адресов хоста</Typography>
                  <Typography variant="h4" fontWeight={700}>
                    {host?.ip_addresses.length ?? 0}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <Card
                onClick={() => openHostSection("endpoints")}
                sx={{
                  cursor: "pointer",
                  border: selectedSection === "endpoints" ? "1px solid rgba(126,224,255,0.45)" : "1px solid rgba(126,224,255,0.16)",
                  backgroundColor: selectedSection === "endpoints" ? "rgba(17,38,62,0.88)" : "rgba(15,27,45,0.82)",
                }}
              >
                <CardContent>
                  <Typography color="text.secondary">Эндпоинтов хоста</Typography>
                  <Typography variant="h4" fontWeight={700}>
                    {endpointsCount}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <Card
                onClick={() => openHostSection("vulns")}
                sx={{
                  cursor: "pointer",
                  border: selectedSection === "vulns" ? "1px solid rgba(126,224,255,0.45)" : "1px solid rgba(126,224,255,0.16)",
                  backgroundColor: selectedSection === "vulns" ? "rgba(17,38,62,0.88)" : "rgba(15,27,45,0.82)",
                }}
              >
                <CardContent>
                  <Typography color="text.secondary">Уязвимостей хоста</Typography>
                  <Typography variant="h4" fontWeight={700}>
                    {vulnerabilitiesCount}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          </Grid>

          {selectedSection === "overview" && (
            <Stack spacing={2}>
              <Card sx={{ border: "1px solid rgba(126,224,255,0.14)" }}>
                <CardContent>
                  <Stack direction="row" alignItems="center" justifyContent="space-between" mb={1}>
                    <Typography variant="h6" fontWeight={700}>
                      IP-адреса
                    </Typography>
                    <IconButton
                      size="small"
                      aria-label="Действия с IP-адресами"
                      onClick={(event) => setIpActionsAnchorEl(event.currentTarget)}
                    >
                      <MoreVertIcon fontSize="small" />
                    </IconButton>
                  </Stack>
                  <Menu
                    anchorEl={ipActionsAnchorEl}
                    open={Boolean(ipActionsAnchorEl)}
                    onClose={() => setIpActionsAnchorEl(null)}
                    anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
                    transformOrigin={{ vertical: "top", horizontal: "right" }}
                  >
                    <MenuItem
                      onClick={() => {
                        setAddIpDraft("");
                        setIpActionsAnchorEl(null);
                      }}
                    >
                      <AddIcon fontSize="small" sx={{ mr: 1 }} />
                      Добавить IP-адрес
                    </MenuItem>
                    <MenuItem
                      onClick={() => {
                        ipCsvInputRef.current?.click();
                        setIpActionsAnchorEl(null);
                      }}
                    >
                      <UploadFileIcon fontSize="small" sx={{ mr: 1 }} />
                      Импортировать из CSV
                    </MenuItem>
                    <MenuItem
                      onClick={() => {
                        setIpBulkDeleteMode(true);
                        setSelectedIpIds(new Set());
                        setIpActionsAnchorEl(null);
                      }}
                    >
                      <DeleteOutlineIcon fontSize="small" sx={{ mr: 1 }} />
                      Удалить IP-адреса
                    </MenuItem>
                  </Menu>
                  {ipBulkDeleteMode && (
                    <Stack direction="row" spacing={1} alignItems="center" mb={1}>
                      <Typography variant="body2" color="text.secondary">
                        Выбрано: {selectedIpIds.size}
                      </Typography>
                      <Box sx={{ flexGrow: 1 }} />
                      <Button
                        size="small"
                        color="error"
                        variant="contained"
                        disabled={selectedIpIds.size === 0 || bulkDeletingIps}
                        onClick={() => void removeSelectedIps()}
                      >
                        {bulkDeletingIps ? "Удаление…" : `Удалить (${selectedIpIds.size})`}
                      </Button>
                      <Button
                        size="small"
                        disabled={bulkDeletingIps}
                        onClick={() => {
                          setIpBulkDeleteMode(false);
                          setSelectedIpIds(new Set());
                        }}
                      >
                        Отмена
                      </Button>
                    </Stack>
                  )}
                  <input
                    ref={ipCsvInputRef}
                    type="file"
                    accept=".csv,text/csv,text/plain"
                    hidden
                    onChange={async (event) => {
                      const file = event.target.files?.[0];
                      event.target.value = "";
                      if (file) await handleImportIpsCsv(file);
                    }}
                  />
                  <Stack spacing={1}>
                    {(host?.ip_addresses?.length ? host.ip_addresses : host?.ip_address ? [{ id: "primary", ip_address: host.ip_address, label: null, is_primary: true }] : []).map((ip) => {
                      const isEditing = editIpDraftId === ip.id;
                      return (
                        <Box
                          key={ip.id}
                          sx={{
                            border: "1px solid rgba(126,224,255,0.12)",
                            p: 1.2,
                            backgroundColor: "rgba(8,17,31,0.24)",
                            "&:hover .ip-row-actions": { opacity: 1 },
                          }}
                        >
                          {isEditing ? (
                            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap">
                              <TextField
                                size="small"
                                value={editIpDraft.ip}
                                onChange={(event) => setEditIpDraft((prev) => ({ ...prev, ip: event.target.value }))}
                                placeholder="IP"
                                sx={{ minWidth: 160 }}
                              />
                              <TextField
                                size="small"
                                value={editIpDraft.label}
                                onChange={(event) => setEditIpDraft((prev) => ({ ...prev, label: event.target.value }))}
                                placeholder="Метка"
                                sx={{ minWidth: 160 }}
                              />
                              <Button
                                size="small"
                                variant="contained"
                                onClick={async () => {
                                  await handleSaveIpEdit(ip.id, editIpDraft.ip, editIpDraft.label);
                                  setEditIpDraftId(null);
                                }}
                              >
                                Сохранить
                              </Button>
                              <Button size="small" onClick={() => setEditIpDraftId(null)}>
                                Отмена
                              </Button>
                            </Stack>
                          ) : (
                            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap">
                              {ipBulkDeleteMode && ip.id !== "primary" && (
                                <Checkbox
                                  size="small"
                                  checked={selectedIpIds.has(ip.id)}
                                  onChange={() => toggleIpSelection(ip.id)}
                                  sx={{ p: 0.25 }}
                                />
                              )}
                              <Typography fontWeight={700}>{ip.ip_address}</Typography>
                              {ip.label ? <Typography color="text.secondary">{ip.label}</Typography> : null}
                              <Box sx={{ flexGrow: 1 }} />
                              {!ipBulkDeleteMode && ip.id !== "primary" && (
                                <IconButton
                                  size="small"
                                  aria-label="Редактировать IP"
                                  className="ip-row-actions"
                                  sx={{ opacity: 0, transition: "opacity .15s ease" }}
                                  onClick={() => {
                                    setEditIpDraftId(ip.id);
                                    setEditIpDraft({ ip: ip.ip_address, label: ip.label ?? "" });
                                  }}
                                >
                                  <EditIcon fontSize="small" />
                                </IconButton>
                              )}
                            </Stack>
                          )}
                        </Box>
                      );
                    })}
                    {addIpDraft !== null && (
                      <Box sx={{ border: "1px dashed rgba(126,224,255,0.3)", p: 1.2, backgroundColor: "rgba(8,17,31,0.18)" }}>
                        <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap">
                          <TextField
                            size="small"
                            autoFocus
                            value={addIpDraft}
                            onChange={(event) => setAddIpDraft(sanitizeIpv4Input(event.target.value))}
                            onKeyDown={async (event) => {
                              if (event.key === "Enter" && addIpDraft && isValidIpv4(addIpDraft)) {
                                event.preventDefault();
                                await handleAddIp(addIpDraft);
                                setAddIpDraft(null);
                              }
                            }}
                            placeholder="0.0.0.0"
                            inputProps={{
                              inputMode: "numeric",
                              maxLength: 15,
                              pattern: "^(25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]?\\d)){3}$",
                              "aria-label": "IPv4-адрес",
                            }}
                            error={Boolean(addIpDraft) && !isValidIpv4(addIpDraft)}
                            helperText={addIpDraft && !isValidIpv4(addIpDraft) ? "Введите IPv4 в формате 0.0.0.0" : " "}
                            sx={{ minWidth: 180 }}
                          />
                          <Button
                            size="small"
                            variant="contained"
                            disabled={!addIpDraft || !isValidIpv4(addIpDraft)}
                            onClick={async () => {
                              if (!addIpDraft) return;
                              await handleAddIp(addIpDraft);
                              setAddIpDraft(null);
                            }}
                          >
                            Добавить
                          </Button>
                          <Button size="small" onClick={() => setAddIpDraft(null)}>
                            Отмена
                          </Button>
                        </Stack>
                      </Box>
                    )}
                    {!host?.ip_addresses?.length && !host?.ip_address && !addIpDraft && (
                      <Typography color="text.secondary">IP-адреса не добавлены.</Typography>
                    )}
                  </Stack>
                </CardContent>
              </Card>
              <Card
                sx={{
                  border: "1px solid rgba(126,224,255,0.14)",
                  "&:hover .host-notes-edit-btn": { opacity: 1 },
                }}
              >
                <CardContent>
                  <Stack direction="row" alignItems="center" justifyContent="space-between" mb={1}>
                    <Typography variant="h6" fontWeight={700}>
                      Описание хоста
                    </Typography>
                    {!hostNotesEditOpen && (
                      <IconButton
                        size="small"
                        aria-label="Редактировать описание хоста"
                        className="host-notes-edit-btn"
                        onClick={startHostNotesEdit}
                        sx={{ opacity: 0, transition: "opacity .15s ease" }}
                      >
                        <EditIcon fontSize="small" />
                      </IconButton>
                    )}
                  </Stack>
                  {hostNotesEditOpen ? (
                    <Stack spacing={1.5}>
                      <MarkdownEditor
                        label="Описание хоста"
                        showLabel={false}
                        minRows={4}
                        value={editingHostNotes}
                        onChange={(next) => setEditingHostNotes(next || "")}
                      />
                      <Stack direction="row" spacing={1} justifyContent="flex-end">
                        <Button onClick={cancelHostNotesEdit} disabled={hostNotesSaving}>
                          Отмена
                        </Button>
                        <Button
                          variant="contained"
                          onClick={() => void submitHostNotes()}
                          disabled={hostNotesSaving}
                        >
                          Сохранить
                        </Button>
                      </Stack>
                    </Stack>
                  ) : (
                    <Box sx={{ border: "1px solid rgba(126,224,255,0.12)", p: 2, borderRadius: 0, backgroundColor: "rgba(8,17,31,0.28)" }}>
                      {host?.notes?.trim() ? (
                        <ReactMarkdown urlTransform={markdownUrlTransform} components={{ img: MarkdownImage }}>
                          {normalizeMarkdownForRender(host.notes)}
                        </ReactMarkdown>
                      ) : (
                        <Typography color="text.secondary">Описание хоста не заполнено</Typography>
                      )}
                    </Box>
                  )}
                </CardContent>
              </Card>
            </Stack>
          )}

          {selectedSection === "ports" && (
            <Card sx={{ border: "1px solid rgba(126,224,255,0.14)" }}>
              <CardContent>
                <Stack direction="row" alignItems="center" justifyContent="space-between" mb={1}>
                  <Typography variant="h6" fontWeight={700}>
                    IP-адреса
                  </Typography>
                  <Stack direction="row" alignItems="center" spacing={0.5}>
                    {ipBulkDeleteMode && selectedIpIds.size > 0 ? (
                      <Tooltip title="Удалить выбранные IP">
                        <span>
                          <Button
                            size="small"
                            color="error"
                            variant="outlined"
                            startIcon={<DeleteIcon fontSize="small" />}
                            disabled={bulkDeletingIps}
                            onClick={() => void removeSelectedIps()}
                          >
                            Удалить ({selectedIpIds.size})
                          </Button>
                        </span>
                      </Tooltip>
                    ) : null}
                    {ipBulkDeleteMode ? (
                      <Button
                        size="small"
                        variant="outlined"
                        disabled={bulkDeletingIps}
                        onClick={() => {
                          setIpBulkDeleteMode(false);
                          setSelectedIpIds(new Set());
                        }}
                      >
                        Отменить
                      </Button>
                    ) : null}
                    <Tooltip title="Действия">
                      <span>
                        <IconButton
                          size="small"
                          onClick={(event) => setPortsSectionMenuAnchorEl(event.currentTarget)}
                          disabled={nmapImporting}
                          sx={{ color: "text.secondary", "&:hover": { backgroundColor: "rgba(126,224,255,0.08)", color: "text.primary" } }}
                        >
                          <MoreVertIcon fontSize="small" />
                        </IconButton>
                      </span>
                    </Tooltip>
                  </Stack>
                  <Menu
                    anchorEl={portsSectionMenuAnchorEl}
                    open={portsSectionMenuOpen}
                    onClose={closePortsSectionMenu}
                    anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
                    transformOrigin={{ vertical: "top", horizontal: "right" }}
                  >
                    <MenuItem
                      disabled={nmapImporting || !host?.ip_addresses.length}
                      onClick={() => {
                        closePortsSectionMenu();
                        const primaryIp = host?.ip_addresses.find((ip) => ip.is_primary) ?? host?.ip_addresses[0];
                        setNmapImportIpId(primaryIp?.id ?? "");
                        setNmapImportOpen(true);
                      }}
                    >
                      <UploadFileIcon fontSize="small" sx={{ mr: 1 }} />
                      Импортировать из Nmap
                    </MenuItem>
                    <MenuItem
                      disabled={!host?.ip_addresses.length}
                      onClick={() => {
                        closePortsSectionMenu();
                        cancelServiceBulkDelete();
                        setSelectedIpIds(new Set());
                        setIpBulkDeleteMode(true);
                      }}
                    >
                      <DeleteOutlineIcon fontSize="small" sx={{ mr: 1 }} />
                      Выбрать IP для удаления
                    </MenuItem>
                  </Menu>
                </Stack>
                <Stack spacing={1}>
                  {host?.ip_addresses.map((ip) => {
                    const isIpExpanded = expandedIpIds.includes(ip.id);
                    return (
                      <Stack
                        key={ip.id}
                        sx={{
                          border: "1px solid rgba(126,224,255,0.18)",
                          borderRadius: 0,
                          backgroundColor: "rgba(8,17,31,0.32)",
                        }}
                      >
                        <Stack
                          direction="row"
                          alignItems="center"
                          justifyContent="space-between"
                          onClick={() => {
                            if (ipBulkDeleteMode) return;
                            toggleExpandedId(ip.id, setExpandedIpIds);
                          }}
                          sx={{ p: 1.4, cursor: ipBulkDeleteMode ? "default" : "pointer" }}
                        >
                          <Stack direction="row" spacing={1.2} alignItems="center" sx={{ minWidth: 0 }}>
                            {ipBulkDeleteMode ? (
                              <Checkbox
                                size="small"
                                checked={selectedIpIds.has(ip.id)}
                                onClick={(event) => event.stopPropagation()}
                                onChange={() => toggleIpSelection(ip.id)}
                                sx={{ p: 0.25 }}
                              />
                            ) : (
                              <ExpandMoreIcon
                                fontSize="small"
                                sx={{
                                  transform: isIpExpanded ? "rotate(0deg)" : "rotate(-90deg)",
                                  transition: "transform 0.15s ease-in-out",
                                  color: "text.secondary",
                                }}
                              />
                            )}
                            <Typography fontWeight={700}>{ip.ip_address}</Typography>
                            {ip.label ? (
                              <Typography variant="caption" color="text.secondary">
                                {ip.label}
                              </Typography>
                            ) : null}
                          </Stack>
                          <Typography variant="caption" color="text.secondary">
                            {ip.ports.length} {ip.ports.length === 1 ? "порт" : ip.ports.length >= 2 && ip.ports.length <= 4 ? "порта" : "портов"}
                          </Typography>
                        </Stack>
                        <Collapse in={isIpExpanded} timeout="auto" unmountOnExit>
                          <Stack spacing={1} sx={{ px: 1.4, pb: 1.4 }}>
                            {ip.ports.map((port) => {
                              const portService = servicesByPortId[port.id]?.[0] ?? null;
                              return (
                                <Stack
                                  key={port.id}
                                  direction="row"
                                  justifyContent="space-between"
                                  alignItems="center"
                                  sx={{
                                    border: "1px solid rgba(126,224,255,0.12)",
                                    p: 1.2,
                                    borderRadius: 0,
                                    backgroundColor: "rgba(8,17,31,0.24)",
                                    "& .port-actions": {
                                      opacity: 0,
                                      pointerEvents: "none",
                                      transition: "opacity 0.15s ease-in-out",
                                    },
                                    "&:hover .port-actions": {
                                      opacity: 1,
                                      pointerEvents: "auto",
                                    },
                                  }}
                                >
                                  <Stack direction="row" spacing={1} alignItems="center" sx={{ flexWrap: "wrap", rowGap: 0.5 }}>
                                    {portBulkDeleteMode ? (
                                      <Checkbox
                                        size="small"
                                        checked={selectedPortIds.has(port.id)}
                                        onClick={(event) => event.stopPropagation()}
                                        onChange={() => togglePortSelection(port.id)}
                                        sx={{ p: 0.25, mr: -0.5 }}
                                      />
                                    ) : null}
                                    <Typography fontWeight={600}>
                                      {port.port_number}/{port.protocol}
                                    </Typography>
                                    <Chip label={port.state} size="small" />
                                    {portService ? (
                                      <Chip
                                        label={portService.version ? `${portService.name} ${portService.version}` : portService.name}
                                        size="small"
                                        variant="outlined"
                                        sx={{
                                          borderColor: "rgba(126,224,255,0.32)",
                                          color: "text.primary",
                                        }}
                                      />
                                    ) : null}
                                  </Stack>
                                  <Stack direction="row" spacing={0.4} className="port-actions" alignItems="center">
                                    <Tooltip title="Действия">
                                      <IconButton size="small" onClick={(event) => openPortActions(event, port)}>
                                        <MoreVertIcon fontSize="small" />
                                      </IconButton>
                                    </Tooltip>
                                  </Stack>
                                </Stack>
                              );
                            })}
                            {ip.ports.length === 0 ? (
                              <Typography variant="caption" color="text.secondary">
                                На этом IP-адресе портов пока нет.
                              </Typography>
                            ) : null}
                            <Button
                              size="small"
                              variant="text"
                              startIcon={<AddIcon fontSize="small" />}
                              onClick={(event) => {
                                event.stopPropagation();
                                openCreatePortDialogForIp(ip.id);
                              }}
                              sx={{ alignSelf: "flex-start", color: "text.secondary" }}
                            >
                              Добавить порт
                            </Button>
                          </Stack>
                        </Collapse>
                      </Stack>
                    );
                  })}
                  {!host?.ip_addresses.length && (
                    <Typography color="text.secondary">
                      У хоста нет IP-адресов. Добавьте IP в разделе «IP-адреса», чтобы создавать порты.
                    </Typography>
                  )}
                </Stack>
                <Menu
                  anchorEl={portActionsAnchorEl}
                  open={portActionsOpen}
                  onClose={closePortActions}
                  anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
                  transformOrigin={{ vertical: "top", horizontal: "right" }}
                >
                  <MenuItem
                    onClick={() => {
                      if (activePort) {
                        openPortEdit(activePort);
                      }
                      closePortActions();
                    }}
                  >
                    <EditIcon fontSize="small" sx={{ mr: 1 }} />
                    Редактировать порт
                  </MenuItem>
                  <MenuItem
                    onClick={() => {
                      if (activePort) {
                        void removeSinglePort(activePort);
                      }
                      closePortActions();
                    }}
                  >
                    <DeleteOutlineIcon fontSize="small" sx={{ mr: 1 }} />
                    Удалить порт
                  </MenuItem>
                </Menu>
              </CardContent>
            </Card>
          )}

          {selectedSection === "endpoints" && (
            <Card sx={{ border: "1px solid rgba(126,224,255,0.14)" }}>
              <CardContent>
                <Stack direction="row" alignItems="center" justifyContent="space-between" mb={1}>
                  <Typography variant="h6" fontWeight={700}>
                    Эндпоинты
                  </Typography>
                  <Stack direction="row" alignItems="center" spacing={0.5}>
                    {endpointBulkDeleteMode && selectedEndpointIds.size > 0 ? (
                      <Tooltip title="Удалить выбранные эндпоинты">
                        <span>
                          <Button
                            size="small"
                            color="error"
                            variant="outlined"
                            data-endpoint-bulk-delete="true"
                            startIcon={<DeleteIcon fontSize="small" />}
                            disabled={bulkDeletingEndpoints}
                            onClick={() => {
                              void removeSelectedEndpoints();
                            }}
                          >
                            Удалить ({selectedEndpointIds.size})
                          </Button>
                        </span>
                      </Tooltip>
                    ) : null}
                    {endpointBulkDeleteMode && selectedEndpointIds.size === 0 ? (
                      <Button
                        size="small"
                        variant="outlined"
                        onClick={() => {
                          setEndpointBulkDeleteMode(false);
                          setSelectedEndpointIds(new Set());
                        }}
                      >
                        Отменить
                      </Button>
                    ) : null}
                    <Tooltip title="Действия с эндпоинтами">
                      <span>
                        <IconButton
                          size="small"
                          onClick={(event) => setEndpointsMenuAnchorEl(event.currentTarget)}
                          disabled={swaggerImporting || swaggerExporting}
                          sx={{ color: "text.secondary", "&:hover": { backgroundColor: "rgba(126,224,255,0.08)", color: "text.primary" } }}
                        >
                          <MoreVertIcon fontSize="small" />
                        </IconButton>
                      </span>
                    </Tooltip>
                  </Stack>
                  <input
                    ref={swaggerImportInputRef}
                    hidden
                    type="file"
                    accept="application/json,.json,.yaml,.yml,text/yaml,application/yaml"
                    onChange={(event) => {
                      const selectedFile = event.target.files?.[0] ?? null;
                      void importEndpointsFromSwaggerFile(selectedFile);
                      event.target.value = "";
                    }}
                  />
                  <Menu
                    anchorEl={endpointsMenuAnchorEl}
                    open={endpointsMenuOpen}
                    onClose={closeEndpointsMenu}
                    anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
                    transformOrigin={{ vertical: "top", horizontal: "right" }}
                  >
                    <MenuItem
                      onClick={() => {
                        closeEndpointsMenu();
                        openCreateEndpointDialog();
                      }}
                    >
                      <AddIcon fontSize="small" sx={{ mr: 1 }} />
                      Добавить эндпоинт
                    </MenuItem>
                    <MenuItem
                      disabled={swaggerImporting}
                      onClick={() => {
                        closeEndpointsMenu();
                        swaggerImportInputRef.current?.click();
                      }}
                    >
                      <UploadFileIcon fontSize="small" sx={{ mr: 1 }} />
                      Импортировать Swagger/OpenAPI
                    </MenuItem>
                    <MenuItem
                      disabled={swaggerExporting || !normalizedHostEndpoints.length}
                      onClick={() => {
                        closeEndpointsMenu();
                        void exportEndpointsToSwaggerFile();
                      }}
                    >
                      <DownloadIcon fontSize="small" sx={{ mr: 1 }} />
                      Экспортировать Swagger/OpenAPI
                    </MenuItem>
                    <MenuItem
                      data-endpoint-delete-mode-item="true"
                      disabled={!normalizedHostEndpoints.length}
                      onClick={() => {
                        closeEndpointsMenu();
                        setEndpointBulkDeleteMode(true);
                      }}
                    >
                      <DeleteOutlineIcon fontSize="small" sx={{ mr: 1 }} />
                      Выбрать эндпоинты для удаления
                    </MenuItem>
                  </Menu>
                </Stack>
                <Stack spacing={1.25}>
                  {normalizedHostEndpoints.length ? renderEndpointPathTree(endpointPathTree) : null}
                  {!normalizedHostEndpoints.length && <Typography color="text.secondary">Эндпоинты для этого хоста пока не добавлены.</Typography>}
                </Stack>
                <Menu
                  anchorEl={endpointActionsAnchorEl}
                  open={endpointActionsOpen}
                  onClose={closeEndpointActions}
                  anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
                  transformOrigin={{ vertical: "top", horizontal: "right" }}
                >
                  <MenuItem
                    onClick={() => {
                      if (activeEndpoint) {
                        openEndpointEdit(activeEndpoint);
                      }
                      closeEndpointActions();
                    }}
                  >
                    <EditIcon fontSize="small" sx={{ mr: 1 }} />
                    Редактировать
                  </MenuItem>
                  <MenuItem
                    onClick={() => {
                      if (activeEndpoint) {
                        void removeEndpoint(activeEndpoint.id);
                      }
                      closeEndpointActions();
                    }}
                  >
                    <DeleteIcon fontSize="small" sx={{ mr: 1 }} />
                    Удалить
                  </MenuItem>
                  <MenuItem onClick={() => void copyEndpointRequest("curl")}>
                    <ContentCopyIcon fontSize="small" sx={{ mr: 1 }} />
                    Скопировать как cURL
                  </MenuItem>
                  <MenuItem onClick={() => void copyEndpointRequest("raw")}>
                    <ContentCopyIcon fontSize="small" sx={{ mr: 1 }} />
                    Скопировать как Raw
                  </MenuItem>
                </Menu>
              </CardContent>
            </Card>
          )}

          {selectedSection === "vulns" &&
            (isVulnerabilityRoute ? (
              <Stack spacing={3}>
                <Card sx={{ border: "1px solid rgba(126,224,255,0.16)", backgroundColor: "rgba(15,27,45,0.82)" }}>
                  <CardContent>
                    <Stack direction={{ xs: "column", sm: "row" }} justifyContent="space-between" alignItems={{ sm: "center" }} spacing={1} mb={2}>
                      <Button startIcon={<ArrowBackIcon />} onClick={closeVulnerabilityView}>
                        Назад
                      </Button>
                      <Tooltip title="Редактировать">
                        <span>
                          <IconButton
                            size="small"
                            onClick={() => setVulnEditMode(true)}
                            disabled={vulnEditMode}
                            sx={{ color: "text.secondary", "&:hover": { backgroundColor: "rgba(126,224,255,0.08)", color: "text.primary" } }}
                          >
                            <EditIcon fontSize="small" />
                          </IconButton>
                        </span>
                      </Tooltip>
                    </Stack>
                    {renderVulnerabilityDetailsContent()}
                  </CardContent>
                </Card>
                <Card sx={{ border: "1px solid rgba(126,224,255,0.16)", backgroundColor: "rgba(15,27,45,0.82)" }}>
                  <CardContent>{renderCommentsSection()}</CardContent>
                </Card>
              </Stack>
            ) : (
            <Card sx={{ border: "1px solid rgba(126,224,255,0.14)" }}>
              <CardContent>
                <Stack direction="row" alignItems="center" justifyContent="space-between" mb={1}>
                  <Typography variant="h6" fontWeight={700}>
                    Уязвимости хоста
                  </Typography>
                  <Stack direction="row" alignItems="center" spacing={0.5}>
                    {vulnerabilityBulkDeleteMode && selectedVulnerabilityIds.size > 0 ? (
                      <Tooltip title="Удалить выбранные уязвимости">
                        <span>
                          <Button
                            size="small"
                            color="error"
                            variant="outlined"
                            startIcon={<DeleteIcon fontSize="small" />}
                            disabled={bulkDeletingVulnerabilities}
                            onClick={() => void removeSelectedVulnerabilities()}
                          >
                            Удалить ({selectedVulnerabilityIds.size})
                          </Button>
                        </span>
                      </Tooltip>
                    ) : null}
                    {vulnerabilityBulkDeleteMode && selectedVulnerabilityIds.size === 0 ? (
                      <Button
                        size="small"
                        variant="outlined"
                        onClick={() => {
                          setVulnerabilityBulkDeleteMode(false);
                          setSelectedVulnerabilityIds(new Set());
                        }}
                      >
                        Отменить
                      </Button>
                    ) : null}
                    <Tooltip title="Действия с уязвимостями">
                      <span>
                        <IconButton
                          size="small"
                          onClick={(event) => setVulnerabilitiesSectionMenuAnchorEl(event.currentTarget)}
                          sx={{ color: "text.secondary", "&:hover": { backgroundColor: "rgba(126,224,255,0.08)", color: "text.primary" } }}
                        >
                          <MoreVertIcon fontSize="small" />
                        </IconButton>
                      </span>
                    </Tooltip>
                  </Stack>
                  <Menu
                    anchorEl={vulnerabilitiesSectionMenuAnchorEl}
                    open={vulnerabilitiesSectionMenuOpen}
                    onClose={closeVulnerabilitiesSectionMenu}
                    anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
                    transformOrigin={{ vertical: "top", horizontal: "right" }}
                  >
                    <MenuItem
                      onClick={() => {
                        closeVulnerabilitiesSectionMenu();
                        setCreateVulnerabilityOpen(true);
                      }}
                    >
                      <AddIcon fontSize="small" sx={{ mr: 1 }} />
                      Добавить уязвимость (конструктор)
                    </MenuItem>
                    <MenuItem
                      disabled={!vulnerabilities.length}
                      onClick={() => {
                        closeVulnerabilitiesSectionMenu();
                        setVulnerabilityBulkDeleteMode(true);
                      }}
                    >
                      <DeleteOutlineIcon fontSize="small" sx={{ mr: 1 }} />
                      Выбрать уязвимости для удаления
                    </MenuItem>
                  </Menu>
                </Stack>
                <Stack spacing={1}>
                  {vulnerabilities.map((item) => (
                    <Box
                      key={item.id}
                      onClick={() => toggleExpandedId(item.id, setExpandedVulnerabilityIds)}
                      sx={{
                        border: "1px solid rgba(126,224,255,0.12)",
                        p: 1.4,
                        borderRadius: 0,
                        backgroundColor: "rgba(8,17,31,0.24)",
                        cursor: "pointer",
                      }}
                    >
                      <Stack direction="row" justifyContent="space-between" alignItems="center" spacing={1}>
                        <Stack direction="row" spacing={1} alignItems="center" sx={{ minWidth: 0, flex: 1 }}>
                          {vulnerabilityBulkDeleteMode ? (
                            <Checkbox
                              size="small"
                              checked={selectedVulnerabilityIds.has(item.id)}
                              onClick={(event) => event.stopPropagation()}
                              onChange={() => toggleVulnerabilitySelection(item.id)}
                              sx={{ p: 0.25, mr: -0.5 }}
                            />
                          ) : null}
                          <Typography fontWeight={600} sx={{ minWidth: 0 }}>
                            {item.title}
                          </Typography>
                        </Stack>
                      </Stack>
                      <Collapse in={expandedVulnerabilityIds.includes(item.id)} timeout="auto" unmountOnExit>
                        <Stack spacing={1} mt={0.8}>
                          <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                              {item.cwe_id && <Chip size="small" variant="outlined" label={item.cwe_id} />}
                              {item.cvss_version && <Chip size="small" variant="outlined" label={`CVSS ${item.cvss_version} ${item.cvss_score ?? "-"}`} />}
                              <Chip size="small" label={item.severity} sx={severityChipSx[item.severity]} />
                            <Chip size="small" label={item.status} sx={vulnerabilityStatusChipSx[item.status]} />
                          </Stack>
                          <Typography color="text.secondary" variant="body2">
                            {item.impact || "Влияние не указано"}
                          </Typography>
                          <Box>
                            <Button
                              size="small"
                              variant="text"
                              onClick={(event) => {
                                event.stopPropagation();
                                openVulnerabilityPage(item.id);
                              }}
                            >
                              Открыть карточку
                            </Button>
                          </Box>
                        </Stack>
                      </Collapse>
                    </Box>
                  ))}
                  {!vulnerabilities.length && <Typography color="text.secondary">Уязвимости, привязанные к этому хосту, пока не добавлены.</Typography>}
                </Stack>
              </CardContent>
            </Card>
            ))}
        </Stack>
      </Stack>

      <Dialog
        open={noteCreateDialogOpen}
        onClose={() => {
          if (noteCreateBusy) return;
          setNoteCreateDialogOpen(false);
        }}
        fullWidth
        maxWidth="xs"
      >
        <DialogTitle>{noteCreateParentId ? "Новая подстраница" : "Новая страница"}</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            fullWidth
            label="Название"
            value={noteCreateTitle}
            onChange={(e) => setNoteCreateTitle(e.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter" && !event.shiftKey) {
                event.preventDefault();
                void submitNewNote();
              }
            }}
            sx={{ mt: 1 }}
            disabled={noteCreateBusy}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setNoteCreateDialogOpen(false)} disabled={noteCreateBusy}>
            Отмена
          </Button>
          <Button
            variant="contained"
            disabled={noteCreateBusy || !noteCreateTitle.trim()}
            onClick={() => void submitNewNote()}
          >
            Создать
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={isEditHostOpen} onClose={() => setEditHostOpen(false)} fullWidth maxWidth="xs">
        <DialogTitle>Редактировать хост</DialogTitle>
        <DialogContent>
          {/*
            Минимальная форма: только название (hostname) и тип ОС. IP-адреса
            и описание редактируются на самой странице хоста (через troеточие
            IP-таблицы и карандашик при наведении на описание).
          */}
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField
              label="Название"
              value={editingHostName}
              onChange={(event) => setEditingHostName(event.target.value)}
              autoFocus
            />
            <FormControl fullWidth size="small">
              <InputLabel id="host-os-type-label">Тип ОС</InputLabel>
              <Select
                labelId="host-os-type-label"
                label="Тип ОС"
                value={editingHostOsType}
                onChange={(event) => setEditingHostOsType(event.target.value as OsType)}
              >
                {OS_TYPE_OPTIONS.map((option) => (
                  <MenuItem key={option.value} value={option.value}>
                    <Stack direction="row" alignItems="center" spacing={1}>
                      <HostOsIcon os_type={option.value} fontSize="small" />
                      <span>{option.label}</span>
                    </Stack>
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditHostOpen(false)}>Отмена</Button>
          <Button variant="contained" onClick={() => void saveHostInfo()}>
            Сохранить
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={isEditPortOpen} onClose={() => setEditPortOpen(false)} fullWidth>
        <DialogTitle>Редактировать порт</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField
              label="Номер порта"
              type="number"
              inputProps={{ min: 1, max: 65535 }}
              value={editingPortNumber}
              onChange={(event) => setEditingPortNumber(event.target.value)}
            />
            <TextField select label="Протокол" value={editingPortProtocol} onChange={(event) => setEditingPortProtocol(event.target.value as Port["protocol"])}>
              <MenuItem value="tcp">tcp</MenuItem>
              <MenuItem value="udp">udp</MenuItem>
            </TextField>
            <TextField select label="Состояние" value={editingPortState} onChange={(event) => setEditingPortState(event.target.value as Port["state"])}>
              <MenuItem value="open">open</MenuItem>
              <MenuItem value="closed">closed</MenuItem>
              <MenuItem value="filtered">filtered</MenuItem>
            </TextField>
            <Stack direction="row" spacing={1.5}>
              <TextField
                label="Сервис"
                placeholder="например: nginx"
                value={editingPortServiceName}
                onChange={(event) => setEditingPortServiceName(event.target.value)}
                sx={{ flex: 1 }}
              />
              <TextField
                label="Версия"
                placeholder="1.25"
                value={editingPortServiceVersion}
                onChange={(event) => setEditingPortServiceVersion(event.target.value)}
                sx={{ flex: 1 }}
              />
            </Stack>
            <Typography variant="caption" color="text.secondary">
              Очистите поле «Сервис», чтобы удалить сервис с порта.
            </Typography>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditPortOpen(false)}>Отмена</Button>
          <Button variant="contained" onClick={() => void savePortEdit()}>
            Сохранить
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={isCreatePortOpen} onClose={() => setCreatePortOpen(false)} fullWidth>
        <DialogTitle>Добавить порт</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField
              select
              label="IP-адрес"
              value={creatingPortIpId}
              onChange={(event) => setCreatingPortIpId(event.target.value)}
            >
              {(host?.ip_addresses ?? []).map((ip) => (
                <MenuItem key={ip.id} value={ip.id}>
                  {ip.ip_address}
                  {ip.label ? ` (${ip.label})` : ""}
                </MenuItem>
              ))}
            </TextField>
            <TextField
              label="Номер порта"
              type="number"
              inputProps={{ min: 1, max: 65535 }}
              value={creatingPortNumber}
              onChange={(event) => setCreatingPortNumber(event.target.value)}
            />
            <TextField select label="Протокол" value={creatingPortProtocol} onChange={(event) => setCreatingPortProtocol(event.target.value as Port["protocol"])}>
              <MenuItem value="tcp">tcp</MenuItem>
              <MenuItem value="udp">udp</MenuItem>
            </TextField>
            <TextField select label="Состояние" value={creatingPortState} onChange={(event) => setCreatingPortState(event.target.value as Port["state"])}>
              <MenuItem value="open">open</MenuItem>
              <MenuItem value="closed">closed</MenuItem>
              <MenuItem value="filtered">filtered</MenuItem>
            </TextField>
            <Stack direction="row" spacing={1.5}>
              <TextField
                label="Сервис (необязательно)"
                placeholder="например: nginx"
                value={creatingPortServiceName}
                onChange={(event) => setCreatingPortServiceName(event.target.value)}
                sx={{ flex: 1 }}
              />
              <TextField
                label="Версия"
                placeholder="1.25"
                value={creatingPortServiceVersion}
                onChange={(event) => setCreatingPortServiceVersion(event.target.value)}
                sx={{ flex: 1 }}
              />
            </Stack>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreatePortOpen(false)}>Отмена</Button>
          <Button
            variant="contained"
            onClick={() => void createHostPort()}
            disabled={!creatingPortIpId || !creatingPortNumber}
          >
            Создать
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog
        open={isNmapImportOpen}
        onClose={() => {
          if (!nmapImporting) {
            setNmapImportOpen(false);
          }
        }}
        fullWidth
        maxWidth="xs"
      >
        <DialogTitle>Импорт портов из Nmap</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <Typography variant="caption" color="text.secondary">
              Выберите IP-адрес, к которому будут привязаны импортированные порты, и загрузите файл (txt/nmap/gnmap/xml).
            </Typography>
            <TextField
              select
              label="IP-адрес"
              value={nmapImportIpId}
              onChange={(event) => setNmapImportIpId(event.target.value)}
              disabled={nmapImporting}
            >
              {(host?.ip_addresses ?? []).map((ip) => (
                <MenuItem key={ip.id} value={ip.id}>
                  {ip.ip_address}
                  {ip.label ? ` (${ip.label})` : ""}
                </MenuItem>
              ))}
            </TextField>
            <input
              ref={nmapImportFileInputRef}
              hidden
              type="file"
              accept=".txt,.nmap,.gnmap,.xml,text/plain,text/xml,application/xml"
              onChange={(event) => {
                const selectedFile = event.target.files?.[0] ?? null;
                event.target.value = "";
                if (!selectedFile || !nmapImportIpId) {
                  return;
                }
                void (async () => {
                  await importPortsFromNmapFile(selectedFile, nmapImportIpId);
                  setNmapImportOpen(false);
                })();
              }}
            />
            <Button
              variant="outlined"
              startIcon={<UploadFileIcon fontSize="small" />}
              onClick={() => nmapImportFileInputRef.current?.click()}
              disabled={nmapImporting || !nmapImportIpId}
            >
              {nmapImporting ? "Импорт..." : "Выбрать файл и импортировать"}
            </Button>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setNmapImportOpen(false)} disabled={nmapImporting}>
            Закрыть
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={isCreateServiceOpen} onClose={() => setCreateServiceOpen(false)} fullWidth>
        <DialogTitle>Добавить сервис</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField label="Название сервиса" value={creatingServiceName} onChange={(event) => setCreatingServiceName(event.target.value)} />
            <TextField label="Версия" value={creatingServiceVersion} onChange={(event) => setCreatingServiceVersion(event.target.value)} />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateServiceOpen(false)}>Отмена</Button>
          <Button variant="contained" onClick={() => void createPortService()} disabled={!creatingServiceName.trim()}>
            Создать
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={isEditServiceOpen} onClose={() => setEditServiceOpen(false)} fullWidth>
        <DialogTitle>Редактировать сервис</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField label="Название сервиса" value={editingServiceName} onChange={(event) => setEditingServiceName(event.target.value)} />
            <TextField label="Версия" value={editingServiceVersion} onChange={(event) => setEditingServiceVersion(event.target.value)} />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditServiceOpen(false)}>Отмена</Button>
          <Button variant="contained" onClick={() => void saveServiceEdit()} disabled={!editingServiceName.trim()}>
            Сохранить
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={isEditEndpointOpen} onClose={() => setEditEndpointOpen(false)} fullWidth maxWidth="md">
        <DialogTitle>Редактировать эндпоинт</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <Stack spacing={1}>
              <TextField
                multiline
                minRows={4}
                label="Вставить Raw HTTP запрос"
                value={editingEndpointImportRaw}
                onChange={(event) => setEditingEndpointImportRaw(event.target.value)}
              />
            </Stack>
            <Divider />
            {editingEndpointImportHostWarn && (
              <Alert severity="warning">
                Заголовок Host из запроса не совпадает с хостом актива ({endpointFormHostLine}). Проверьте путь и целевой хост.
              </Alert>
            )}
            <TextField label="Путь" value={editingEndpointPath} onChange={(event) => setEditingEndpointPath(event.target.value)} />
            <TextField
              select
              label="HTTP-метод"
              value={editingEndpointMethod}
              onChange={(event) => {
                const next = event.target.value as Exclude<Endpoint["method"], null>;
                setEditingEndpointMethod(next);
                if (next === "POST") {
                  setEditingEndpointQueryString("");
                }
                if (!methodSupportsRequestBody(next)) {
                  setEditingEndpointRequestBody("");
                  setEditingEndpointRequestContentType("application/json");
                }
              }}
            >
              {["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map((method) => (
                <MenuItem key={method} value={method}>
                  {method}
                </MenuItem>
              ))}
            </TextField>
            {methodShowsQueryString(editingEndpointMethod) && (
              <TextField
                multiline
                minRows={2}
                label="Параметры запроса (query string)"
                value={editingEndpointQueryString}
                onChange={(event) => setEditingEndpointQueryString(event.target.value)}
              />
            )}
            <TextField
              multiline
              minRows={4}
              label="Заголовки"
              value={editingEndpointHeadersText}
              onChange={(event) => setEditingEndpointHeadersText(event.target.value)}
              sx={{ "& textarea": { fontFamily: "ui-monospace, monospace", fontSize: "0.85rem" } }}
            />
            {methodSupportsRequestBody(editingEndpointMethod) && (
              <>
                <TextField
                  select
                  label="Content-Type"
                  value={editingEndpointRequestContentType}
                  onChange={(event) => setEditingEndpointRequestContentType(event.target.value)}
                >
                  {["application/json", "application/x-www-form-urlencoded", "multipart/form-data", "text/plain", "application/xml"].map(
                    (contentType) => (
                      <MenuItem key={contentType} value={contentType}>
                        {contentType}
                      </MenuItem>
                    )
                  )}
                </TextField>
                <TextField
                  multiline
                  minRows={6}
                  label="Тело запроса"
                  value={editingEndpointRequestBody}
                  onChange={(event) => setEditingEndpointRequestBody(event.target.value)}
                />
              </>
            )}
            <Paper variant="outlined" sx={{ p: 1.5, borderColor: "rgba(126,224,255,0.14)" }}>
              <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 1 }}>
                Предпросмотр Raw HTTP
              </Typography>
              <Box
                component="pre"
                sx={{
                  m: 0,
                  maxHeight: 220,
                  overflow: "auto",
                  fontSize: "0.75rem",
                  fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                }}
              >
                {editingEndpointPreviewRequest}
              </Box>
              <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap sx={{ mt: 1.5 }}>
                <Button size="small" variant="outlined" onClick={() => void copyEditingEndpointDraft("raw")}>
                  Скопировать как Raw
                </Button>
                <Button size="small" variant="outlined" onClick={() => void copyEditingEndpointDraft("curl")}>
                  Скопировать как cURL
                </Button>
              </Stack>
            </Paper>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditEndpointOpen(false)}>Отмена</Button>
          <Button variant="contained" onClick={() => void saveEndpointEdit()} disabled={!editingEndpointPath.trim()}>
            Сохранить
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={isCreateEndpointOpen} onClose={() => setCreateEndpointOpen(false)} fullWidth maxWidth="md">
        <DialogTitle>Добавить эндпоинт</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <Stack spacing={1}>
              <TextField
                multiline
                minRows={4}
                label="Вставить Raw HTTP запрос"
                value={creatingEndpointImportRaw}
                onChange={(event) => setCreatingEndpointImportRaw(event.target.value)}
              />
            </Stack>
            <Divider />
            {creatingEndpointImportHostWarn && (
              <Alert severity="warning">
                Заголовок Host из запроса не совпадает с хостом актива ({endpointFormHostLine}). Проверьте путь и целевой хост.
              </Alert>
            )}
            <TextField label="Путь" value={creatingEndpointPath} onChange={(event) => setCreatingEndpointPath(event.target.value)} />
            <TextField
              select
              label="HTTP-метод"
              value={creatingEndpointMethod}
              onChange={(event) => {
                const next = event.target.value as Exclude<Endpoint["method"], null>;
                setCreatingEndpointMethod(next);
                if (next === "POST") {
                  setCreatingEndpointQueryString("");
                }
                if (!methodSupportsRequestBody(next)) {
                  setCreatingEndpointRequestBody("");
                  setCreatingEndpointRequestContentType("application/json");
                }
              }}
            >
              {["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map((method) => (
                <MenuItem key={method} value={method}>
                  {method}
                </MenuItem>
              ))}
            </TextField>
            {methodShowsQueryString(creatingEndpointMethod) && (
              <TextField
                multiline
                minRows={2}
                label="Параметры запроса (query string)"
                value={creatingEndpointQueryString}
                onChange={(event) => setCreatingEndpointQueryString(event.target.value)}
              />
            )}
            <TextField
              multiline
              minRows={4}
              label="Заголовки"
              value={creatingEndpointHeadersText}
              onChange={(event) => setCreatingEndpointHeadersText(event.target.value)}
              sx={{ "& textarea": { fontFamily: "ui-monospace, monospace", fontSize: "0.85rem" } }}
            />
            {methodSupportsRequestBody(creatingEndpointMethod) && (
              <>
                <TextField
                  select
                  label="Content-Type"
                  value={creatingEndpointRequestContentType}
                  onChange={(event) => setCreatingEndpointRequestContentType(event.target.value)}
                >
                  {["application/json", "application/x-www-form-urlencoded", "multipart/form-data", "text/plain", "application/xml"].map(
                    (contentType) => (
                      <MenuItem key={contentType} value={contentType}>
                        {contentType}
                      </MenuItem>
                    )
                  )}
                </TextField>
                <TextField
                  multiline
                  minRows={6}
                  label="Тело запроса"
                  value={creatingEndpointRequestBody}
                  onChange={(event) => setCreatingEndpointRequestBody(event.target.value)}
                />
              </>
            )}
            <Paper variant="outlined" sx={{ p: 1.5, borderColor: "rgba(126,224,255,0.14)" }}>
              <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 1 }}>
                Предпросмотр Raw HTTP
              </Typography>
              <Box
                component="pre"
                sx={{
                  m: 0,
                  maxHeight: 220,
                  overflow: "auto",
                  fontSize: "0.75rem",
                  fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                }}
              >
                {creatingEndpointPreviewRequest}
              </Box>
              <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap sx={{ mt: 1.5 }}>
                <Button size="small" variant="outlined" onClick={() => void copyCreatingEndpointDraft("raw")}>
                  Скопировать как Raw
                </Button>
                <Button size="small" variant="outlined" onClick={() => void copyCreatingEndpointDraft("curl")}>
                  Скопировать как cURL
                </Button>
              </Stack>
            </Paper>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateEndpointOpen(false)}>Отмена</Button>
          <Button variant="contained" onClick={() => void createHostEndpoint()} disabled={!creatingEndpointPath.trim()}>
            Создать
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={!isVulnerabilityRoute && vulnDetailOpen} onClose={closeVulnerabilityView} fullWidth maxWidth="lg">
        <DialogTitle>Карточка уязвимости</DialogTitle>
        <DialogContent>
          <Stack spacing={3} sx={{ mt: 0.5 }}>
            {renderVulnerabilityDetailsContent()}
            <Divider />
            {renderCommentsSection()}
          </Stack>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 3, pt: 1.5 }}>
          <Button onClick={closeVulnerabilityView}>Закрыть</Button>
          {!vulnEditMode && (
            <Tooltip title="Редактировать">
              <span>
                <IconButton
                  onClick={() => setVulnEditMode(true)}
                  disabled={!activeVulnDetails}
                  sx={{ color: "text.secondary", "&:hover": { backgroundColor: "rgba(126,224,255,0.08)", color: "text.primary" } }}
                >
                  <EditIcon fontSize="small" />
                </IconButton>
              </span>
            </Tooltip>
          )}
        </DialogActions>
      </Dialog>

      <Dialog open={editCommentOpen} onClose={() => setEditCommentOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>Редактировать комментарий</DialogTitle>
        <DialogContent>
          <TextField
            fullWidth
            multiline
            minRows={4}
            sx={{ mt: 1 }}
            value={editingCommentContent}
            onChange={(event) => setEditingCommentContent(event.target.value)}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditCommentOpen(false)}>Отмена</Button>
          <Button variant="contained" onClick={() => void saveCommentEdit()} disabled={!editingCommentContent.trim() || vulnBusy}>
            Сохранить
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={isEditVulnerabilityOpen} onClose={() => setEditVulnerabilityOpen(false)} fullWidth>
        <DialogTitle>Редактировать уязвимость</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField label="Название" value={editingVulnerabilityTitle} onChange={(event) => setEditingVulnerabilityTitle(event.target.value)} />
            <MarkdownEditor
              minRows={3}
              label="Описание"
              value={editingVulnerabilityDescription}
              onChange={(next) => setEditingVulnerabilityDescription(next || "")}
            />
            <TextField
              select
              label="Критичность"
              value={editingVulnerabilitySeverity}
              onChange={(event) => setEditingVulnerabilitySeverity(event.target.value as Vulnerability["severity"])}
            >
              <MenuItem value="critical">critical</MenuItem>
              <MenuItem value="high">high</MenuItem>
              <MenuItem value="medium">medium</MenuItem>
              <MenuItem value="low">low</MenuItem>
              <MenuItem value="info">info</MenuItem>
            </TextField>
            <TextField
              select
              label="Статус"
              value={editingVulnerabilityStatus}
              onChange={(event) => setEditingVulnerabilityStatus(event.target.value as Vulnerability["status"])}
            >
              <MenuItem value="open">open</MenuItem>
              <MenuItem value="in_progress">in_progress</MenuItem>
              <MenuItem value="fixed">fixed</MenuItem>
              <MenuItem value="wont_fix">wont_fix</MenuItem>
              <MenuItem value="accepted_risk">accepted_risk</MenuItem>
            </TextField>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditVulnerabilityOpen(false)}>Отмена</Button>
          <Button variant="contained" onClick={() => void saveVulnerabilityEdit()} disabled={!editingVulnerabilityTitle.trim()}>
            Сохранить
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={isCreateVulnerabilityOpen} onClose={() => setCreateVulnerabilityOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>Новая уязвимость</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <Typography variant="body2" color="text.secondary">
              Укажите название — после создания откроется карточка, где можно заполнить остальные поля.
            </Typography>
            <TextField
              label="Название"
              value={creatingVulnerabilityTitle}
              onChange={(event) => setCreatingVulnerabilityTitle(event.target.value)}
              fullWidth
              autoFocus
            />
          </Stack>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 3, pt: 1.5 }}>
          <Button onClick={() => setCreateVulnerabilityOpen(false)}>Отмена</Button>
          <Button variant="contained" size="large" sx={{ minWidth: 180 }} onClick={() => void createHostVulnerability()} disabled={!creatingVulnerabilityTitle.trim()}>
            Создать и открыть карточку
          </Button>
        </DialogActions>
      </Dialog>
    </Stack>
  );
}
