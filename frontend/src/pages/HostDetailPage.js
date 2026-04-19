import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import DeleteIcon from "@mui/icons-material/Delete";
import DeleteOutlineIcon from "@mui/icons-material/DeleteOutline";
import EditIcon from "@mui/icons-material/Edit";
import AddIcon from "@mui/icons-material/Add";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import MoreVertIcon from "@mui/icons-material/MoreVert";
import UploadFileIcon from "@mui/icons-material/UploadFile";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import { Alert, Avatar, Box, Button, Card, CardContent, Chip, Collapse, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, Divider, Grid2 as Grid, IconButton, List, ListItem, Menu, MenuItem, Paper, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Tooltip, Typography, } from "@mui/material";
import { useCallback, useEffect, useMemo, useState } from "react";
import ReactMarkdown from "react-markdown";
import { useLocation, useNavigate, useParams } from "react-router-dom";
import { createVulnerabilityComment, createEndpoint, createPort, createService, createVulnerability, deleteVulnerabilityComment, deleteEndpoint, deleteHost, deletePort, deleteService, deleteVulnerability, getVulnerability, getApiErrorMessage, getServices, getHost, getHosts, getHostVulnerabilities, importOpenApiFile, listVulnerabilityComments, updateEndpoint, updateHost, updatePort, updateService, updateVulnerabilityComment, updateVulnerability, uploadVulnerabilityFile, } from "../api";
import { calculateCvssScore, severityFromCvssScore } from "../cvss";
import { ProjectTreeNav } from "../components/ProjectTreeNav";
import { VulnerabilityStagesEditor } from "../components/VulnerabilityStagesEditor";
import { useAuthStore } from "../store";
import { useErrorToast, useToastMessage } from "../useErrorToast";
/** Swagger UI–style colors for HTTP methods */
const SWAGGER_METHOD_COLORS = {
    GET: { main: "#61affe", contrast: "#fff" },
    POST: { main: "#49cc90", contrast: "#fff" },
    PUT: { main: "#fca130", contrast: "#fff" },
    PATCH: { main: "#50e3c2", contrast: "#0d1b12" },
    DELETE: { main: "#f93e3e", contrast: "#fff" },
    HEAD: { main: "#9012fe", contrast: "#fff" },
    OPTIONS: { main: "#0d5aa7", contrast: "#fff" },
};
const CVSS_VERSION = "4.0";
const UUID_PATH_SEGMENT_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function swaggerMethodColors(method) {
    const key = (method || "GET").toUpperCase();
    return SWAGGER_METHOD_COLORS[key] ?? { main: "rgba(100,116,139,0.85)", contrast: "#fff" };
}
function formatRequestBodyPreview(body) {
    if (!body?.trim()) {
        return "";
    }
    try {
        return JSON.stringify(JSON.parse(body), null, 2);
    }
    catch {
        return body;
    }
}
function normalizeEndpointQueryParams(params) {
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
function queryStringToQueryParams(raw) {
    const t = raw.trim();
    if (!t) {
        return [];
    }
    const parts = t
        .split(/[&\n\r]+/)
        .map((p) => p.trim())
        .filter(Boolean);
    const out = [];
    for (const part of parts) {
        const eq = part.indexOf("=");
        if (eq === -1) {
            out.push({ name: part, value: "", required: false, description: "" });
        }
        else {
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
function queryParamsToQueryString(params) {
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
function methodSupportsRequestBody(method) {
    return method === "POST" || method === "PUT" || method === "PATCH";
}
function methodShowsQueryString(method) {
    return method !== "POST";
}
function normalizeHostForCompare(value) {
    return value.trim().toLowerCase().replace(/:\d+$/, "");
}
function hostTokensMismatch(sourceHost, assetHost) {
    if (!sourceHost?.trim() || !assetHost?.trim()) {
        return false;
    }
    return normalizeHostForCompare(sourceHost) !== normalizeHostForCompare(assetHost);
}
function parsePathAndQueryFromToken(pathToken) {
    const t = pathToken.trim();
    const toParams = (searchParams) => {
        const params = [];
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
        return { path: u.pathname || "/", queryParams: toParams(u.searchParams) };
    }
    const fake = `http://stub.local${t.startsWith("/") ? t : `/${t}`}`;
    const u = new URL(fake);
    return { path: u.pathname || "/", queryParams: toParams(u.searchParams) };
}
function sanitizeEndpointHeaderPairs(pairs) {
    const out = [];
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
function parseHeaderTextToPairs(text) {
    const out = [];
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
function parseHeaderTextToSanitizedList(text) {
    return sanitizeEndpointHeaderPairs(parseHeaderTextToPairs(text));
}
function headersArrayToText(headers) {
    if (!headers?.length) {
        return "";
    }
    return headers.map((h) => `${h.name}: ${h.value}`).join("\n");
}
function escapeForCurlDoubleQuotes(s) {
    return s.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\r?\n/g, "\\n");
}
function buildDraftCurlLine({ method, path, queryString, requestBody, requestContentType, requestHeaders, hostTarget, }) {
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
function parseRawHttpRequest(rawRequest) {
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
    const method = requestLineMatch[1].toUpperCase();
    const { path, queryParams } = parsePathAndQueryFromToken(requestLineMatch[2]);
    const headerPairsRaw = [];
    let requestContentType = "application/json";
    let hostHeaderRaw = null;
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
function normalizeUriPathForTree(p) {
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
function endpointPathToSegments(p) {
    const n = normalizeUriPathForTree(p);
    if (n === "/") {
        return [];
    }
    return n.slice(1).split("/").filter(Boolean);
}
function mergeEndpointForDisplay(base, next) {
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
function dedupeEndpointsByNormalizedPath(endpoints) {
    const deduped = new Map();
    for (const endpoint of endpoints) {
        const normalizedPath = normalizeUriPathForTree(endpoint.path);
        const key = `${(endpoint.method || "GET").toUpperCase()} ${normalizedPath}`;
        const candidate = { ...endpoint, path: normalizedPath };
        const existing = deduped.get(key);
        deduped.set(key, existing ? mergeEndpointForDisplay(existing, candidate) : candidate);
    }
    return Array.from(deduped.values());
}
function buildEndpointPathTree(endpoints) {
    const root = { segment: "", pathKey: "", children: [], endpointsAtNode: [] };
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
    const sortRecursive = (n) => {
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
function collectExpandableFolderKeys(node) {
    const keys = [];
    if (node.pathKey && node.children.length > 0) {
        keys.push(node.pathKey);
    }
    for (const c of node.children) {
        keys.push(...collectExpandableFolderKeys(c));
    }
    return keys;
}
export function HostDetailPage() {
    const { projectId, hostId, vulnerabilityId } = useParams();
    const location = useLocation();
    const navigate = useNavigate();
    const user = useAuthStore((s) => s.user);
    const storagePrefix = projectId && hostId ? `host-detail:${projectId}:${hostId}` : null;
    const highlightedCommentId = new URLSearchParams(location.search).get("comment");
    const isVulnerabilityRoute = Boolean(vulnerabilityId);
    const [host, setHost] = useState(null);
    const [hosts, setHosts] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [infoMessage, setInfoMessage] = useState(null);
    const [vulnerabilities, setVulnerabilities] = useState([]);
    const [selectedSection, setSelectedSection] = useState(isVulnerabilityRoute ? "vulns" : "overview");
    const [isSidebarCollapsed, setSidebarCollapsed] = useState(false);
    const [hostStatsById, setHostStatsById] = useState({});
    const [isEditPortOpen, setEditPortOpen] = useState(false);
    const [editingPortId, setEditingPortId] = useState(null);
    const [editingPortNumber, setEditingPortNumber] = useState("1");
    const [editingPortProtocol, setEditingPortProtocol] = useState("tcp");
    const [editingPortState, setEditingPortState] = useState("open");
    const [servicesByPortId, setServicesByPortId] = useState({});
    const [isCreateServiceOpen, setCreateServiceOpen] = useState(false);
    const [createServicePortId, setCreateServicePortId] = useState(null);
    const [creatingServiceName, setCreatingServiceName] = useState("");
    const [creatingServiceVersion, setCreatingServiceVersion] = useState("");
    const [creatingServiceBanner, setCreatingServiceBanner] = useState("");
    const [isEditServiceOpen, setEditServiceOpen] = useState(false);
    const [editServicePortId, setEditServicePortId] = useState(null);
    const [editingServiceId, setEditingServiceId] = useState(null);
    const [editingServiceName, setEditingServiceName] = useState("");
    const [editingServiceVersion, setEditingServiceVersion] = useState("");
    const [editingServiceBanner, setEditingServiceBanner] = useState("");
    const [isEditEndpointOpen, setEditEndpointOpen] = useState(false);
    const [editingEndpointId, setEditingEndpointId] = useState(null);
    const [editingEndpointPath, setEditingEndpointPath] = useState("");
    const [editingEndpointMethod, setEditingEndpointMethod] = useState("GET");
    const [editingEndpointImportRaw, setEditingEndpointImportRaw] = useState("");
    const [editingEndpointQueryString, setEditingEndpointQueryString] = useState("");
    const [editingEndpointHeadersText, setEditingEndpointHeadersText] = useState("");
    const [editingEndpointImportHostWarn, setEditingEndpointImportHostWarn] = useState(false);
    const [editingEndpointRequestBody, setEditingEndpointRequestBody] = useState("");
    const [editingEndpointRequestContentType, setEditingEndpointRequestContentType] = useState("application/json");
    const [isEditVulnerabilityOpen, setEditVulnerabilityOpen] = useState(false);
    const [editingVulnerabilityId, setEditingVulnerabilityId] = useState(null);
    const [editingVulnerabilityTitle, setEditingVulnerabilityTitle] = useState("");
    const [editingVulnerabilityDescription, setEditingVulnerabilityDescription] = useState("");
    const [editingVulnerabilitySeverity, setEditingVulnerabilitySeverity] = useState("medium");
    const [editingVulnerabilityStatus, setEditingVulnerabilityStatus] = useState("open");
    const [isCreatePortOpen, setCreatePortOpen] = useState(false);
    const [creatingPortNumber, setCreatingPortNumber] = useState("443");
    const [creatingPortProtocol, setCreatingPortProtocol] = useState("tcp");
    const [creatingPortState, setCreatingPortState] = useState("open");
    const [isCreateEndpointOpen, setCreateEndpointOpen] = useState(false);
    const [creatingEndpointPath, setCreatingEndpointPath] = useState("");
    const [creatingEndpointMethod, setCreatingEndpointMethod] = useState("GET");
    const [creatingEndpointImportRaw, setCreatingEndpointImportRaw] = useState("");
    const [creatingEndpointQueryString, setCreatingEndpointQueryString] = useState("");
    const [creatingEndpointHeadersText, setCreatingEndpointHeadersText] = useState("");
    const [creatingEndpointImportHostWarn, setCreatingEndpointImportHostWarn] = useState(false);
    const [creatingEndpointRequestBody, setCreatingEndpointRequestBody] = useState("");
    const [creatingEndpointRequestContentType, setCreatingEndpointRequestContentType] = useState("application/json");
    const [swaggerImporting, setSwaggerImporting] = useState(false);
    const [nmapImporting, setNmapImporting] = useState(false);
    const [isCreateVulnerabilityOpen, setCreateVulnerabilityOpen] = useState(false);
    const [creatingVulnerabilityTitle, setCreatingVulnerabilityTitle] = useState("");
    const [creatingVulnerabilitySeverity, setCreatingVulnerabilitySeverity] = useState("info");
    const [creatingVulnerabilityStatus, setCreatingVulnerabilityStatus] = useState("open");
    const [creatingVulnerabilityCvssScore, setCreatingVulnerabilityCvssScore] = useState("");
    const [creatingVulnerabilityCvssVector, setCreatingVulnerabilityCvssVector] = useState("");
    const [creatingVulnerabilityCweId, setCreatingVulnerabilityCweId] = useState("");
    const [creatingVulnerabilityStages, setCreatingVulnerabilityStages] = useState([]);
    const [creatingVulnerabilityImpact, setCreatingVulnerabilityImpact] = useState("");
    const [creatingVulnerabilityRecommendations, setCreatingVulnerabilityRecommendations] = useState("");
    const [hostActionsAnchorEl, setHostActionsAnchorEl] = useState(null);
    const [isEditHostOpen, setEditHostOpen] = useState(false);
    const [editingHostIp, setEditingHostIp] = useState("");
    const [editingHostName, setEditingHostName] = useState("");
    const [editingHostNotes, setEditingHostNotes] = useState("");
    const [portActionsAnchorEl, setPortActionsAnchorEl] = useState(null);
    const [activePort, setActivePort] = useState(null);
    const [endpointActionsAnchorEl, setEndpointActionsAnchorEl] = useState(null);
    const [activeEndpoint, setActiveEndpoint] = useState(null);
    const [vulnerabilityActionsAnchorEl, setVulnerabilityActionsAnchorEl] = useState(null);
    const [activeVulnerability, setActiveVulnerability] = useState(null);
    const [expandedPortIds, setExpandedPortIds] = useState([]);
    const [expandedEndpointIds, setExpandedEndpointIds] = useState([]);
    const [expandedVulnerabilityIds, setExpandedVulnerabilityIds] = useState([]);
    const normalizedHostEndpoints = useMemo(() => dedupeEndpointsByNormalizedPath(host?.endpoints ?? []), [host?.endpoints]);
    const endpointPathTree = useMemo(() => buildEndpointPathTree(normalizedHostEndpoints), [normalizedHostEndpoints]);
    const [endpointTreeExpandedKeys, setEndpointTreeExpandedKeys] = useState(() => new Set());
    const [vulnDetailOpen, setVulnDetailOpen] = useState(false);
    const [activeVulnDetails, setActiveVulnDetails] = useState(null);
    const [vulnComments, setVulnComments] = useState([]);
    const [newComment, setNewComment] = useState("");
    const [vulnBusy, setVulnBusy] = useState(false);
    const [vulnEditMode, setVulnEditMode] = useState(false);
    const [editCommentOpen, setEditCommentOpen] = useState(false);
    const [editingCommentId, setEditingCommentId] = useState(null);
    const [editingCommentContent, setEditingCommentContent] = useState("");
    const [commentActionsAnchorEl, setCommentActionsAnchorEl] = useState(null);
    const [activeComment, setActiveComment] = useState(null);
    const pendingSection = location.state?.section;
    useErrorToast(error);
    useToastMessage(infoMessage, "success");
    const openHostSection = useCallback((section) => {
        if (!projectId || !hostId) {
            return;
        }
        if (isVulnerabilityRoute) {
            navigate(`/projects/${projectId}/hosts/${hostId}`, { state: { section } });
            return;
        }
        setSelectedSection(section);
    }, [hostId, isVulnerabilityRoute, navigate, projectId]);
    const openVulnerabilityPage = useCallback((targetVulnerabilityId, commentId) => {
        if (!projectId || !hostId) {
            return;
        }
        const query = commentId ? `?comment=${commentId}` : "";
        navigate(`/projects/${projectId}/hosts/${hostId}/vulnerabilities/${targetVulnerabilityId}${query}`, {
            state: { section: "vulns" },
        });
    }, [hostId, navigate, projectId]);
    const loadHost = useCallback(async () => {
        if (!projectId || !hostId) {
            return;
        }
        setLoading(true);
        setError(null);
        try {
            const [hostResponse, hostsResponse, hostVulnsResponse] = await Promise.all([
                getHost(projectId, hostId),
                getHosts(projectId),
                getHostVulnerabilities(projectId, hostId),
            ]);
            setHost(hostResponse);
            setHosts(hostsResponse.items);
            setVulnerabilities(hostVulnsResponse.items);
            const statsEntries = await Promise.allSettled(hostsResponse.items.map(async (listedHost) => {
                if (listedHost.id === hostId) {
                    return [
                        listedHost.id,
                        {
                            portsCount: hostResponse.ports.length,
                            endpointsCount: hostResponse.endpoints.length,
                            vulnerabilitiesCount: hostVulnsResponse.items.length,
                        },
                    ];
                }
                const [hostDetails, hostVulns] = await Promise.all([
                    getHost(projectId, listedHost.id),
                    getHostVulnerabilities(projectId, listedHost.id),
                ]);
                return [
                    listedHost.id,
                    {
                        portsCount: hostDetails.ports.length,
                        endpointsCount: hostDetails.endpoints.length,
                        vulnerabilitiesCount: hostVulns.items.length,
                    },
                ];
            }));
            const mappedStats = {};
            statsEntries.forEach((result) => {
                if (result.status === "fulfilled") {
                    const [key, value] = result.value;
                    mappedStats[key] = value;
                }
            });
            setHostStatsById(mappedStats);
        }
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось загрузить страницу хоста."));
        }
        finally {
            setLoading(false);
        }
    }, [hostId, projectId]);
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
            void loadHost();
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
        const storedSection = window.localStorage.getItem(`${storagePrefix}:selectedSection`);
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
            if (!projectId || !hostId || !host?.ports.length) {
                setServicesByPortId({});
                return;
            }
            const entries = await Promise.allSettled(host.ports.map(async (port) => {
                const services = await getServices(projectId, hostId, port.id);
                return [port.id, services];
            }));
            const mapped = {};
            entries.forEach((result) => {
                if (result.status === "fulfilled") {
                    const [portId, services] = result.value;
                    mapped[portId] = services;
                }
            });
            setServicesByPortId(mapped);
        };
        void loadServices();
    }, [host?.ports, hostId, projectId]);
    const hostActionsOpen = Boolean(hostActionsAnchorEl);
    const portActionsOpen = Boolean(portActionsAnchorEl);
    const endpointActionsOpen = Boolean(endpointActionsAnchorEl);
    const vulnerabilityActionsOpen = Boolean(vulnerabilityActionsAnchorEl);
    const openHostActionsMenu = (event) => {
        setHostActionsAnchorEl(event.currentTarget);
    };
    const closeHostActionsMenu = () => {
        setHostActionsAnchorEl(null);
    };
    const openPortActions = (event, port) => {
        event.stopPropagation();
        setPortActionsAnchorEl(event.currentTarget);
        setActivePort(port);
    };
    const closePortActions = () => {
        setPortActionsAnchorEl(null);
        setActivePort(null);
    };
    const openHostEdit = () => {
        if (!host) {
            return;
        }
        setEditingHostIp(host.ip_address ?? "");
        setEditingHostName(host.hostname ?? "");
        setEditingHostNotes(host.notes ?? "");
        closeHostActionsMenu();
        setEditHostOpen(true);
    };
    const saveHostInfo = async () => {
        if (!projectId || !hostId) {
            return;
        }
        setError(null);
        try {
            const updatedHost = await updateHost(projectId, hostId, {
                ip_address: editingHostIp.trim() || undefined,
                hostname: editingHostName.trim() || undefined,
                notes: editingHostNotes.trim() || undefined,
            });
            setHost((prev) => prev
                ? {
                    ...prev,
                    ip_address: updatedHost.ip_address,
                    hostname: updatedHost.hostname,
                    status: updatedHost.status,
                    notes: updatedHost.notes,
                }
                : prev);
            setEditHostOpen(false);
        }
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось обновить информацию о хосте."));
        }
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
    const openEndpointActions = (event, endpoint) => {
        event.stopPropagation();
        setEndpointActionsAnchorEl(event.currentTarget);
        setActiveEndpoint(endpoint);
    };
    const closeEndpointActions = () => {
        setEndpointActionsAnchorEl(null);
        setActiveEndpoint(null);
    };
    const openVulnerabilityActions = (event, vulnerability) => {
        event.stopPropagation();
        setVulnerabilityActionsAnchorEl(event.currentTarget);
        setActiveVulnerability(vulnerability);
    };
    const closeVulnerabilityActions = () => {
        setVulnerabilityActionsAnchorEl(null);
        setActiveVulnerability(null);
    };
    const toggleExpandedId = (id, setExpanded) => {
        setExpanded((current) => (current.includes(id) ? current.filter((itemId) => itemId !== id) : [...current, id]));
    };
    const toggleEndpointTreeFolder = useCallback((folderPathKey) => {
        setEndpointTreeExpandedKeys((prev) => {
            const next = new Set(prev);
            if (next.has(folderPathKey)) {
                next.delete(folderPathKey);
            }
            else {
                next.add(folderPathKey);
            }
            return next;
        });
    }, []);
    useEffect(() => {
        setEndpointTreeExpandedKeys(new Set(collectExpandableFolderKeys(endpointPathTree)));
    }, [endpointPathTree]);
    const buildEndpointRawRequestFromEndpoint = (endpoint) => {
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
        const requestBody = methodSupportsRequestBody(method) ? (endpoint.request_body || "") : "";
        if (requestBody.trim()) {
            lines.push(`Content-Type: ${endpoint.request_content_type || "application/json"}`);
        }
        return `${lines.join("\n")}\n\n${requestBody}`.trimEnd();
    };
    const buildEndpointCurl = (endpoint) => {
        const hostTarget = host?.hostname || host?.ip_address || "example.local";
        return buildDraftCurlLine({
            method: (endpoint.method || "GET"),
            path: endpoint.path,
            queryString: queryParamsToQueryString(endpoint.query_params),
            requestBody: endpoint.request_body || "",
            requestContentType: endpoint.request_content_type || "application/json",
            requestHeaders: endpoint.request_headers || [],
            hostTarget,
        });
    };
    const copyEndpointRequest = async (format) => {
        if (!activeEndpoint) {
            return;
        }
        try {
            const text = format === "curl" ? buildEndpointCurl(activeEndpoint) : buildEndpointRawRequestFromEndpoint(activeEndpoint);
            await navigator.clipboard.writeText(text);
            setInfoMessage(format === "curl" ? "cURL запрос скопирован." : "Raw HTTP запрос скопирован.");
            closeEndpointActions();
        }
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось скопировать запрос в буфер обмена."));
        }
    };
    const openPortEdit = (port) => {
        setEditingPortId(port.id);
        setEditingPortNumber(String(port.port_number));
        setEditingPortProtocol(port.protocol);
        setEditingPortState(port.state);
        setEditPortOpen(true);
    };
    const savePortEdit = async () => {
        if (!projectId || !hostId || !editingPortId) {
            return;
        }
        await updatePort(projectId, hostId, editingPortId, {
            port_number: Number(editingPortNumber),
            protocol: editingPortProtocol,
            state: editingPortState,
        });
        setEditPortOpen(false);
        await loadHost();
    };
    const removePort = async (portId) => {
        if (!projectId || !hostId) {
            return;
        }
        if (!window.confirm("Удалить порт?")) {
            return;
        }
        await deletePort(projectId, hostId, portId);
        await loadHost();
    };
    const createHostPort = async () => {
        if (!projectId || !hostId) {
            return;
        }
        await createPort(projectId, hostId, {
            port_number: Number(creatingPortNumber),
            protocol: creatingPortProtocol,
            state: creatingPortState,
        });
        setCreatePortOpen(false);
        setCreatingPortNumber("443");
        setCreatingPortProtocol("tcp");
        setCreatingPortState("open");
        await loadHost();
    };
    const normalizeImportedPortState = (value) => {
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
    const parseNmapPortsFromText = (rawText) => {
        const entries = new Map();
        const lines = rawText.replace(/\r/g, "").split("\n");
        const addEntry = (portNumber, protocol, stateRaw) => {
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
            addEntry(Number(match[1]), match[2].toLowerCase(), match[3]);
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
        let xmlMatch;
        while ((xmlMatch = xmlPortRegex.exec(rawText)) !== null) {
            addEntry(Number(xmlMatch[2]), xmlMatch[1].toLowerCase(), xmlMatch[3]);
        }
        return Array.from(entries.values()).sort((left, right) => left.port_number - right.port_number);
    };
    const importPortsFromNmapFile = async (file) => {
        if (!file || !projectId || !hostId) {
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
            const existingKeys = new Set((host?.ports ?? []).map((item) => `${item.port_number}/${item.protocol}`));
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
                    await createPort(projectId, hostId, entry);
                    existingKeys.add(key);
                    created += 1;
                }
                catch {
                    failed += 1;
                }
            }
            await loadHost();
            setInfoMessage(`Nmap импорт завершен: добавлено ${created}, пропущено ${skipped}, ошибок ${failed}.`);
        }
        catch (importError) {
            setError(getApiErrorMessage(importError, "Не удалось импортировать порты из Nmap."));
        }
        finally {
            setNmapImporting(false);
        }
    };
    const openCreateServiceDialog = (portId) => {
        setCreateServicePortId(portId);
        setCreatingServiceName("");
        setCreatingServiceVersion("");
        setCreatingServiceBanner("");
        setCreateServiceOpen(true);
    };
    const createPortService = async () => {
        if (!projectId || !hostId || !createServicePortId) {
            return;
        }
        await createService(projectId, hostId, createServicePortId, {
            name: creatingServiceName.trim(),
            version: creatingServiceVersion.trim() || undefined,
            banner: creatingServiceBanner.trim() || undefined,
        });
        setCreateServiceOpen(false);
        await loadHost();
    };
    const openEditServiceDialog = (portId, service) => {
        setEditServicePortId(portId);
        setEditingServiceId(service.id);
        setEditingServiceName(service.name);
        setEditingServiceVersion(service.version || "");
        setEditingServiceBanner(service.banner || "");
        setEditServiceOpen(true);
    };
    const saveServiceEdit = async () => {
        if (!projectId || !hostId || !editServicePortId || !editingServiceId) {
            return;
        }
        await updateService(projectId, hostId, editServicePortId, editingServiceId, {
            name: editingServiceName.trim() || undefined,
            version: editingServiceVersion.trim() || undefined,
            banner: editingServiceBanner.trim() || undefined,
        });
        setEditServiceOpen(false);
        await loadHost();
    };
    const removeService = async (portId, serviceId) => {
        if (!projectId || !hostId) {
            return;
        }
        if (!window.confirm("Удалить сервис?")) {
            return;
        }
        await deleteService(projectId, hostId, portId, serviceId);
        await loadHost();
    };
    const buildEndpointRawRequestFromFields = ({ method, path, queryParams, requestHeaders, requestBody, requestContentType, hostLine, }) => {
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
    const editingEndpointResolvedQueryParams = useMemo(() => editingEndpointMethod === "POST"
        ? []
        : normalizeEndpointQueryParams(queryStringToQueryParams(editingEndpointQueryString)), [editingEndpointMethod, editingEndpointQueryString]);
    const creatingEndpointResolvedQueryParams = useMemo(() => creatingEndpointMethod === "POST"
        ? []
        : normalizeEndpointQueryParams(queryStringToQueryParams(creatingEndpointQueryString)), [creatingEndpointMethod, creatingEndpointQueryString]);
    const endpointFormHostLine = host?.hostname || host?.ip_address || "example.local";
    const creatingEndpointSanitizedHeaders = useMemo(() => parseHeaderTextToSanitizedList(creatingEndpointHeadersText), [creatingEndpointHeadersText]);
    const editingEndpointSanitizedHeaders = useMemo(() => parseHeaderTextToSanitizedList(editingEndpointHeadersText), [editingEndpointHeadersText]);
    const applyParsedRequestToCreateEndpoint = (rawRequest) => {
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
        }
        else {
            setCreatingEndpointQueryString(queryParamsToQueryString(parsed.queryParams));
        }
    };
    const applyParsedRequestToEditEndpoint = (rawRequest) => {
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
        }
        else {
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
    const editingEndpointPreviewRequest = useMemo(() => buildEndpointRawRequestFromFields({
        method: editingEndpointMethod,
        path: editingEndpointPath,
        queryParams: editingEndpointResolvedQueryParams,
        requestHeaders: editingEndpointSanitizedHeaders,
        requestBody: editingEndpointRequestBody,
        requestContentType: editingEndpointRequestContentType,
        hostLine: endpointFormHostLine,
    }), [
        editingEndpointMethod,
        editingEndpointPath,
        editingEndpointResolvedQueryParams,
        editingEndpointSanitizedHeaders,
        editingEndpointRequestBody,
        editingEndpointRequestContentType,
        endpointFormHostLine,
    ]);
    const creatingEndpointPreviewRequest = useMemo(() => buildEndpointRawRequestFromFields({
        method: creatingEndpointMethod,
        path: creatingEndpointPath,
        queryParams: creatingEndpointResolvedQueryParams,
        requestHeaders: creatingEndpointSanitizedHeaders,
        requestBody: creatingEndpointRequestBody,
        requestContentType: creatingEndpointRequestContentType,
        hostLine: endpointFormHostLine,
    }), [
        creatingEndpointMethod,
        creatingEndpointPath,
        creatingEndpointResolvedQueryParams,
        creatingEndpointSanitizedHeaders,
        creatingEndpointRequestBody,
        creatingEndpointRequestContentType,
        endpointFormHostLine,
    ]);
    const copyCreatingEndpointDraft = async (format) => {
        const hostTarget = host?.hostname || host?.ip_address || "example.local";
        try {
            const text = format === "raw"
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
        }
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось скопировать в буфер обмена."));
        }
    };
    const copyEditingEndpointDraft = async (format) => {
        const hostTarget = host?.hostname || host?.ip_address || "example.local";
        try {
            const text = format === "raw"
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
        }
        catch (error) {
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
    const openEndpointEdit = (endpoint) => {
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
            query_params: editingEndpointMethod === "POST" ? [] : normalizeEndpointQueryParams(queryStringToQueryParams(editingEndpointQueryString)),
            request_headers: headers,
            request_body: bodyAllowed && editingEndpointRequestBody.trim() ? editingEndpointRequestBody.trim() : null,
            request_content_type: bodyAllowed && editingEndpointRequestBody.trim() ? editingEndpointRequestContentType.trim() || "application/json" : null,
        });
        setEditEndpointOpen(false);
        setEditingEndpointImportRaw("");
        await loadHost();
    };
    const removeEndpoint = async (endpointId) => {
        if (!projectId || !hostId) {
            return;
        }
        if (!window.confirm("Удалить эндпоинт?")) {
            return;
        }
        await deleteEndpoint(projectId, hostId, endpointId);
        await loadHost();
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
            query_params: creatingEndpointMethod === "POST" ? [] : normalizeEndpointQueryParams(queryStringToQueryParams(creatingEndpointQueryString)),
            request_headers: headers,
            request_body: bodyAllowed && creatingEndpointRequestBody.trim() ? creatingEndpointRequestBody.trim() : null,
            request_content_type: bodyAllowed && creatingEndpointRequestBody.trim() ? creatingEndpointRequestContentType.trim() || "application/json" : null,
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
    const importEndpointsFromSwaggerFile = async (file) => {
        if (!file || !projectId || !hostId) {
            return;
        }
        setSwaggerImporting(true);
        setError(null);
        setInfoMessage(null);
        try {
            const result = await importOpenApiFile(projectId, hostId, file);
            await loadHost();
            setInfoMessage(`Swagger импорт завершен: добавлено ${result.endpoints_created}, пропущено ${result.endpoints_skipped}, предупреждений ${result.errors.length}.`);
            if (result.errors.length) {
                setError(result.errors.join("\n"));
            }
        }
        catch (importError) {
            setError(getApiErrorMessage(importError, "Не удалось импортировать Swagger/OpenAPI."));
        }
        finally {
            setSwaggerImporting(false);
        }
    };
    const openVulnerabilityEdit = (vulnerability) => {
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
    const removeVulnerability = async (vulnerabilityId) => {
        if (!projectId) {
            return;
        }
        if (!window.confirm("Удалить уязвимость?")) {
            return;
        }
        await deleteVulnerability(projectId, vulnerabilityId);
        await loadHost();
    };
    const createHostVulnerability = async () => {
        if (!projectId || !hostId) {
            return;
        }
        const created = await createVulnerability(projectId, {
            host_id: hostId,
            title: creatingVulnerabilityTitle.trim(),
            description: null,
            severity: severityFromCvssScore(creatingVulnerabilityCvssScore === "" ? null : Number(creatingVulnerabilityCvssScore), creatingVulnerabilitySeverity),
            status: creatingVulnerabilityStatus,
            cvss_version: creatingVulnerabilityCvssVector.trim() ? CVSS_VERSION : null,
            cvss_score: creatingVulnerabilityCvssScore === "" ? null : Number(creatingVulnerabilityCvssScore),
            cvss_vector: creatingVulnerabilityCvssVector.trim() || null,
            cwe_id: creatingVulnerabilityCweId.trim() || null,
            workflow_steps: creatingVulnerabilityStages,
            impact: creatingVulnerabilityImpact.trim() || null,
            recommendations: creatingVulnerabilityRecommendations.trim() || null,
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
        await loadHost();
        if (isVulnerabilityRoute) {
            navigate(`/projects/${projectId}/hosts/${hostId}/vulnerabilities/${created.id}`, { replace: true, state: { section: "vulns" } });
        }
    };
    const hostServices = useMemo(() => Object.values(servicesByPortId).flat(), [servicesByPortId]);
    const buildAutoCvssFields = (vector) => {
        const normalizedVersion = vector?.trim() ? CVSS_VERSION : null;
        const { score } = calculateCvssScore(normalizedVersion, vector);
        return {
            severity: severityFromCvssScore(score),
            cvss_version: normalizedVersion,
            cvss_vector: vector,
            cvss_score: score,
        };
    };
    const loadVulnerabilityDetails = useCallback(async (vulnerabilityId) => {
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
            setVulnEditMode(false);
            setVulnDetailOpen(true);
        }
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось загрузить карточку уязвимости."));
        }
        finally {
            setVulnBusy(false);
        }
    }, [hostId, projectId]);
    useEffect(() => {
        if (!vulnerabilityId) {
            setVulnDetailOpen(false);
            setActiveVulnDetails(null);
            setVulnComments([]);
            return;
        }
        setSelectedSection("vulns");
        void loadVulnerabilityDetails(vulnerabilityId);
    }, [loadVulnerabilityDetails, vulnerabilityId]);
    useEffect(() => {
        if (!highlightedCommentId || !activeVulnDetails || !vulnComments.some((comment) => comment.id === highlightedCommentId)) {
            return;
        }
        const element = document.getElementById(`comment-${highlightedCommentId}`);
        if (!element) {
            return;
        }
        window.setTimeout(() => {
            element.scrollIntoView({ behavior: "smooth", block: "center" });
        }, 0);
    }, [activeVulnDetails, highlightedCommentId, vulnComments]);
    const saveActiveVulnerability = async () => {
        if (!projectId || !activeVulnDetails) {
            return;
        }
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
                workflow_steps: activeVulnDetails.workflow_steps,
                steps_to_reproduce: activeVulnDetails.steps_to_reproduce || null,
                impact: activeVulnDetails.impact || null,
                recommendations: activeVulnDetails.recommendations || null,
            });
            setActiveVulnDetails((prev) => (prev ? { ...prev, ...updated } : prev));
            await loadHost();
            setVulnEditMode(false);
        }
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось сохранить уязвимость."));
        }
        finally {
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
        }
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось добавить комментарий."));
        }
        finally {
            setVulnBusy(false);
        }
    };
    const removeCommentFromActiveVuln = async (commentId) => {
        if (!projectId || !activeVulnDetails) {
            return;
        }
        setVulnBusy(true);
        try {
            await deleteVulnerabilityComment(projectId, activeVulnDetails.id, commentId);
            setVulnComments((prev) => prev.filter((comment) => comment.id !== commentId));
        }
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось удалить комментарий."));
        }
        finally {
            setVulnBusy(false);
        }
    };
    const openCommentEdit = (comment) => {
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
        }
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось обновить комментарий."));
        }
        finally {
            setVulnBusy(false);
        }
    };
    const hostTitle = host?.hostname || host?.ip_address || "unknown-host";
    const portsCount = host?.ports.length ?? 0;
    const endpointsCount = normalizedHostEndpoints.length;
    const vulnerabilitiesCount = vulnerabilities.length;
    const severityChipSx = {
        critical: { bgcolor: "rgba(244,67,54,0.18)", color: "#ff8a80", border: "1px solid rgba(244,67,54,0.4)" },
        high: { bgcolor: "rgba(255,152,0,0.18)", color: "#ffcc80", border: "1px solid rgba(255,152,0,0.4)" },
        medium: { bgcolor: "rgba(255,235,59,0.14)", color: "#fff59d", border: "1px solid rgba(255,235,59,0.35)" },
        low: { bgcolor: "rgba(76,175,80,0.16)", color: "#a5d6a7", border: "1px solid rgba(76,175,80,0.38)" },
        info: { bgcolor: "rgba(33,150,243,0.18)", color: "#90caf9", border: "1px solid rgba(33,150,243,0.38)" },
    };
    const vulnerabilityStatusChipSx = {
        open: { bgcolor: "rgba(244,67,54,0.18)", color: "#ff8a80", border: "1px solid rgba(244,67,54,0.4)" },
        in_progress: { bgcolor: "rgba(255,152,0,0.18)", color: "#ffcc80", border: "1px solid rgba(255,152,0,0.4)" },
        fixed: { bgcolor: "rgba(76,175,80,0.16)", color: "#a5d6a7", border: "1px solid rgba(76,175,80,0.38)" },
        wont_fix: { bgcolor: "rgba(156,39,176,0.16)", color: "#ce93d8", border: "1px solid rgba(156,39,176,0.38)" },
        accepted_risk: { bgcolor: "rgba(96,125,139,0.2)", color: "#b0bec5", border: "1px solid rgba(96,125,139,0.38)" },
    };
    const renderEndpointPaper = (endpoint) => {
        const methodColors = swaggerMethodColors(endpoint.method);
        const expanded = expandedEndpointIds.includes(endpoint.id);
        const segs = endpointPathToSegments(endpoint.path);
        const shortTitle = segs.length ? segs[segs.length - 1] : "/";
        const fullPathDisplay = normalizeUriPathForTree(endpoint.path);
        const hasParams = !!endpoint.query_params?.length;
        const hasBody = !!(endpoint.request_body && endpoint.request_body.trim());
        const showBodySection = methodSupportsRequestBody((endpoint.method || "GET"));
        const hasSavedHeaders = !!(endpoint.request_headers && endpoint.request_headers.length > 0);
        return (_jsxs(Paper, { variant: "outlined", sx: {
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
            }, children: [_jsxs(Stack, { direction: "row", alignItems: "center", spacing: 1, onClick: () => toggleExpandedId(endpoint.id, setExpandedEndpointIds), sx: {
                        px: 1.5,
                        py: 1.1,
                        cursor: "pointer",
                        flexWrap: "wrap",
                        rowGap: 0.5,
                        backgroundColor: expanded ? "rgba(126,224,255,0.06)" : "transparent",
                    }, children: [_jsx(Chip, { size: "small", label: (endpoint.method || "GET").toUpperCase(), sx: {
                                fontWeight: 800,
                                fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
                                letterSpacing: 0.4,
                                bgcolor: methodColors.main,
                                color: methodColors.contrast,
                                borderRadius: 0.75,
                                height: 26,
                            } }), _jsxs(Stack, { spacing: 0.15, sx: { minWidth: 0 }, children: [_jsx(Typography, { component: "span", sx: {
                                        fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
                                        fontWeight: 700,
                                        fontSize: "0.95rem",
                                        lineHeight: 1.2,
                                    }, children: shortTitle }), _jsx(Typography, { variant: "caption", color: "text.secondary", sx: { fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace", wordBreak: "break-all", lineHeight: 1.2 }, children: fullPathDisplay })] }), _jsx(Box, { sx: { flex: "1 1 40px" } }), _jsx(Stack, { direction: "row", spacing: 0.25, alignItems: "center", className: "endpoint-actions", onClick: (e) => e.stopPropagation(), children: _jsx(Tooltip, { title: "\u0414\u0435\u0439\u0441\u0442\u0432\u0438\u044F", children: _jsx(IconButton, { size: "small", onClick: (event) => openEndpointActions(event, endpoint), children: _jsx(MoreVertIcon, { fontSize: "small" }) }) }) }), _jsx(ExpandMoreIcon, { fontSize: "small", sx: {
                                color: "text.secondary",
                                transform: expanded ? "rotate(180deg)" : "rotate(0deg)",
                                transition: "transform 0.2s ease",
                            } })] }), _jsx(Collapse, { in: expanded, timeout: "auto", unmountOnExit: true, children: _jsxs(Box, { sx: { px: 2, pb: 2, pt: 0, borderTop: "1px solid rgba(126,224,255,0.1)" }, children: [hasParams ? (_jsxs(_Fragment, { children: [_jsx(Typography, { variant: "subtitle2", fontWeight: 700, sx: { mt: 1.25, mb: 1 }, children: "\u041F\u0430\u0440\u0430\u043C\u0435\u0442\u0440\u044B" }), _jsx(TableContainer, { component: Paper, variant: "outlined", sx: { borderColor: "rgba(126,224,255,0.14)", backgroundColor: "rgba(8,17,31,0.45)" }, children: _jsxs(Table, { size: "small", children: [_jsx(TableHead, { children: _jsxs(TableRow, { children: [_jsx(TableCell, { sx: { fontWeight: 700, width: "34%", borderColor: "rgba(126,224,255,0.12)" }, children: "\u0418\u043C\u044F" }), _jsx(TableCell, { sx: { fontWeight: 700, borderColor: "rgba(126,224,255,0.12)" }, children: "\u041E\u043F\u0438\u0441\u0430\u043D\u0438\u0435" })] }) }), _jsx(TableBody, { children: endpoint.query_params.map((param, index) => (_jsxs(TableRow, { children: [_jsx(TableCell, { sx: {
                                                                    verticalAlign: "top",
                                                                    borderColor: "rgba(126,224,255,0.1)",
                                                                    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
                                                                }, children: _jsxs(Box, { component: "span", fontWeight: 700, children: [param.name, param.required ? (_jsx(Box, { component: "span", sx: { color: "error.main", ml: 0.25 }, children: "*" })) : null] }) }), _jsxs(TableCell, { sx: { verticalAlign: "top", borderColor: "rgba(126,224,255,0.1)" }, children: [param.description && (_jsx(Typography, { variant: "body2", color: "text.secondary", sx: { mb: 0.5 }, children: param.description })), _jsx(Typography, { variant: "body2", component: "div", sx: { fontFamily: "ui-monospace, monospace", wordBreak: "break-all" }, children: param.value || "—" })] })] }, `${endpoint.id}-${param.name}-${index}`))) })] }) })] })) : null, hasSavedHeaders && (_jsxs(_Fragment, { children: [_jsx(Typography, { variant: "subtitle2", fontWeight: 700, sx: { mt: 2.5, mb: 1 }, children: "\u0417\u0430\u0433\u043E\u043B\u043E\u0432\u043A\u0438" }), _jsx(TableContainer, { component: Paper, variant: "outlined", sx: { borderColor: "rgba(126,224,255,0.14)", backgroundColor: "rgba(8,17,31,0.45)" }, children: _jsxs(Table, { size: "small", children: [_jsx(TableHead, { children: _jsxs(TableRow, { children: [_jsx(TableCell, { sx: { fontWeight: 700, width: "28%", borderColor: "rgba(126,224,255,0.12)" }, children: "\u0418\u043C\u044F" }), _jsx(TableCell, { sx: { fontWeight: 700, borderColor: "rgba(126,224,255,0.12)" }, children: "\u0417\u043D\u0430\u0447\u0435\u043D\u0438\u0435" })] }) }), _jsx(TableBody, { children: endpoint.request_headers.map((h, index) => (_jsxs(TableRow, { children: [_jsx(TableCell, { sx: {
                                                                    verticalAlign: "top",
                                                                    borderColor: "rgba(126,224,255,0.1)",
                                                                    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
                                                                }, children: h.name }), _jsx(TableCell, { sx: {
                                                                    verticalAlign: "top",
                                                                    borderColor: "rgba(126,224,255,0.1)",
                                                                    wordBreak: "break-word",
                                                                    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
                                                                    fontSize: "0.8125rem",
                                                                }, children: h.value })] }, `${endpoint.id}-hdr-${index}`))) })] }) })] })), showBodySection && (hasBody || endpoint.request_content_type) && (_jsxs(_Fragment, { children: [_jsx(Typography, { variant: "subtitle2", fontWeight: 700, sx: { mt: 2.5, mb: 1 }, children: "\u0422\u0435\u043B\u043E \u0437\u0430\u043F\u0440\u043E\u0441\u0430" }), endpoint.request_content_type && (_jsxs(Stack, { direction: "row", alignItems: "center", spacing: 1, sx: { mb: 1 }, children: [_jsx(Typography, { variant: "caption", color: "text.secondary", children: "\u0422\u0438\u043F \u0441\u043E\u0434\u0435\u0440\u0436\u0438\u043C\u043E\u0433\u043E" }), _jsx(Chip, { size: "small", variant: "outlined", label: endpoint.request_content_type, sx: { fontFamily: "ui-monospace, monospace", borderColor: "rgba(126,224,255,0.25)" } })] })), hasBody ? (_jsxs(_Fragment, { children: [_jsx(Typography, { variant: "caption", color: "text.secondary", display: "block", sx: { mb: 0.75 }, children: "\u041F\u0440\u0438\u043C\u0435\u0440 \u0437\u043D\u0430\u0447\u0435\u043D\u0438\u044F" }), _jsx(Paper, { variant: "outlined", sx: {
                                                    m: 0,
                                                    p: 1.5,
                                                    borderColor: "rgba(126,224,255,0.14)",
                                                    backgroundColor: "rgba(15,23,42,0.92)",
                                                    overflowX: "auto",
                                                }, children: _jsx(Box, { component: "pre", sx: {
                                                        m: 0,
                                                        fontSize: "0.8125rem",
                                                        lineHeight: 1.55,
                                                        fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
                                                        whiteSpace: "pre-wrap",
                                                        wordBreak: "break-word",
                                                        color: "#e2e8f0",
                                                    }, children: formatRequestBodyPreview(endpoint.request_body) }) })] })) : (_jsx(Typography, { variant: "body2", color: "text.disabled", fontStyle: "italic", children: "\u0422\u0435\u043B\u043E \u0437\u0430\u043F\u0440\u043E\u0441\u0430 \u043D\u0435 \u0437\u0430\u0434\u0430\u043D\u043E (\u0443\u043A\u0430\u0437\u0430\u043D \u0442\u043E\u043B\u044C\u043A\u043E \u0442\u0438\u043F \u0441\u043E\u0434\u0435\u0440\u0436\u0438\u043C\u043E\u0433\u043E)" }))] }))] }) })] }, endpoint.id));
    };
    const renderEndpointPathTree = (root) => {
        const walk = (node, depth) => {
            const isRoot = node.pathKey === "";
            const papers = node.endpointsAtNode.map((ep) => renderEndpointPaper(ep));
            if (isRoot) {
                return (_jsxs(Stack, { spacing: 1.25, children: [papers, node.children.map((child) => (_jsx(Box, { children: walk(child, 1) }, child.pathKey)))] }, "ep-tree-root"));
            }
            if (node.children.length === 0) {
                return (_jsx(Stack, { spacing: 1.25, children: papers }, node.pathKey));
            }
            const expanded = endpointTreeExpandedKeys.has(node.pathKey);
            return (_jsxs(Box, { children: [_jsxs(Stack, { direction: "row", alignItems: "center", spacing: 0.75, onClick: () => toggleEndpointTreeFolder(node.pathKey), sx: {
                            cursor: "pointer",
                            py: 0.65,
                            px: 0.5,
                            borderRadius: 0.75,
                            pl: Math.min(depth, 6) * 1.25,
                            "&:hover": { backgroundColor: "rgba(126,224,255,0.06)" },
                        }, children: [_jsx(ExpandMoreIcon, { fontSize: "small", sx: {
                                    color: "text.secondary",
                                    transform: expanded ? "rotate(0deg)" : "rotate(-90deg)",
                                    transition: "transform 0.2s ease",
                                } }), _jsx(Typography, { fontWeight: 700, sx: { fontFamily: "ui-monospace, monospace", fontSize: "0.9rem" }, children: node.segment })] }), _jsx(Collapse, { in: expanded, timeout: "auto", unmountOnExit: true, children: _jsxs(Stack, { spacing: 1.25, sx: {
                                pl: 1.5,
                                ml: Math.min(depth, 6) * 1.25 + 0.75,
                                borderLeft: "1px solid rgba(126,224,255,0.12)",
                                mt: 0.5,
                            }, children: [papers, node.children.map((child) => (_jsx(Box, { children: walk(child, depth + 1) }, child.pathKey)))] }) })] }, node.pathKey));
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
    const openCommentActionsMenu = (event, comment) => {
        setActiveComment(comment);
        setCommentActionsAnchorEl(event.currentTarget);
    };
    const closeCommentActionsMenu = () => {
        setCommentActionsAnchorEl(null);
        setActiveComment(null);
    };
    const formatCommentTimestamp = (value) => new Intl.DateTimeFormat("ru-RU", {
        day: "2-digit",
        month: "2-digit",
        year: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
    }).format(new Date(value));
    const renderCommentsSection = () => (_jsxs(Stack, { spacing: 1.25, children: [_jsxs(Typography, { variant: "subtitle1", fontWeight: 700, children: ["\u041A\u043E\u043C\u043C\u0435\u043D\u0442\u0430\u0440\u0438\u0438 (", vulnComments.length, ")"] }), _jsxs(List, { dense: true, disablePadding: true, children: [vulnComments.map((comment) => {
                        const isHighlighted = highlightedCommentId === comment.id;
                        const canManageComment = user?.id === comment.user_id;
                        return (_jsx(ListItem, { id: `comment-${comment.id}`, alignItems: "flex-start", sx: {
                                border: isHighlighted ? "1px solid rgba(76,175,80,0.65)" : undefined,
                                backgroundColor: isHighlighted ? "rgba(76,175,80,0.08)" : undefined,
                                scrollMarginTop: 96,
                                ...(canManageComment
                                    ? {
                                        "&:hover .comment-row-actions, &:focus-within .comment-row-actions": {
                                            opacity: 1,
                                            pointerEvents: "auto",
                                        },
                                    }
                                    : {}),
                            }, children: _jsxs(Stack, { spacing: 0.75, sx: { width: "100%" }, children: [_jsxs(Stack, { direction: "row", justifyContent: "space-between", alignItems: "center", spacing: 2, children: [_jsxs(Stack, { direction: "row", alignItems: "center", spacing: 1.25, minWidth: 0, children: [_jsx(Avatar, { src: comment.avatar_url || undefined, alt: comment.username, sx: { width: 28, height: 28, fontSize: "0.8rem", bgcolor: "rgba(126,224,255,0.18)" }, children: comment.username.slice(0, 1).toUpperCase() }), _jsx(Typography, { fontWeight: 700, color: "text.primary", noWrap: true, children: comment.username })] }), _jsxs(Stack, { direction: "row", alignItems: "center", spacing: 0, sx: { flexShrink: 0 }, children: [_jsx(Typography, { variant: "caption", color: "text.secondary", sx: { whiteSpace: "nowrap", textAlign: "right", minWidth: "7.75rem", pr: 0.5 }, children: formatCommentTimestamp(comment.created_at) }), _jsx(Box, { sx: { width: 36, display: "flex", justifyContent: "flex-end", flexShrink: 0 }, children: canManageComment ? (_jsx(IconButton, { className: "comment-row-actions", size: "small", onClick: (event) => openCommentActionsMenu(event, comment), sx: {
                                                                mr: -0.75,
                                                                opacity: 0,
                                                                pointerEvents: "none",
                                                                transition: "opacity 0.15s ease",
                                                                color: "rgba(148,163,184,0.85)",
                                                                "&:hover": {
                                                                    color: "rgba(148,163,184,1)",
                                                                    backgroundColor: "rgba(126,224,255,0.06)",
                                                                },
                                                            }, children: _jsx(MoreVertIcon, { fontSize: "small" }) })) : null })] })] }), _jsx(Typography, { variant: "body2", color: "rgba(235,245,255,0.92)", sx: { whiteSpace: "pre-wrap", pr: 1 }, children: comment.content })] }) }, comment.id));
                    }), vulnComments.length === 0 && _jsx(Typography, { color: "text.secondary", children: "\u041A\u043E\u043C\u043C\u0435\u043D\u0442\u0430\u0440\u0438\u0435\u0432 \u043F\u043E\u043A\u0430 \u043D\u0435\u0442." })] }), _jsx(TextField, { label: "\u041A\u043E\u043C\u043C\u0435\u043D\u0442\u0430\u0440\u0438\u0439 (@username \u0442\u043E\u043B\u044C\u043A\u043E \u0434\u043B\u044F \u0443\u0447\u0430\u0441\u0442\u043D\u0438\u043A\u043E\u0432 \u043F\u0440\u043E\u0435\u043A\u0442\u0430)", multiline: true, minRows: 3, value: newComment, onChange: (event) => setNewComment(event.target.value) }), _jsx(Stack, { direction: "row", justifyContent: "flex-end", children: _jsx(Button, { variant: "contained", disabled: !newComment.trim() || vulnBusy, onClick: () => void addCommentToActiveVuln(), children: "\u0414\u043E\u0431\u0430\u0432\u0438\u0442\u044C \u043A\u043E\u043C\u043C\u0435\u043D\u0442\u0430\u0440\u0438\u0439" }) }), _jsxs(Menu, { anchorEl: commentActionsAnchorEl, open: Boolean(commentActionsAnchorEl), onClose: closeCommentActionsMenu, anchorOrigin: { vertical: "bottom", horizontal: "right" }, transformOrigin: { vertical: "top", horizontal: "right" }, children: [_jsxs(MenuItem, { onClick: () => {
                            if (activeComment) {
                                openCommentEdit(activeComment);
                            }
                            closeCommentActionsMenu();
                        }, children: [_jsx(EditIcon, { fontSize: "small", sx: { mr: 1 } }), "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C"] }), _jsxs(MenuItem, { onClick: () => {
                            if (activeComment) {
                                void removeCommentFromActiveVuln(activeComment.id);
                            }
                            closeCommentActionsMenu();
                        }, children: [_jsx(DeleteOutlineIcon, { fontSize: "small", sx: { mr: 1 } }), "\u0423\u0434\u0430\u043B\u0438\u0442\u044C"] })] })] }));
    const renderMarkdownPreview = (value, emptyText) => (_jsx(Box, { sx: { border: "1px solid rgba(126,224,255,0.14)", p: 1.5, backgroundColor: "rgba(8,17,31,0.28)" }, children: value?.trim() ? _jsx(ReactMarkdown, { children: value }) : _jsx(Typography, { color: "text.secondary", children: emptyText }) }));
    const renderVulnerabilityDetailsContent = () => {
        if (!activeVulnDetails) {
            return _jsx(Typography, { color: "text.secondary", children: "\u0423\u044F\u0437\u0432\u0438\u043C\u043E\u0441\u0442\u044C \u043D\u0435 \u0432\u044B\u0431\u0440\u0430\u043D\u0430." });
        }
        return (_jsx(Stack, { spacing: 2, sx: { mt: 0.5 }, children: _jsxs(Grid, { container: true, spacing: 2, children: [_jsx(Grid, { size: { xs: 12, md: 7 }, children: _jsx(TextField, { label: "\u041D\u0430\u0437\u0432\u0430\u043D\u0438\u0435", fullWidth: true, value: activeVulnDetails.title, onChange: (event) => setActiveVulnDetails((prev) => (prev ? { ...prev, title: event.target.value } : prev)), slotProps: { input: { readOnly: !vulnEditMode } } }) }), _jsx(Grid, { size: { xs: 12, md: 3 }, children: _jsx(TextField, { label: "CWE ID", fullWidth: true, value: activeVulnDetails.cwe_id || "", onChange: (event) => setActiveVulnDetails((prev) => (prev ? { ...prev, cwe_id: event.target.value || null } : prev)), slotProps: { input: { readOnly: !vulnEditMode } } }) }), _jsx(Grid, { size: { xs: 12, md: 2 }, children: vulnEditMode ? (_jsxs(TextField, { select: true, label: "\u0421\u0442\u0430\u0442\u0443\u0441", fullWidth: true, value: activeVulnDetails.status, onChange: (event) => setActiveVulnDetails((prev) => (prev ? { ...prev, status: event.target.value } : prev)), children: [_jsx(MenuItem, { value: "open", children: "open" }), _jsx(MenuItem, { value: "in_progress", children: "in_progress" }), _jsx(MenuItem, { value: "fixed", children: "fixed" }), _jsx(MenuItem, { value: "wont_fix", children: "wont_fix" }), _jsx(MenuItem, { value: "accepted_risk", children: "accepted_risk" })] })) : (_jsx(TextField, { label: "\u0421\u0442\u0430\u0442\u0443\u0441", fullWidth: true, value: activeVulnDetails.status, slotProps: { input: { readOnly: true } } })) }), _jsx(Grid, { size: { xs: 12, md: 2 }, children: _jsx(TextField, { label: "CVSS score", type: "number", fullWidth: true, value: activeVulnDetails.cvss_score ?? "", slotProps: { input: { readOnly: true } } }) }), _jsx(Grid, { size: { xs: 12, md: 2 }, children: _jsx(TextField, { label: "\u041A\u0440\u0438\u0442\u0438\u0447\u043D\u043E\u0441\u0442\u044C", fullWidth: true, value: activeVulnDetails.severity, slotProps: { input: { readOnly: true } } }) }), _jsx(Grid, { size: { xs: 12, md: 8 }, children: _jsx(TextField, { label: "CVSS vector", fullWidth: true, value: activeVulnDetails.cvss_vector || "", onChange: (event) => setActiveVulnDetails((prev) => (prev ? { ...prev, ...buildAutoCvssFields(event.target.value || null) } : prev)), slotProps: { input: { readOnly: !vulnEditMode } } }) }), _jsx(Grid, { size: { xs: 12 }, children: _jsx(VulnerabilityStagesEditor, { stages: activeVulnDetails.workflow_steps || [], endpoints: normalizedHostEndpoints, hostLabel: host?.hostname || host?.ip_address || undefined, busy: vulnBusy, editable: vulnEditMode, onChange: (nextStages) => setActiveVulnDetails((prev) => prev
                                ? {
                                    ...prev,
                                    workflow_steps: nextStages,
                                }
                                : prev), onUploadImage: async (stageId, file) => {
                                if (!projectId || !activeVulnDetails) {
                                    return null;
                                }
                                try {
                                    const uploadedFile = await uploadVulnerabilityFile(projectId, activeVulnDetails.id, file);
                                    setActiveVulnDetails((prev) => prev
                                        ? {
                                            ...prev,
                                            files: [uploadedFile, ...prev.files.filter((fileMeta) => fileMeta.id !== uploadedFile.id)],
                                        }
                                        : prev);
                                    return `![${uploadedFile.original_name}](/api/v1/files/${uploadedFile.id}/download)`;
                                }
                                catch {
                                    setError("Не удалось загрузить картинку этапа.");
                                    return null;
                                }
                            } }) }), _jsx(Grid, { size: { xs: 12 }, children: vulnEditMode ? (_jsx(TextField, { label: "\u0412\u043B\u0438\u044F\u043D\u0438\u0435", fullWidth: true, multiline: true, minRows: 2, value: activeVulnDetails.impact || "", onChange: (event) => setActiveVulnDetails((prev) => (prev ? { ...prev, impact: event.target.value || null } : prev)) })) : (_jsxs(_Fragment, { children: [_jsx(Typography, { variant: "subtitle2", sx: { mb: 0.75 }, children: "\u0412\u043B\u0438\u044F\u043D\u0438\u0435" }), renderMarkdownPreview(activeVulnDetails.impact, "Влияние не указано.")] })) }), _jsx(Grid, { size: { xs: 12 }, children: vulnEditMode ? (_jsx(TextField, { label: "\u0420\u0435\u043A\u043E\u043C\u0435\u043D\u0434\u0430\u0446\u0438\u0438", fullWidth: true, multiline: true, minRows: 2, value: activeVulnDetails.recommendations || "", onChange: (event) => setActiveVulnDetails((prev) => (prev ? { ...prev, recommendations: event.target.value || null } : prev)) })) : (_jsxs(_Fragment, { children: [_jsx(Typography, { variant: "subtitle2", sx: { mb: 0.75 }, children: "\u0420\u0435\u043A\u043E\u043C\u0435\u043D\u0434\u0430\u0446\u0438\u0438" }), renderMarkdownPreview(activeVulnDetails.recommendations, "Рекомендации не указаны.")] })) }), vulnEditMode && (_jsx(Grid, { size: { xs: 12 }, children: _jsxs(Stack, { direction: { xs: "column", sm: "row" }, justifyContent: "flex-end", spacing: 1.5, children: [_jsx(Button, { variant: "outlined", size: "large", sx: { minWidth: { sm: 180 } }, onClick: () => void loadVulnerabilityDetails(activeVulnDetails.id), children: "\u041E\u0442\u043C\u0435\u043D\u0438\u0442\u044C" }), _jsx(Button, { variant: "contained", size: "large", sx: { minWidth: { sm: 200 } }, onClick: () => void saveActiveVulnerability(), disabled: !activeVulnDetails || vulnBusy, children: "\u0421\u043E\u0445\u0440\u0430\u043D\u0438\u0442\u044C \u0438\u0437\u043C\u0435\u043D\u0435\u043D\u0438\u044F" })] }) }))] }) }));
    };
    if (loading) {
        return (_jsx(Box, { display: "flex", justifyContent: "center", py: 6, children: _jsx(CircularProgress, {}) }));
    }
    return (_jsxs(Stack, { spacing: 2.5, children: [_jsx(Stack, { direction: "row", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 1, children: _jsx(Stack, { spacing: 0.2, children: _jsxs(Typography, { variant: "h4", fontWeight: 700, children: ["\u0425\u043E\u0441\u0442: ", hostTitle] }) }) }), _jsxs(Menu, { anchorEl: hostActionsAnchorEl, open: hostActionsOpen, onClose: closeHostActionsMenu, anchorOrigin: { vertical: "bottom", horizontal: "right" }, transformOrigin: { vertical: "top", horizontal: "right" }, children: [_jsxs(MenuItem, { onClick: openHostEdit, children: [_jsx(EditIcon, { fontSize: "small", sx: { mr: 1 } }), "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u0445\u043E\u0441\u0442"] }), _jsxs(MenuItem, { onClick: () => {
                            closeHostActionsMenu();
                            void removeHost();
                        }, children: [_jsx(DeleteIcon, { fontSize: "small", sx: { mr: 1 } }), "\u0423\u0434\u0430\u043B\u0438\u0442\u044C \u0445\u043E\u0441\u0442"] })] }), _jsxs(Stack, { direction: { xs: "column", md: "row" }, spacing: 2, children: [_jsx(ProjectTreeNav, { hosts: hosts, selectedHostId: hostId ?? null, selectedSection: selectedSection, isCollapsed: isSidebarCollapsed, portsCount: portsCount, endpointsCount: endpointsCount, vulnerabilitiesCount: vulnerabilitiesCount, hostStatsById: hostStatsById, onToggleCollapsed: () => setSidebarCollapsed((v) => !v), onSelectSection: openHostSection, onSelectProjectOverview: () => navigate(`/projects/${projectId}`), onSelectHost: () => undefined, onOpenHost: (nextHostId, section) => navigate(`/projects/${projectId}/hosts/${nextHostId}`, { state: { section } }) }), _jsxs(Stack, { flex: 1, spacing: 2, children: [_jsxs(Grid, { container: true, spacing: 2, children: [_jsx(Grid, { size: { xs: 12, md: 4 }, children: _jsx(Card, { onClick: () => openHostSection("ports"), sx: {
                                                cursor: "pointer",
                                                border: selectedSection === "ports" ? "1px solid rgba(126,224,255,0.45)" : "1px solid rgba(126,224,255,0.16)",
                                                backgroundColor: selectedSection === "ports" ? "rgba(17,38,62,0.88)" : "rgba(15,27,45,0.82)",
                                            }, children: _jsxs(CardContent, { children: [_jsx(Typography, { color: "text.secondary", children: "\u041F\u043E\u0440\u0442\u043E\u0432 \u0445\u043E\u0441\u0442\u0430" }), _jsx(Typography, { variant: "h4", fontWeight: 700, children: portsCount })] }) }) }), _jsx(Grid, { size: { xs: 12, md: 4 }, children: _jsx(Card, { onClick: () => openHostSection("endpoints"), sx: {
                                                cursor: "pointer",
                                                border: selectedSection === "endpoints" ? "1px solid rgba(126,224,255,0.45)" : "1px solid rgba(126,224,255,0.16)",
                                                backgroundColor: selectedSection === "endpoints" ? "rgba(17,38,62,0.88)" : "rgba(15,27,45,0.82)",
                                            }, children: _jsxs(CardContent, { children: [_jsx(Typography, { color: "text.secondary", children: "\u042D\u043D\u0434\u043F\u043E\u0438\u043D\u0442\u043E\u0432 \u0445\u043E\u0441\u0442\u0430" }), _jsx(Typography, { variant: "h4", fontWeight: 700, children: endpointsCount })] }) }) }), _jsx(Grid, { size: { xs: 12, md: 4 }, children: _jsx(Card, { onClick: () => openHostSection("vulns"), sx: {
                                                cursor: "pointer",
                                                border: selectedSection === "vulns" ? "1px solid rgba(126,224,255,0.45)" : "1px solid rgba(126,224,255,0.16)",
                                                backgroundColor: selectedSection === "vulns" ? "rgba(17,38,62,0.88)" : "rgba(15,27,45,0.82)",
                                            }, children: _jsxs(CardContent, { children: [_jsx(Typography, { color: "text.secondary", children: "\u0423\u044F\u0437\u0432\u0438\u043C\u043E\u0441\u0442\u0435\u0439 \u0445\u043E\u0441\u0442\u0430" }), _jsx(Typography, { variant: "h4", fontWeight: 700, children: vulnerabilitiesCount })] }) }) })] }), selectedSection === "overview" && (_jsx(Stack, { spacing: 2, children: _jsx(Card, { sx: { border: "1px solid rgba(126,224,255,0.14)" }, children: _jsxs(CardContent, { children: [_jsxs(Stack, { direction: "row", alignItems: "center", justifyContent: "space-between", mb: 1, children: [_jsx(Typography, { variant: "h6", fontWeight: 700, children: "\u041E\u043F\u0438\u0441\u0430\u043D\u0438\u0435 \u0445\u043E\u0441\u0442\u0430" }), _jsx(IconButton, { size: "small", onClick: openHostActionsMenu, sx: { border: "1px solid rgba(126,224,255,0.2)", backgroundColor: "rgba(15,27,45,0.6)" }, children: _jsx(MoreVertIcon, { fontSize: "small" }) })] }), _jsx(Box, { sx: { border: "1px solid rgba(126,224,255,0.12)", p: 2, borderRadius: 0, backgroundColor: "rgba(8,17,31,0.28)" }, children: _jsx(ReactMarkdown, { children: host?.notes || "_Описание хоста не заполнено_" }) })] }) }) })), selectedSection === "ports" && (_jsx(Card, { sx: { border: "1px solid rgba(126,224,255,0.14)" }, children: _jsxs(CardContent, { children: [_jsxs(Stack, { direction: "row", alignItems: "center", justifyContent: "space-between", mb: 1, children: [_jsx(Typography, { variant: "h6", fontWeight: 700, children: "\u041F\u043E\u0440\u0442\u044B" }), _jsxs(Stack, { direction: "row", spacing: 0.5, children: [_jsx(Tooltip, { title: "\u0418\u043C\u043F\u043E\u0440\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u043F\u043E\u0440\u0442\u044B \u0438\u0437 Nmap", children: _jsxs(IconButton, { size: "small", component: "label", disabled: nmapImporting, children: [_jsx(UploadFileIcon, { fontSize: "small" }), _jsx("input", { hidden: true, type: "file", accept: ".txt,.nmap,.gnmap,.xml,text/plain,text/xml,application/xml", onChange: (event) => {
                                                                            const selectedFile = event.target.files?.[0] ?? null;
                                                                            void importPortsFromNmapFile(selectedFile);
                                                                            event.target.value = "";
                                                                        } })] }) }), _jsx(Tooltip, { title: "\u0414\u043E\u0431\u0430\u0432\u0438\u0442\u044C \u043F\u043E\u0440\u0442", children: _jsx(IconButton, { size: "small", onClick: () => setCreatePortOpen(true), sx: { color: "text.secondary", "&:hover": { backgroundColor: "rgba(126,224,255,0.08)", color: "text.primary" } }, children: _jsx(AddIcon, { fontSize: "small" }) }) })] })] }), _jsxs(Stack, { spacing: 1, children: [host?.ports.map((port) => (_jsxs(Stack, { onClick: () => toggleExpandedId(port.id, setExpandedPortIds), sx: {
                                                        border: "1px solid rgba(126,224,255,0.12)",
                                                        p: 1.4,
                                                        borderRadius: 0,
                                                        backgroundColor: "rgba(8,17,31,0.24)",
                                                        cursor: "pointer",
                                                        "& .port-actions": {
                                                            opacity: 0,
                                                            pointerEvents: "none",
                                                            transition: "opacity 0.15s ease-in-out",
                                                        },
                                                        "&:hover .port-actions": {
                                                            opacity: 1,
                                                            pointerEvents: "auto",
                                                        },
                                                    }, children: [_jsxs(Stack, { direction: "row", justifyContent: "space-between", alignItems: "center", children: [_jsxs(Stack, { direction: "row", spacing: 1, alignItems: "center", children: [_jsxs(Typography, { fontWeight: 600, children: [port.port_number, "/", port.protocol] }), _jsx(Chip, { label: port.state, size: "small" })] }), _jsx(Stack, { direction: "row", spacing: 0.4, className: "port-actions", children: _jsx(Tooltip, { title: "\u0414\u0435\u0439\u0441\u0442\u0432\u0438\u044F", children: _jsx(IconButton, { size: "small", onClick: (event) => openPortActions(event, port), children: _jsx(MoreVertIcon, { fontSize: "small" }) }) }) })] }), _jsx(Collapse, { in: expandedPortIds.includes(port.id), timeout: "auto", unmountOnExit: true, children: _jsxs(Stack, { mt: 1, spacing: 1, children: [_jsxs(Typography, { color: "text.secondary", variant: "body2", children: ["\u041F\u043E\u0440\u0442 ", port.port_number, "/", port.protocol, " \u0441\u0435\u0439\u0447\u0430\u0441 \u0432 \u0441\u043E\u0441\u0442\u043E\u044F\u043D\u0438\u0438 ", port.state, "."] }), _jsxs(Stack, { direction: "row", justifyContent: "space-between", alignItems: "center", children: [_jsx(Typography, { variant: "body2", fontWeight: 600, children: "\u0421\u0435\u0440\u0432\u0438\u0441\u044B" }), _jsx(Tooltip, { title: "\u0414\u043E\u0431\u0430\u0432\u0438\u0442\u044C \u0441\u0435\u0440\u0432\u0438\u0441", children: _jsx(IconButton, { size: "small", onClick: (event) => {
                                                                                        event.stopPropagation();
                                                                                        openCreateServiceDialog(port.id);
                                                                                    }, sx: { color: "text.secondary", "&:hover": { backgroundColor: "rgba(126,224,255,0.08)", color: "text.primary" } }, children: _jsx(AddIcon, { fontSize: "small" }) }) })] }), _jsxs(Stack, { spacing: 0.8, children: [(servicesByPortId[port.id] ?? []).map((service) => (_jsxs(Stack, { direction: "row", justifyContent: "space-between", alignItems: "center", sx: { border: "1px solid rgba(126,224,255,0.12)", p: 1, borderRadius: 0, backgroundColor: "rgba(8,17,31,0.26)" }, children: [_jsxs(Stack, { spacing: 0.2, children: [_jsx(Typography, { variant: "body2", fontWeight: 600, children: service.name }), _jsx(Typography, { variant: "caption", color: "text.secondary", children: service.version || "version n/a" })] }), _jsxs(Stack, { direction: "row", spacing: 0.4, children: [_jsx(Tooltip, { title: "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u0441\u0435\u0440\u0432\u0438\u0441", children: _jsx(IconButton, { size: "small", onClick: (event) => {
                                                                                                        event.stopPropagation();
                                                                                                        openEditServiceDialog(port.id, service);
                                                                                                    }, children: _jsx(EditIcon, { fontSize: "small" }) }) }), _jsx(Tooltip, { title: "\u0423\u0434\u0430\u043B\u0438\u0442\u044C \u0441\u0435\u0440\u0432\u0438\u0441", children: _jsx(IconButton, { size: "small", color: "error", onClick: (event) => {
                                                                                                        event.stopPropagation();
                                                                                                        void removeService(port.id, service.id);
                                                                                                    }, children: _jsx(DeleteIcon, { fontSize: "small" }) }) })] })] }, service.id))), (servicesByPortId[port.id] ?? []).length === 0 && (_jsx(Typography, { variant: "caption", color: "text.secondary", children: "\u0421\u0435\u0440\u0432\u0438\u0441\u044B \u043D\u0430 \u043F\u043E\u0440\u0442\u0443 \u043F\u043E\u043A\u0430 \u043D\u0435 \u0434\u043E\u0431\u0430\u0432\u043B\u0435\u043D\u044B." }))] })] }) })] }, port.id))), !host?.ports.length && _jsx(Typography, { color: "text.secondary", children: "\u041F\u043E\u0440\u0442\u044B \u0434\u043B\u044F \u044D\u0442\u043E\u0433\u043E \u0445\u043E\u0441\u0442\u0430 \u043F\u043E\u043A\u0430 \u043D\u0435 \u0434\u043E\u0431\u0430\u0432\u043B\u0435\u043D\u044B." })] }), _jsxs(Menu, { anchorEl: portActionsAnchorEl, open: portActionsOpen, onClose: closePortActions, anchorOrigin: { vertical: "bottom", horizontal: "right" }, transformOrigin: { vertical: "top", horizontal: "right" }, children: [_jsxs(MenuItem, { onClick: () => {
                                                        if (activePort) {
                                                            openPortEdit(activePort);
                                                        }
                                                        closePortActions();
                                                    }, children: [_jsx(EditIcon, { fontSize: "small", sx: { mr: 1 } }), "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C"] }), _jsxs(MenuItem, { onClick: () => {
                                                        if (activePort) {
                                                            void removePort(activePort.id);
                                                        }
                                                        closePortActions();
                                                    }, children: [_jsx(DeleteIcon, { fontSize: "small", sx: { mr: 1 } }), "\u0423\u0434\u0430\u043B\u0438\u0442\u044C"] })] })] }) })), selectedSection === "endpoints" && (_jsx(Card, { sx: { border: "1px solid rgba(126,224,255,0.14)" }, children: _jsxs(CardContent, { children: [_jsxs(Stack, { direction: "row", alignItems: "center", justifyContent: "space-between", mb: 1, children: [_jsx(Typography, { variant: "h6", fontWeight: 700, children: "\u042D\u043D\u0434\u043F\u043E\u0438\u043D\u0442\u044B" }), _jsxs(Stack, { direction: "row", spacing: 0.5, children: [_jsx(Tooltip, { title: "\u0418\u043C\u043F\u043E\u0440\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u0438\u0437 Swagger/OpenAPI (JSON/YAML)", children: _jsxs(IconButton, { size: "small", component: "label", disabled: swaggerImporting, children: [_jsx(UploadFileIcon, { fontSize: "small" }), _jsx("input", { hidden: true, type: "file", accept: "application/json,.json,.yaml,.yml,text/yaml,application/yaml", onChange: (event) => {
                                                                            const selectedFile = event.target.files?.[0] ?? null;
                                                                            void importEndpointsFromSwaggerFile(selectedFile);
                                                                            event.target.value = "";
                                                                        } })] }) }), _jsx(Tooltip, { title: "\u0414\u043E\u0431\u0430\u0432\u0438\u0442\u044C \u044D\u043D\u0434\u043F\u043E\u0438\u043D\u0442", children: _jsx(IconButton, { size: "small", onClick: openCreateEndpointDialog, sx: { color: "text.secondary", "&:hover": { backgroundColor: "rgba(126,224,255,0.08)", color: "text.primary" } }, children: _jsx(AddIcon, { fontSize: "small" }) }) })] })] }), _jsxs(Stack, { spacing: 1.25, children: [normalizedHostEndpoints.length ? renderEndpointPathTree(endpointPathTree) : null, !normalizedHostEndpoints.length && _jsx(Typography, { color: "text.secondary", children: "\u042D\u043D\u0434\u043F\u043E\u0438\u043D\u0442\u044B \u0434\u043B\u044F \u044D\u0442\u043E\u0433\u043E \u0445\u043E\u0441\u0442\u0430 \u043F\u043E\u043A\u0430 \u043D\u0435 \u0434\u043E\u0431\u0430\u0432\u043B\u0435\u043D\u044B." })] }), _jsxs(Menu, { anchorEl: endpointActionsAnchorEl, open: endpointActionsOpen, onClose: closeEndpointActions, anchorOrigin: { vertical: "bottom", horizontal: "right" }, transformOrigin: { vertical: "top", horizontal: "right" }, children: [_jsxs(MenuItem, { onClick: () => {
                                                        if (activeEndpoint) {
                                                            openEndpointEdit(activeEndpoint);
                                                        }
                                                        closeEndpointActions();
                                                    }, children: [_jsx(EditIcon, { fontSize: "small", sx: { mr: 1 } }), "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C"] }), _jsxs(MenuItem, { onClick: () => {
                                                        if (activeEndpoint) {
                                                            void removeEndpoint(activeEndpoint.id);
                                                        }
                                                        closeEndpointActions();
                                                    }, children: [_jsx(DeleteIcon, { fontSize: "small", sx: { mr: 1 } }), "\u0423\u0434\u0430\u043B\u0438\u0442\u044C"] }), _jsxs(MenuItem, { onClick: () => void copyEndpointRequest("curl"), children: [_jsx(ContentCopyIcon, { fontSize: "small", sx: { mr: 1 } }), "\u0421\u043A\u043E\u043F\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u043A\u0430\u043A cURL"] }), _jsxs(MenuItem, { onClick: () => void copyEndpointRequest("raw"), children: [_jsx(ContentCopyIcon, { fontSize: "small", sx: { mr: 1 } }), "\u0421\u043A\u043E\u043F\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u043A\u0430\u043A Raw"] })] })] }) })), selectedSection === "vulns" &&
                                (isVulnerabilityRoute ? (_jsxs(Stack, { spacing: 3, children: [_jsx(Card, { sx: { border: "1px solid rgba(126,224,255,0.16)", backgroundColor: "rgba(15,27,45,0.82)" }, children: _jsxs(CardContent, { children: [_jsxs(Stack, { direction: { xs: "column", sm: "row" }, justifyContent: "space-between", alignItems: { sm: "center" }, spacing: 1, mb: 2, children: [_jsx(Button, { startIcon: _jsx(ArrowBackIcon, {}), onClick: closeVulnerabilityView, children: "\u041D\u0430\u0437\u0430\u0434" }), _jsx(Tooltip, { title: "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C", children: _jsx("span", { children: _jsx(IconButton, { size: "small", onClick: () => setVulnEditMode(true), disabled: vulnEditMode, sx: { color: "text.secondary", "&:hover": { backgroundColor: "rgba(126,224,255,0.08)", color: "text.primary" } }, children: _jsx(EditIcon, { fontSize: "small" }) }) }) })] }), renderVulnerabilityDetailsContent()] }) }), _jsx(Card, { sx: { border: "1px solid rgba(126,224,255,0.16)", backgroundColor: "rgba(15,27,45,0.82)" }, children: _jsx(CardContent, { children: renderCommentsSection() }) })] })) : (_jsx(Card, { sx: { border: "1px solid rgba(126,224,255,0.14)" }, children: _jsxs(CardContent, { children: [_jsx(Typography, { variant: "h6", fontWeight: 700, mb: 1, children: "\u0423\u044F\u0437\u0432\u0438\u043C\u043E\u0441\u0442\u0438 \u0445\u043E\u0441\u0442\u0430" }), _jsxs(Stack, { spacing: 1, children: [vulnerabilities.map((item) => (_jsxs(Box, { onClick: () => toggleExpandedId(item.id, setExpandedVulnerabilityIds), sx: {
                                                            border: "1px solid rgba(126,224,255,0.12)",
                                                            p: 1.4,
                                                            borderRadius: 0,
                                                            backgroundColor: "rgba(8,17,31,0.24)",
                                                            cursor: "pointer",
                                                            "& .vuln-actions": {
                                                                opacity: 0,
                                                                pointerEvents: "none",
                                                                transition: "opacity 0.15s ease-in-out",
                                                            },
                                                            "&:hover .vuln-actions": {
                                                                opacity: 1,
                                                                pointerEvents: "auto",
                                                            },
                                                        }, children: [_jsxs(Stack, { direction: "row", justifyContent: "space-between", alignItems: "center", children: [_jsx(Typography, { fontWeight: 600, children: item.title }), _jsx(Stack, { direction: "row", spacing: 0.4, alignItems: "center", className: "vuln-actions", children: _jsx(Tooltip, { title: "\u0414\u0435\u0439\u0441\u0442\u0432\u0438\u044F", children: _jsx(IconButton, { size: "small", onClick: (event) => openVulnerabilityActions(event, item), children: _jsx(MoreVertIcon, { fontSize: "small" }) }) }) })] }), _jsx(Collapse, { in: expandedVulnerabilityIds.includes(item.id), timeout: "auto", unmountOnExit: true, children: _jsxs(Stack, { spacing: 1, mt: 0.8, children: [_jsxs(Stack, { direction: "row", spacing: 1, flexWrap: "wrap", useFlexGap: true, children: [item.cwe_id && _jsx(Chip, { size: "small", variant: "outlined", label: item.cwe_id }), item.cvss_version && _jsx(Chip, { size: "small", variant: "outlined", label: `CVSS ${item.cvss_version} ${item.cvss_score ?? "-"}` }), _jsx(Chip, { size: "small", label: item.severity, sx: severityChipSx[item.severity] }), _jsx(Chip, { size: "small", label: item.status, sx: vulnerabilityStatusChipSx[item.status] })] }), _jsx(Typography, { color: "text.secondary", variant: "body2", children: item.impact || "Влияние не указано" }), _jsx(Box, { children: _jsx(Button, { size: "small", variant: "text", onClick: (event) => {
                                                                                    event.stopPropagation();
                                                                                    openVulnerabilityPage(item.id);
                                                                                }, children: "\u041E\u0442\u043A\u0440\u044B\u0442\u044C \u043A\u0430\u0440\u0442\u043E\u0447\u043A\u0443" }) })] }) })] }, item.id))), !vulnerabilities.length && _jsx(Typography, { color: "text.secondary", children: "\u0423\u044F\u0437\u0432\u0438\u043C\u043E\u0441\u0442\u0438, \u043F\u0440\u0438\u0432\u044F\u0437\u0430\u043D\u043D\u044B\u0435 \u043A \u044D\u0442\u043E\u043C\u0443 \u0445\u043E\u0441\u0442\u0443, \u043F\u043E\u043A\u0430 \u043D\u0435 \u0434\u043E\u0431\u0430\u0432\u043B\u0435\u043D\u044B." })] }), _jsxs(Menu, { anchorEl: vulnerabilityActionsAnchorEl, open: vulnerabilityActionsOpen, onClose: closeVulnerabilityActions, anchorOrigin: { vertical: "bottom", horizontal: "right" }, transformOrigin: { vertical: "top", horizontal: "right" }, children: [_jsxs(MenuItem, { onClick: () => {
                                                            if (activeVulnerability) {
                                                                openVulnerabilityPage(activeVulnerability.id);
                                                            }
                                                            closeVulnerabilityActions();
                                                        }, children: [_jsx(EditIcon, { fontSize: "small", sx: { mr: 1 } }), "\u041A\u0430\u0440\u0442\u043E\u0447\u043A\u0430"] }), _jsxs(MenuItem, { onClick: () => {
                                                            if (activeVulnerability) {
                                                                openVulnerabilityEdit(activeVulnerability);
                                                            }
                                                            closeVulnerabilityActions();
                                                        }, children: [_jsx(EditIcon, { fontSize: "small", sx: { mr: 1 } }), "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C"] }), _jsxs(MenuItem, { onClick: () => {
                                                            if (activeVulnerability) {
                                                                void removeVulnerability(activeVulnerability.id);
                                                            }
                                                            closeVulnerabilityActions();
                                                        }, children: [_jsx(DeleteIcon, { fontSize: "small", sx: { mr: 1 } }), "\u0423\u0434\u0430\u043B\u0438\u0442\u044C"] })] })] }) })))] })] }), _jsxs(Dialog, { open: isEditHostOpen, onClose: () => setEditHostOpen(false), fullWidth: true, children: [_jsx(DialogTitle, { children: "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u0445\u043E\u0441\u0442" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [_jsx(TextField, { label: "IP-\u0430\u0434\u0440\u0435\u0441", value: editingHostIp, onChange: (event) => setEditingHostIp(event.target.value) }), _jsx(TextField, { label: "Hostname", value: editingHostName, onChange: (event) => setEditingHostName(event.target.value) }), _jsx(TextField, { multiline: true, minRows: 4, label: "\u041E\u043F\u0438\u0441\u0430\u043D\u0438\u0435", value: editingHostNotes, onChange: (event) => setEditingHostNotes(event.target.value) })] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setEditHostOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", onClick: () => void saveHostInfo(), disabled: !editingHostIp.trim() && !editingHostName.trim(), children: "\u0421\u043E\u0445\u0440\u0430\u043D\u0438\u0442\u044C" })] })] }), _jsxs(Dialog, { open: isEditPortOpen, onClose: () => setEditPortOpen(false), fullWidth: true, children: [_jsx(DialogTitle, { children: "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u043F\u043E\u0440\u0442" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [_jsx(TextField, { label: "\u041D\u043E\u043C\u0435\u0440 \u043F\u043E\u0440\u0442\u0430", type: "number", inputProps: { min: 1, max: 65535 }, value: editingPortNumber, onChange: (event) => setEditingPortNumber(event.target.value) }), _jsxs(TextField, { select: true, label: "\u041F\u0440\u043E\u0442\u043E\u043A\u043E\u043B", value: editingPortProtocol, onChange: (event) => setEditingPortProtocol(event.target.value), children: [_jsx(MenuItem, { value: "tcp", children: "tcp" }), _jsx(MenuItem, { value: "udp", children: "udp" })] }), _jsxs(TextField, { select: true, label: "\u0421\u043E\u0441\u0442\u043E\u044F\u043D\u0438\u0435", value: editingPortState, onChange: (event) => setEditingPortState(event.target.value), children: [_jsx(MenuItem, { value: "open", children: "open" }), _jsx(MenuItem, { value: "closed", children: "closed" }), _jsx(MenuItem, { value: "filtered", children: "filtered" })] })] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setEditPortOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", onClick: () => void savePortEdit(), children: "\u0421\u043E\u0445\u0440\u0430\u043D\u0438\u0442\u044C" })] })] }), _jsxs(Dialog, { open: isCreatePortOpen, onClose: () => setCreatePortOpen(false), fullWidth: true, children: [_jsx(DialogTitle, { children: "\u0414\u043E\u0431\u0430\u0432\u0438\u0442\u044C \u043F\u043E\u0440\u0442" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [_jsx(TextField, { label: "\u041D\u043E\u043C\u0435\u0440 \u043F\u043E\u0440\u0442\u0430", type: "number", inputProps: { min: 1, max: 65535 }, value: creatingPortNumber, onChange: (event) => setCreatingPortNumber(event.target.value) }), _jsxs(TextField, { select: true, label: "\u041F\u0440\u043E\u0442\u043E\u043A\u043E\u043B", value: creatingPortProtocol, onChange: (event) => setCreatingPortProtocol(event.target.value), children: [_jsx(MenuItem, { value: "tcp", children: "tcp" }), _jsx(MenuItem, { value: "udp", children: "udp" })] }), _jsxs(TextField, { select: true, label: "\u0421\u043E\u0441\u0442\u043E\u044F\u043D\u0438\u0435", value: creatingPortState, onChange: (event) => setCreatingPortState(event.target.value), children: [_jsx(MenuItem, { value: "open", children: "open" }), _jsx(MenuItem, { value: "closed", children: "closed" }), _jsx(MenuItem, { value: "filtered", children: "filtered" })] })] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setCreatePortOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", onClick: () => void createHostPort(), children: "\u0421\u043E\u0437\u0434\u0430\u0442\u044C" })] })] }), _jsxs(Dialog, { open: isCreateServiceOpen, onClose: () => setCreateServiceOpen(false), fullWidth: true, children: [_jsx(DialogTitle, { children: "\u0414\u043E\u0431\u0430\u0432\u0438\u0442\u044C \u0441\u0435\u0440\u0432\u0438\u0441" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [_jsx(TextField, { label: "\u041D\u0430\u0437\u0432\u0430\u043D\u0438\u0435 \u0441\u0435\u0440\u0432\u0438\u0441\u0430", value: creatingServiceName, onChange: (event) => setCreatingServiceName(event.target.value) }), _jsx(TextField, { label: "\u0412\u0435\u0440\u0441\u0438\u044F", value: creatingServiceVersion, onChange: (event) => setCreatingServiceVersion(event.target.value) }), _jsx(TextField, { multiline: true, minRows: 3, label: "Banner", value: creatingServiceBanner, onChange: (event) => setCreatingServiceBanner(event.target.value) })] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setCreateServiceOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", onClick: () => void createPortService(), disabled: !creatingServiceName.trim(), children: "\u0421\u043E\u0437\u0434\u0430\u0442\u044C" })] })] }), _jsxs(Dialog, { open: isEditServiceOpen, onClose: () => setEditServiceOpen(false), fullWidth: true, children: [_jsx(DialogTitle, { children: "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u0441\u0435\u0440\u0432\u0438\u0441" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [_jsx(TextField, { label: "\u041D\u0430\u0437\u0432\u0430\u043D\u0438\u0435 \u0441\u0435\u0440\u0432\u0438\u0441\u0430", value: editingServiceName, onChange: (event) => setEditingServiceName(event.target.value) }), _jsx(TextField, { label: "\u0412\u0435\u0440\u0441\u0438\u044F", value: editingServiceVersion, onChange: (event) => setEditingServiceVersion(event.target.value) }), _jsx(TextField, { multiline: true, minRows: 3, label: "Banner", value: editingServiceBanner, onChange: (event) => setEditingServiceBanner(event.target.value) })] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setEditServiceOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", onClick: () => void saveServiceEdit(), disabled: !editingServiceName.trim(), children: "\u0421\u043E\u0445\u0440\u0430\u043D\u0438\u0442\u044C" })] })] }), _jsxs(Dialog, { open: isEditEndpointOpen, onClose: () => setEditEndpointOpen(false), fullWidth: true, maxWidth: "md", children: [_jsx(DialogTitle, { children: "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u044D\u043D\u0434\u043F\u043E\u0438\u043D\u0442" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [_jsx(Stack, { spacing: 1, children: _jsx(TextField, { multiline: true, minRows: 4, label: "\u0412\u0441\u0442\u0430\u0432\u0438\u0442\u044C Raw HTTP \u0437\u0430\u043F\u0440\u043E\u0441", placeholder: "GET /api/items?page=1 HTTP/1.1\nHost: example.com\n\n", value: editingEndpointImportRaw, onChange: (event) => setEditingEndpointImportRaw(event.target.value), helperText: "\u041F\u043E\u043B\u044F \u043D\u0438\u0436\u0435 \u0437\u0430\u043F\u043E\u043B\u043D\u044F\u044E\u0442\u0441\u044F \u0430\u0432\u0442\u043E\u043C\u0430\u0442\u0438\u0447\u0435\u0441\u043A\u0438, \u0435\u0441\u043B\u0438 \u0437\u0430\u043F\u0440\u043E\u0441 \u0443\u0434\u0430\u043B\u043E\u0441\u044C \u0440\u0430\u0437\u043E\u0431\u0440\u0430\u0442\u044C." }) }), _jsx(Divider, {}), editingEndpointImportHostWarn && (_jsxs(Alert, { severity: "warning", children: ["\u0417\u0430\u0433\u043E\u043B\u043E\u0432\u043E\u043A Host \u0438\u0437 \u0437\u0430\u043F\u0440\u043E\u0441\u0430 \u043D\u0435 \u0441\u043E\u0432\u043F\u0430\u0434\u0430\u0435\u0442 \u0441 \u0445\u043E\u0441\u0442\u043E\u043C \u0430\u043A\u0442\u0438\u0432\u0430 (", endpointFormHostLine, "). \u041F\u0440\u043E\u0432\u0435\u0440\u044C\u0442\u0435 \u043F\u0443\u0442\u044C \u0438 \u0446\u0435\u043B\u0435\u0432\u043E\u0439 \u0445\u043E\u0441\u0442."] })), _jsx(TextField, { label: "\u041F\u0443\u0442\u044C", value: editingEndpointPath, onChange: (event) => setEditingEndpointPath(event.target.value) }), _jsx(TextField, { select: true, label: "HTTP-\u043C\u0435\u0442\u043E\u0434", value: editingEndpointMethod, onChange: (event) => {
                                        const next = event.target.value;
                                        setEditingEndpointMethod(next);
                                        if (next === "POST") {
                                            setEditingEndpointQueryString("");
                                        }
                                        if (!methodSupportsRequestBody(next)) {
                                            setEditingEndpointRequestBody("");
                                            setEditingEndpointRequestContentType("application/json");
                                        }
                                    }, children: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map((method) => (_jsx(MenuItem, { value: method, children: method }, method))) }), methodShowsQueryString(editingEndpointMethod) && (_jsx(TextField, { multiline: true, minRows: 2, label: "\u041F\u0430\u0440\u0430\u043C\u0435\u0442\u0440\u044B \u0437\u0430\u043F\u0440\u043E\u0441\u0430 (query string)", placeholder: "foo=bar&limit=10", helperText: "\u041F\u0430\u0440\u044B \u0438\u043C\u044F=\u0437\u043D\u0430\u0447\u0435\u043D\u0438\u0435, \u0440\u0430\u0437\u0434\u0435\u043B\u0438\u0442\u0435\u043B\u044C & \u0438\u043B\u0438 \u043D\u043E\u0432\u0430\u044F \u0441\u0442\u0440\u043E\u043A\u0430", value: editingEndpointQueryString, onChange: (event) => setEditingEndpointQueryString(event.target.value) })), _jsx(TextField, { multiline: true, minRows: 4, label: "\u0417\u0430\u0433\u043E\u043B\u043E\u0432\u043A\u0438", placeholder: "Accept: application/json\nCookie: ... (будет заменён на плейсхолдер при сохранении)", helperText: "\u041A\u0430\u0436\u0434\u044B\u0439 \u0437\u0430\u0433\u043E\u043B\u043E\u0432\u043E\u043A \u0441 \u043D\u043E\u0432\u043E\u0439 \u0441\u0442\u0440\u043E\u043A\u0438: Name: value. Cookie \u0438 Authorization \u043F\u0440\u0438 \u0441\u043E\u0445\u0440\u0430\u043D\u0435\u043D\u0438\u0438 \u043E\u0447\u0438\u0449\u0430\u044E\u0442\u0441\u044F.", value: editingEndpointHeadersText, onChange: (event) => setEditingEndpointHeadersText(event.target.value), sx: { "& textarea": { fontFamily: "ui-monospace, monospace", fontSize: "0.85rem" } } }), methodSupportsRequestBody(editingEndpointMethod) && (_jsxs(_Fragment, { children: [_jsx(TextField, { select: true, label: "Content-Type", value: editingEndpointRequestContentType, onChange: (event) => setEditingEndpointRequestContentType(event.target.value), children: ["application/json", "application/x-www-form-urlencoded", "multipart/form-data", "text/plain", "application/xml"].map((contentType) => (_jsx(MenuItem, { value: contentType, children: contentType }, contentType))) }), _jsx(TextField, { multiline: true, minRows: 6, label: "\u0422\u0435\u043B\u043E \u0437\u0430\u043F\u0440\u043E\u0441\u0430", placeholder: '{"user":"admin"}', value: editingEndpointRequestBody, onChange: (event) => setEditingEndpointRequestBody(event.target.value) })] })), _jsxs(Paper, { variant: "outlined", sx: { p: 1.5, borderColor: "rgba(126,224,255,0.14)" }, children: [_jsx(Typography, { variant: "caption", color: "text.secondary", display: "block", sx: { mb: 1 }, children: "\u041F\u0440\u0435\u0434\u043F\u0440\u043E\u0441\u043C\u043E\u0442\u0440 Raw HTTP" }), _jsx(Box, { component: "pre", sx: {
                                                m: 0,
                                                maxHeight: 220,
                                                overflow: "auto",
                                                fontSize: "0.75rem",
                                                fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
                                                whiteSpace: "pre-wrap",
                                                wordBreak: "break-word",
                                            }, children: editingEndpointPreviewRequest }), _jsxs(Stack, { direction: "row", spacing: 1, flexWrap: "wrap", useFlexGap: true, sx: { mt: 1.5 }, children: [_jsx(Button, { size: "small", variant: "outlined", onClick: () => void copyEditingEndpointDraft("raw"), children: "\u0421\u043A\u043E\u043F\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u043A\u0430\u043A Raw" }), _jsx(Button, { size: "small", variant: "outlined", onClick: () => void copyEditingEndpointDraft("curl"), children: "\u0421\u043A\u043E\u043F\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u043A\u0430\u043A cURL" })] })] })] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setEditEndpointOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", onClick: () => void saveEndpointEdit(), disabled: !editingEndpointPath.trim(), children: "\u0421\u043E\u0445\u0440\u0430\u043D\u0438\u0442\u044C" })] })] }), _jsxs(Dialog, { open: isCreateEndpointOpen, onClose: () => setCreateEndpointOpen(false), fullWidth: true, maxWidth: "md", children: [_jsx(DialogTitle, { children: "\u0414\u043E\u0431\u0430\u0432\u0438\u0442\u044C \u044D\u043D\u0434\u043F\u043E\u0438\u043D\u0442" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [_jsx(Stack, { spacing: 1, children: _jsx(TextField, { multiline: true, minRows: 4, label: "\u0412\u0441\u0442\u0430\u0432\u0438\u0442\u044C Raw HTTP \u0437\u0430\u043F\u0440\u043E\u0441", placeholder: "GET /api/items?page=1 HTTP/1.1\nHost: example.com\n\n", value: creatingEndpointImportRaw, onChange: (event) => setCreatingEndpointImportRaw(event.target.value), helperText: "\u041F\u043E\u043B\u044F \u043D\u0438\u0436\u0435 \u0437\u0430\u043F\u043E\u043B\u043D\u044F\u044E\u0442\u0441\u044F \u0430\u0432\u0442\u043E\u043C\u0430\u0442\u0438\u0447\u0435\u0441\u043A\u0438, \u0435\u0441\u043B\u0438 \u0437\u0430\u043F\u0440\u043E\u0441 \u0443\u0434\u0430\u043B\u043E\u0441\u044C \u0440\u0430\u0437\u043E\u0431\u0440\u0430\u0442\u044C." }) }), _jsx(Divider, {}), creatingEndpointImportHostWarn && (_jsxs(Alert, { severity: "warning", children: ["\u0417\u0430\u0433\u043E\u043B\u043E\u0432\u043E\u043A Host \u0438\u0437 \u0437\u0430\u043F\u0440\u043E\u0441\u0430 \u043D\u0435 \u0441\u043E\u0432\u043F\u0430\u0434\u0430\u0435\u0442 \u0441 \u0445\u043E\u0441\u0442\u043E\u043C \u0430\u043A\u0442\u0438\u0432\u0430 (", endpointFormHostLine, "). \u041F\u0440\u043E\u0432\u0435\u0440\u044C\u0442\u0435 \u043F\u0443\u0442\u044C \u0438 \u0446\u0435\u043B\u0435\u0432\u043E\u0439 \u0445\u043E\u0441\u0442."] })), _jsx(TextField, { label: "\u041F\u0443\u0442\u044C", value: creatingEndpointPath, onChange: (event) => setCreatingEndpointPath(event.target.value) }), _jsx(TextField, { select: true, label: "HTTP-\u043C\u0435\u0442\u043E\u0434", value: creatingEndpointMethod, onChange: (event) => {
                                        const next = event.target.value;
                                        setCreatingEndpointMethod(next);
                                        if (next === "POST") {
                                            setCreatingEndpointQueryString("");
                                        }
                                        if (!methodSupportsRequestBody(next)) {
                                            setCreatingEndpointRequestBody("");
                                            setCreatingEndpointRequestContentType("application/json");
                                        }
                                    }, children: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map((method) => (_jsx(MenuItem, { value: method, children: method }, method))) }), methodShowsQueryString(creatingEndpointMethod) && (_jsx(TextField, { multiline: true, minRows: 2, label: "\u041F\u0430\u0440\u0430\u043C\u0435\u0442\u0440\u044B \u0437\u0430\u043F\u0440\u043E\u0441\u0430 (query string)", placeholder: "foo=bar&limit=10", helperText: "\u041F\u0430\u0440\u044B \u0438\u043C\u044F=\u0437\u043D\u0430\u0447\u0435\u043D\u0438\u0435, \u0440\u0430\u0437\u0434\u0435\u043B\u0438\u0442\u0435\u043B\u044C & \u0438\u043B\u0438 \u043D\u043E\u0432\u0430\u044F \u0441\u0442\u0440\u043E\u043A\u0430", value: creatingEndpointQueryString, onChange: (event) => setCreatingEndpointQueryString(event.target.value) })), _jsx(TextField, { multiline: true, minRows: 4, label: "\u0417\u0430\u0433\u043E\u043B\u043E\u0432\u043A\u0438", placeholder: "Accept: application/json\nAuthorization: Bearer ...", helperText: "\u041A\u0430\u0436\u0434\u044B\u0439 \u0437\u0430\u0433\u043E\u043B\u043E\u0432\u043E\u043A \u0441 \u043D\u043E\u0432\u043E\u0439 \u0441\u0442\u0440\u043E\u043A\u0438: Name: value. Cookie \u0438 Authorization \u043F\u0440\u0438 \u0441\u043E\u0445\u0440\u0430\u043D\u0435\u043D\u0438\u0438 \u043E\u0447\u0438\u0449\u0430\u044E\u0442\u0441\u044F.", value: creatingEndpointHeadersText, onChange: (event) => setCreatingEndpointHeadersText(event.target.value), sx: { "& textarea": { fontFamily: "ui-monospace, monospace", fontSize: "0.85rem" } } }), methodSupportsRequestBody(creatingEndpointMethod) && (_jsxs(_Fragment, { children: [_jsx(TextField, { select: true, label: "Content-Type", value: creatingEndpointRequestContentType, onChange: (event) => setCreatingEndpointRequestContentType(event.target.value), children: ["application/json", "application/x-www-form-urlencoded", "multipart/form-data", "text/plain", "application/xml"].map((contentType) => (_jsx(MenuItem, { value: contentType, children: contentType }, contentType))) }), _jsx(TextField, { multiline: true, minRows: 6, label: "\u0422\u0435\u043B\u043E \u0437\u0430\u043F\u0440\u043E\u0441\u0430", placeholder: '{"user":"admin"}', value: creatingEndpointRequestBody, onChange: (event) => setCreatingEndpointRequestBody(event.target.value) })] })), _jsxs(Paper, { variant: "outlined", sx: { p: 1.5, borderColor: "rgba(126,224,255,0.14)" }, children: [_jsx(Typography, { variant: "caption", color: "text.secondary", display: "block", sx: { mb: 1 }, children: "\u041F\u0440\u0435\u0434\u043F\u0440\u043E\u0441\u043C\u043E\u0442\u0440 Raw HTTP" }), _jsx(Box, { component: "pre", sx: {
                                                m: 0,
                                                maxHeight: 220,
                                                overflow: "auto",
                                                fontSize: "0.75rem",
                                                fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
                                                whiteSpace: "pre-wrap",
                                                wordBreak: "break-word",
                                            }, children: creatingEndpointPreviewRequest }), _jsxs(Stack, { direction: "row", spacing: 1, flexWrap: "wrap", useFlexGap: true, sx: { mt: 1.5 }, children: [_jsx(Button, { size: "small", variant: "outlined", onClick: () => void copyCreatingEndpointDraft("raw"), children: "\u0421\u043A\u043E\u043F\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u043A\u0430\u043A Raw" }), _jsx(Button, { size: "small", variant: "outlined", onClick: () => void copyCreatingEndpointDraft("curl"), children: "\u0421\u043A\u043E\u043F\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u043A\u0430\u043A cURL" })] })] })] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setCreateEndpointOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", onClick: () => void createHostEndpoint(), disabled: !creatingEndpointPath.trim(), children: "\u0421\u043E\u0437\u0434\u0430\u0442\u044C" })] })] }), _jsxs(Dialog, { open: !isVulnerabilityRoute && vulnDetailOpen, onClose: closeVulnerabilityView, fullWidth: true, maxWidth: "lg", children: [_jsx(DialogTitle, { children: "\u041A\u0430\u0440\u0442\u043E\u0447\u043A\u0430 \u0443\u044F\u0437\u0432\u0438\u043C\u043E\u0441\u0442\u0438" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 3, sx: { mt: 0.5 }, children: [renderVulnerabilityDetailsContent(), _jsx(Divider, {}), renderCommentsSection()] }) }), _jsxs(DialogActions, { sx: { px: 3, pb: 3, pt: 1.5 }, children: [_jsx(Button, { onClick: closeVulnerabilityView, children: "\u0417\u0430\u043A\u0440\u044B\u0442\u044C" }), !vulnEditMode && (_jsx(Tooltip, { title: "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C", children: _jsx("span", { children: _jsx(IconButton, { onClick: () => setVulnEditMode(true), disabled: !activeVulnDetails, sx: { color: "text.secondary", "&:hover": { backgroundColor: "rgba(126,224,255,0.08)", color: "text.primary" } }, children: _jsx(EditIcon, { fontSize: "small" }) }) }) }))] })] }), _jsxs(Dialog, { open: editCommentOpen, onClose: () => setEditCommentOpen(false), fullWidth: true, maxWidth: "sm", children: [_jsx(DialogTitle, { children: "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u043A\u043E\u043C\u043C\u0435\u043D\u0442\u0430\u0440\u0438\u0439" }), _jsx(DialogContent, { children: _jsx(TextField, { fullWidth: true, multiline: true, minRows: 4, sx: { mt: 1 }, value: editingCommentContent, onChange: (event) => setEditingCommentContent(event.target.value) }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setEditCommentOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", onClick: () => void saveCommentEdit(), disabled: !editingCommentContent.trim() || vulnBusy, children: "\u0421\u043E\u0445\u0440\u0430\u043D\u0438\u0442\u044C" })] })] }), _jsxs(Dialog, { open: isEditVulnerabilityOpen, onClose: () => setEditVulnerabilityOpen(false), fullWidth: true, children: [_jsx(DialogTitle, { children: "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u0443\u044F\u0437\u0432\u0438\u043C\u043E\u0441\u0442\u044C" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [_jsx(TextField, { label: "\u041D\u0430\u0437\u0432\u0430\u043D\u0438\u0435", value: editingVulnerabilityTitle, onChange: (event) => setEditingVulnerabilityTitle(event.target.value) }), _jsx(TextField, { multiline: true, minRows: 3, label: "\u041E\u043F\u0438\u0441\u0430\u043D\u0438\u0435", value: editingVulnerabilityDescription, onChange: (event) => setEditingVulnerabilityDescription(event.target.value) }), _jsxs(TextField, { select: true, label: "\u041A\u0440\u0438\u0442\u0438\u0447\u043D\u043E\u0441\u0442\u044C", value: editingVulnerabilitySeverity, onChange: (event) => setEditingVulnerabilitySeverity(event.target.value), children: [_jsx(MenuItem, { value: "critical", children: "critical" }), _jsx(MenuItem, { value: "high", children: "high" }), _jsx(MenuItem, { value: "medium", children: "medium" }), _jsx(MenuItem, { value: "low", children: "low" }), _jsx(MenuItem, { value: "info", children: "info" })] }), _jsxs(TextField, { select: true, label: "\u0421\u0442\u0430\u0442\u0443\u0441", value: editingVulnerabilityStatus, onChange: (event) => setEditingVulnerabilityStatus(event.target.value), children: [_jsx(MenuItem, { value: "open", children: "open" }), _jsx(MenuItem, { value: "in_progress", children: "in_progress" }), _jsx(MenuItem, { value: "fixed", children: "fixed" }), _jsx(MenuItem, { value: "wont_fix", children: "wont_fix" }), _jsx(MenuItem, { value: "accepted_risk", children: "accepted_risk" })] })] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setEditVulnerabilityOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", onClick: () => void saveVulnerabilityEdit(), disabled: !editingVulnerabilityTitle.trim(), children: "\u0421\u043E\u0445\u0440\u0430\u043D\u0438\u0442\u044C" })] })] }), _jsxs(Dialog, { open: isCreateVulnerabilityOpen, onClose: () => setCreateVulnerabilityOpen(false), fullWidth: true, children: [_jsx(DialogTitle, { children: "\u0414\u043E\u0431\u0430\u0432\u0438\u0442\u044C \u0443\u044F\u0437\u0432\u0438\u043C\u043E\u0441\u0442\u044C \u043A \u0445\u043E\u0441\u0442\u0443" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [_jsxs(Grid, { container: true, spacing: 2, children: [_jsx(Grid, { size: { xs: 12, md: 7 }, children: _jsx(TextField, { label: "\u041D\u0430\u0437\u0432\u0430\u043D\u0438\u0435", value: creatingVulnerabilityTitle, onChange: (event) => setCreatingVulnerabilityTitle(event.target.value), fullWidth: true }) }), _jsx(Grid, { size: { xs: 12, md: 3 }, children: _jsx(TextField, { label: "CWE ID", value: creatingVulnerabilityCweId, onChange: (event) => setCreatingVulnerabilityCweId(event.target.value), fullWidth: true }) }), _jsx(Grid, { size: { xs: 12, md: 2 }, children: _jsxs(TextField, { select: true, label: "\u0421\u0442\u0430\u0442\u0443\u0441", value: creatingVulnerabilityStatus, onChange: (event) => setCreatingVulnerabilityStatus(event.target.value), fullWidth: true, children: [_jsx(MenuItem, { value: "open", children: "open" }), _jsx(MenuItem, { value: "in_progress", children: "in_progress" }), _jsx(MenuItem, { value: "fixed", children: "fixed" }), _jsx(MenuItem, { value: "wont_fix", children: "wont_fix" }), _jsx(MenuItem, { value: "accepted_risk", children: "accepted_risk" })] }) }), _jsx(Grid, { size: { xs: 12, md: 2 }, children: _jsx(TextField, { label: "\u041A\u0440\u0438\u0442\u0438\u0447\u043D\u043E\u0441\u0442\u044C", value: creatingVulnerabilitySeverity, slotProps: { input: { readOnly: true } }, fullWidth: true }) }), _jsx(Grid, { size: { xs: 12, md: 2 }, children: _jsx(TextField, { label: "CVSS score", type: "number", inputProps: { min: 0, max: 10, step: 0.1 }, value: creatingVulnerabilityCvssScore, slotProps: { input: { readOnly: true } }, fullWidth: true }) }), _jsx(Grid, { size: { xs: 12, md: 8 }, children: _jsx(TextField, { label: "CVSS vector", value: creatingVulnerabilityCvssVector, onChange: (event) => {
                                                    const nextVector = event.target.value;
                                                    const { score } = calculateCvssScore(CVSS_VERSION, nextVector || null);
                                                    setCreatingVulnerabilityCvssVector(nextVector);
                                                    setCreatingVulnerabilityCvssScore(score === null ? "" : String(score));
                                                    setCreatingVulnerabilitySeverity(severityFromCvssScore(score));
                                                }, fullWidth: true }) })] }), _jsx(VulnerabilityStagesEditor, { stages: creatingVulnerabilityStages, endpoints: normalizedHostEndpoints, hostLabel: host?.hostname || host?.ip_address || undefined, onChange: setCreatingVulnerabilityStages }), _jsx(TextField, { multiline: true, minRows: 3, label: "\u0412\u043B\u0438\u044F\u043D\u0438\u0435", value: creatingVulnerabilityImpact, onChange: (event) => setCreatingVulnerabilityImpact(event.target.value) }), _jsx(TextField, { multiline: true, minRows: 3, label: "\u0420\u0435\u043A\u043E\u043C\u0435\u043D\u0434\u0430\u0446\u0438\u0438", value: creatingVulnerabilityRecommendations, onChange: (event) => setCreatingVulnerabilityRecommendations(event.target.value) })] }) }), _jsxs(DialogActions, { sx: { px: 3, pb: 3, pt: 1.5 }, children: [_jsx(Button, { onClick: () => setCreateVulnerabilityOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", size: "large", sx: { minWidth: 180 }, onClick: () => void createHostVulnerability(), disabled: !creatingVulnerabilityTitle.trim(), children: "\u0421\u043E\u0437\u0434\u0430\u0442\u044C" })] })] })] }));
}
