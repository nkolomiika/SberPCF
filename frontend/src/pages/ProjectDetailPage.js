import { jsxs as _jsxs, jsx as _jsx, Fragment as _Fragment } from "react/jsx-runtime";
import AccessTimeIcon from "@mui/icons-material/AccessTime";
import DeleteOutlineIcon from "@mui/icons-material/DeleteOutline";
import DownloadIcon from "@mui/icons-material/Download";
import EditIcon from "@mui/icons-material/Edit";
import FlagIcon from "@mui/icons-material/Flag";
import MoreVertIcon from "@mui/icons-material/MoreVert";
import UploadFileIcon from "@mui/icons-material/UploadFile";
import { Avatar, Box, Button, Card, CardContent, Checkbox, Chip, Dialog, DialogActions, DialogContent, DialogTitle, Divider, Grid2 as Grid, IconButton, List, ListItem, ListItemText, Menu, MenuItem, Stack, TextField, Tooltip, Typography, } from "@mui/material";
import { useCallback, useEffect, useMemo, useState } from "react";
import ReactMarkdown from "react-markdown";
import { useNavigate, useParams } from "react-router-dom";
import { createHost, createVulnerabilityComment, deleteHost, addProjectMember, deleteVulnerabilityComment, getApiErrorMessage, generateProjectReport, getEndpoints, getHostVulnerabilities, getHosts, getPorts, getProjectMembers, getUsers, getProject, getVulnerability, importProjectData, listVulnerabilityComments, removeProjectMember, updateProject, updateVulnerabilityComment, updateVulnerability, uploadVulnerabilityFile, } from "../api";
import { calculateCvssScore, severityFromCvssScore } from "../cvss";
import { PROJECT_STATUS_LABELS, PROJECT_STATUS_ORDER } from "../projectStatus";
import { ProjectTreeNav } from "../components/ProjectTreeNav";
import { VulnerabilityStagesEditor } from "../components/VulnerabilityStagesEditor";
import { useAuthStore } from "../store";
import { useErrorToast } from "../useErrorToast";
const DAY_IN_MS = 24 * 60 * 60 * 1000;
const CVSS_VERSION = "4.0";
const UUID_PATH_SEGMENT_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const normalizeEndpointDisplayPath = (pathValue) => {
    const raw = (pathValue || "/").trim().replace(/\/+/g, "/");
    if (!raw || raw === "/") {
        return "/";
    }
    const withSlash = raw.startsWith("/") ? raw : `/${raw}`;
    const trimmed = withSlash.length > 1 && withSlash.endsWith("/") ? withSlash.slice(0, -1) || "/" : withSlash;
    const segments = trimmed
        .split("/")
        .filter(Boolean)
        .map((segment) => (UUID_PATH_SEGMENT_RE.test(segment) ? "{UUID}" : segment));
    return segments.length ? `/${segments.join("/")}` : "/";
};
const dedupeEndpointsByNormalizedPath = (endpoints) => {
    const deduped = new Map();
    for (const endpoint of endpoints) {
        const normalizedPath = normalizeEndpointDisplayPath(endpoint.path);
        const key = `${(endpoint.method || "GET").toUpperCase()} ${normalizedPath}`;
        const candidate = { ...endpoint, path: normalizedPath };
        const existing = deduped.get(key);
        deduped.set(key, existing
            ? {
                ...existing,
                description: existing.description || candidate.description,
                query_params: existing.query_params?.length ? existing.query_params : candidate.query_params,
                request_body: existing.request_body || candidate.request_body,
                request_content_type: existing.request_content_type || candidate.request_content_type,
                request_headers: existing.request_headers?.length ? existing.request_headers : candidate.request_headers,
            }
            : candidate);
    }
    return Array.from(deduped.values());
};
const toDateInputValue = (date) => {
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, "0");
    const day = String(date.getDate()).padStart(2, "0");
    return `${year}-${month}-${day}`;
};
const parseIsoDateOnly = (value) => {
    if (!value) {
        return null;
    }
    const parsed = new Date(`${value}T00:00:00`);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
};
const parseIsoDateTimeToDateOnly = (value) => {
    if (!value) {
        return null;
    }
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
        return null;
    }
    parsed.setHours(0, 0, 0, 0);
    return parsed;
};
export function ProjectDetailPage() {
    const { projectId } = useParams();
    const navigate = useNavigate();
    const user = useAuthStore((s) => s.user);
    const [hosts, setHosts] = useState([]);
    const [ports, setPorts] = useState([]);
    const [endpoints, setEndpoints] = useState([]);
    const normalizedEndpoints = useMemo(() => dedupeEndpointsByNormalizedPath(endpoints), [endpoints]);
    const [vulnerabilities, setVulnerabilities] = useState([]);
    const [error, setError] = useState(null);
    const [selectedHostId, setSelectedHostId] = useState(null);
    const [selectedSection, setSelectedSection] = useState("overview");
    const [isSidebarCollapsed, setSidebarCollapsed] = useState(false);
    const [projectName, setProjectName] = useState("");
    const [projectDescription, setProjectDescription] = useState("");
    const [projectStatus, setProjectStatus] = useState("active");
    const [projectStartDate, setProjectStartDate] = useState(null);
    const [projectEndDate, setProjectEndDate] = useState(null);
    const [projectTimelineFrozenAt, setProjectTimelineFrozenAt] = useState(null);
    const [projectMembers, setProjectMembers] = useState([]);
    const [usersCatalog, setUsersCatalog] = useState([]);
    const [membersDialogOpen, setMembersDialogOpen] = useState(false);
    const [removeMembersDialogOpen, setRemoveMembersDialogOpen] = useState(false);
    const [selectedAvailableMemberIds, setSelectedAvailableMemberIds] = useState([]);
    const [memberSearchQuery, setMemberSearchQuery] = useState("");
    const [selectedMemberIds, setSelectedMemberIds] = useState([]);
    const [membersBusy, setMembersBusy] = useState(false);
    const [hostStatsById, setHostStatsById] = useState({});
    const [importOpen, setImportOpen] = useState(false);
    const [importFile, setImportFile] = useState(null);
    const [importing, setImporting] = useState(false);
    const [importSummary, setImportSummary] = useState(null);
    const [reportLoadingFormat, setReportLoadingFormat] = useState(null);
    const [actionsAnchorEl, setActionsAnchorEl] = useState(null);
    const [hostsMenuAnchorEl, setHostsMenuAnchorEl] = useState(null);
    const [membersMenuAnchorEl, setMembersMenuAnchorEl] = useState(null);
    const [exportOpen, setExportOpen] = useState(false);
    const [exportFormat, setExportFormat] = useState("pdf");
    const [extendDialogOpen, setExtendDialogOpen] = useState(false);
    const [statusDialogOpen, setStatusDialogOpen] = useState(false);
    const [projectEditDialogOpen, setProjectEditDialogOpen] = useState(false);
    const [projectDescriptionEditOpen, setProjectDescriptionEditOpen] = useState(false);
    const [projectDraftName, setProjectDraftName] = useState("");
    const [projectDraftStartDate, setProjectDraftStartDate] = useState("");
    const [projectDraftEndDate, setProjectDraftEndDate] = useState("");
    const [projectDraftDescription, setProjectDraftDescription] = useState("");
    const [projectSaving, setProjectSaving] = useState(false);
    const [pendingProjectStatus, setPendingProjectStatus] = useState("active");
    const [extendEndDate, setExtendEndDate] = useState("");
    const [extendingProject, setExtendingProject] = useState(false);
    const storagePrefix = projectId ? `project-detail:${projectId}` : null;
    const [hostOpen, setHostOpen] = useState(false);
    const [removeHostsDialogOpen, setRemoveHostsDialogOpen] = useState(false);
    const [selectedHostIds, setSelectedHostIds] = useState([]);
    const [hostIp, setHostIp] = useState("");
    const [hostName, setHostName] = useState("");
    const [hostNotes, setHostNotes] = useState("");
    const [vulnDetailOpen, setVulnDetailOpen] = useState(false);
    const [activeVuln, setActiveVuln] = useState(null);
    const [vulnComments, setVulnComments] = useState([]);
    const [newComment, setNewComment] = useState("");
    const [vulnBusy, setVulnBusy] = useState(false);
    const [vulnEditMode, setVulnEditMode] = useState(false);
    const [editCommentOpen, setEditCommentOpen] = useState(false);
    const [editingCommentId, setEditingCommentId] = useState(null);
    const [editingCommentContent, setEditingCommentContent] = useState("");
    const [commentActionsAnchorEl, setCommentActionsAnchorEl] = useState(null);
    const [activeComment, setActiveComment] = useState(null);
    useErrorToast(error);
    const membersDialogUsers = useMemo(() => {
        const memberById = new Map(projectMembers.map((member) => [member.user_id, member]));
        const catalogIds = new Set(usersCatalog.map((candidate) => candidate.id));
        const mergedUsers = [
            ...usersCatalog.map((candidate) => ({
                id: candidate.id,
                username: candidate.username,
                email: candidate.email,
                role: candidate.role,
                inProject: memberById.has(candidate.id),
            })),
            ...projectMembers
                .filter((member) => !catalogIds.has(member.user_id))
                .map((member) => ({
                id: member.user_id,
                username: member.username,
                email: member.email,
                role: member.role,
                inProject: true,
            })),
        ];
        const normalizedQuery = memberSearchQuery.trim().toLowerCase();
        return mergedUsers
            .filter((candidate) => !normalizedQuery || candidate.username.toLowerCase().includes(normalizedQuery))
            .sort((left, right) => Number(right.inProject) - Number(left.inProject) || left.username.localeCompare(right.username, "ru-RU"));
    }, [memberSearchQuery, projectMembers, usersCatalog]);
    const loadProjectData = useCallback(async () => {
        if (!projectId) {
            return;
        }
        try {
            const [hostsResp, projectResp, membersResp] = await Promise.all([
                getHosts(projectId),
                getProject(projectId),
                getProjectMembers(projectId),
            ]);
            setHosts(hostsResp.items);
            setProjectMembers(membersResp);
            setProjectName(projectResp.name ?? projectId);
            setProjectDescription(projectResp.description ?? "");
            setProjectStatus(projectResp.status);
            setProjectStartDate(projectResp.start_date);
            setProjectEndDate(projectResp.end_date);
            setProjectTimelineFrozenAt(projectResp.timeline_frozen_at);
            setSelectedHostId((previousHostId) => {
                const storedHostId = storagePrefix ? window.localStorage.getItem(`${storagePrefix}:selectedHostId`) : null;
                if (previousHostId && hostsResp.items.some((host) => host.id === previousHostId)) {
                    return previousHostId;
                }
                if (storedHostId && hostsResp.items.some((host) => host.id === storedHostId)) {
                    return storedHostId;
                }
                return hostsResp.items[0]?.id ?? null;
            });
        }
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось загрузить данные проекта"));
        }
    }, [projectId, storagePrefix]);
    const loadHostAssets = useCallback(async () => {
        if (!projectId || !selectedHostId) {
            setPorts([]);
            setEndpoints([]);
            setVulnerabilities([]);
            return;
        }
        try {
            const [portsResp, endpointsResp, vulnsResp] = await Promise.all([
                getPorts(projectId, selectedHostId),
                getEndpoints(projectId, selectedHostId),
                getHostVulnerabilities(projectId, selectedHostId),
            ]);
            setPorts(portsResp);
            setEndpoints(endpointsResp);
            setVulnerabilities(vulnsResp.items);
        }
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось загрузить структуру выбранного хоста"));
        }
    }, [projectId, selectedHostId]);
    useEffect(() => {
        void loadProjectData();
    }, [loadProjectData]);
    useEffect(() => {
        void loadHostAssets();
    }, [loadHostAssets]);
    useEffect(() => {
        if (!projectId || hosts.length === 0) {
            setHostStatsById({});
            return;
        }
        const loadStats = async () => {
            const statsEntries = await Promise.allSettled(hosts.map(async (host) => {
                if (host.id === selectedHostId) {
                    return [
                        host.id,
                        {
                            portsCount: ports.length,
                            endpointsCount: endpoints.length,
                            vulnerabilitiesCount: vulnerabilities.length,
                        },
                    ];
                }
                const [hostPorts, hostEndpoints, hostVulns] = await Promise.all([
                    getPorts(projectId, host.id),
                    getEndpoints(projectId, host.id),
                    getHostVulnerabilities(projectId, host.id),
                ]);
                return [
                    host.id,
                    {
                        portsCount: hostPorts.length,
                        endpointsCount: hostEndpoints.length,
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
            if (selectedHostId) {
                mappedStats[selectedHostId] = {
                    portsCount: ports.length,
                    endpointsCount: endpoints.length,
                    vulnerabilitiesCount: vulnerabilities.length,
                };
            }
            setHostStatsById(mappedStats);
        };
        void loadStats();
    }, [projectId, hosts, selectedHostId, ports.length, endpoints.length, vulnerabilities.length]);
    useEffect(() => {
        if (!projectId) {
            return;
        }
        const wsProtocol = window.location.protocol === "https:" ? "wss" : "ws";
        const ws = new WebSocket(`${wsProtocol}://${window.location.host}/ws/projects/${projectId}`);
        ws.onmessage = () => {
            void loadProjectData();
            void loadHostAssets();
        };
        return () => ws.close();
    }, [projectId, loadHostAssets, loadProjectData]);
    useEffect(() => {
        if (!storagePrefix) {
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
    }, [storagePrefix]);
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
        if (!storagePrefix || !selectedHostId) {
            return;
        }
        window.localStorage.setItem(`${storagePrefix}:selectedHostId`, selectedHostId);
    }, [selectedHostId, storagePrefix]);
    const severityStats = useMemo(() => {
        const stats = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        vulnerabilities.forEach((item) => {
            stats[item.severity] += 1;
        });
        return stats;
    }, [vulnerabilities]);
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
    const projectTimeMetrics = useMemo(() => {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const startRaw = parseIsoDateOnly(projectStartDate);
        const endRaw = parseIsoDateOnly(projectEndDate);
        const start = startRaw ?? (endRaw ? new Date(endRaw.getTime() - 14 * DAY_IN_MS) : null);
        const end = endRaw ?? (startRaw ? new Date(startRaw.getTime() + 14 * DAY_IN_MS) : null);
        if (!start || !end || end.getTime() <= start.getTime()) {
            return {
                startLabel: start ? start.toLocaleDateString("ru-RU") : "не задано",
                endLabel: end ? end.toLocaleDateString("ru-RU") : "не задано",
                daysLeft: null,
                statusTone: "neutral",
                statusLabel: projectStatus === "active" ? "Стандартный срок: 14 дней" : `Статус: ${PROJECT_STATUS_LABELS[projectStatus]}`,
            };
        }
        if (projectStatus !== "active") {
            return {
                startLabel: start.toLocaleDateString("ru-RU"),
                endLabel: end.toLocaleDateString("ru-RU"),
                daysLeft: null,
                statusTone: "neutral",
                statusLabel: `Статус: ${PROJECT_STATUS_LABELS[projectStatus]}`,
            };
        }
        const daysLeft = Math.ceil((end.getTime() - today.getTime()) / DAY_IN_MS);
        if (daysLeft < 0) {
            return {
                startLabel: start.toLocaleDateString("ru-RU"),
                endLabel: end.toLocaleDateString("ru-RU"),
                daysLeft,
                statusTone: "error",
                statusLabel: "Просрочен",
            };
        }
        if (daysLeft <= 2) {
            return {
                startLabel: start.toLocaleDateString("ru-RU"),
                endLabel: end.toLocaleDateString("ru-RU"),
                daysLeft,
                statusTone: "warning",
                statusLabel: "Отчёт: последние 2 дня",
            };
        }
        return {
            startLabel: start.toLocaleDateString("ru-RU"),
            endLabel: end.toLocaleDateString("ru-RU"),
            daysLeft,
            statusTone: "success",
            statusLabel: "В графике",
        };
    }, [projectEndDate, projectStartDate, projectStatus]);
    const timelineBar = useMemo(() => {
        const startRaw = parseIsoDateOnly(projectStartDate);
        const endRaw = parseIsoDateOnly(projectEndDate);
        const start = startRaw ?? (endRaw ? new Date(endRaw.getTime() - 14 * DAY_IN_MS) : null);
        const end = endRaw ?? (startRaw ? new Date(startRaw.getTime() + 14 * DAY_IN_MS) : null);
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const frozenAtFallback = new Date(Math.min(today.getTime(), end?.getTime() ?? today.getTime()));
        const frozenAt = parseIsoDateTimeToDateOnly(projectTimelineFrozenAt) ?? frozenAtFallback;
        const effectiveToday = projectStatus === "active" ? today : new Date(Math.min(frozenAt.getTime(), end?.getTime() ?? frozenAt.getTime()));
        if (!start || !end || end.getTime() <= start.getTime()) {
            return {
                ready: false,
            };
        }
        const totalDays = Math.max(1, Math.ceil((end.getTime() - start.getTime()) / DAY_IN_MS));
        const elapsedInclusive = Math.floor((effectiveToday.getTime() - start.getTime()) / DAY_IN_MS) + 1;
        const passedDays = Math.max(0, Math.min(totalDays, elapsedInclusive));
        const reportStartIndex = Math.max(0, totalDays - 2);
        const cells = Array.from({ length: totalDays }, (_, index) => {
            const cellDate = new Date(start.getTime() + index * DAY_IN_MS);
            const isElapsed = index < passedDays;
            const isReportWindow = index >= reportStartIndex;
            const isToday = cellDate.getTime() === today.getTime();
            let bgColor = "rgba(148,163,184,0.14)";
            if (isElapsed && isReportWindow) {
                bgColor = "rgba(255,152,0,0.5)";
            }
            else if (isElapsed) {
                bgColor = "rgba(76,175,80,0.5)";
            }
            else if (isReportWindow) {
                bgColor = "rgba(255,152,0,0.2)";
            }
            return { bgColor, isToday };
        });
        return {
            ready: true,
            totalDays,
            cells,
            startLabel: start.toLocaleDateString("ru-RU"),
            endLabel: end.toLocaleDateString("ru-RU"),
        };
    }, [projectEndDate, projectStartDate, projectStatus, projectTimelineFrozenAt]);
    const submitHost = async () => {
        if (!projectId) {
            return;
        }
        await createHost(projectId, {
            ip_address: hostIp || undefined,
            hostname: hostName || undefined,
            notes: hostNotes || undefined,
        });
        setHostOpen(false);
        setHostIp("");
        setHostName("");
        setHostNotes("");
        await loadProjectData();
    };
    const selectedHost = hosts.find((host) => host.id === selectedHostId) ?? null;
    const hostLabel = selectedHost ? selectedHost.hostname || selectedHost.ip_address || "unknown-host" : "Хост не выбран";
    const loadVulnerabilityDetails = async (vulnerabilityId) => {
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
            setActiveVuln(vulnDetail);
            setVulnComments(commentsPage.items);
            setVulnEditMode(false);
            setVulnDetailOpen(true);
        }
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось загрузить карточку уязвимости"));
        }
        finally {
            setVulnBusy(false);
        }
    };
    const saveActiveVulnerability = async () => {
        if (!projectId || !activeVuln) {
            return;
        }
        setVulnBusy(true);
        setError(null);
        try {
            const updated = await updateVulnerability(projectId, activeVuln.id, {
                title: activeVuln.title,
                description: activeVuln.description || null,
                severity: activeVuln.severity,
                status: activeVuln.status,
                cvss_version: activeVuln.cvss_vector?.trim() ? CVSS_VERSION : null,
                cvss_score: activeVuln.cvss_score,
                cvss_vector: activeVuln.cvss_vector,
                cwe_id: activeVuln.cwe_id,
                workflow_steps: activeVuln.workflow_steps,
                steps_to_reproduce: activeVuln.steps_to_reproduce || null,
                impact: activeVuln.impact || null,
                recommendations: activeVuln.recommendations || null,
            });
            setActiveVuln((prev) => (prev ? { ...prev, ...updated } : prev));
            setVulnEditMode(false);
            await loadHostAssets();
        }
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось сохранить уязвимость"));
        }
        finally {
            setVulnBusy(false);
        }
    };
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
    const addCommentToActiveVuln = async () => {
        if (!projectId || !activeVuln || !newComment.trim()) {
            return;
        }
        setVulnBusy(true);
        try {
            const created = await createVulnerabilityComment(projectId, activeVuln.id, newComment.trim());
            setVulnComments((prev) => [...prev, created]);
            setNewComment("");
        }
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось добавить комментарий"));
        }
        finally {
            setVulnBusy(false);
        }
    };
    const removeCommentFromActiveVuln = async (commentId) => {
        if (!projectId || !activeVuln) {
            return;
        }
        setVulnBusy(true);
        try {
            await deleteVulnerabilityComment(projectId, activeVuln.id, commentId);
            setVulnComments((prev) => prev.filter((comment) => comment.id !== commentId));
        }
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось удалить комментарий"));
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
        if (!projectId || !activeVuln || !editingCommentId || !editingCommentContent.trim()) {
            return;
        }
        setVulnBusy(true);
        try {
            const updated = await updateVulnerabilityComment(projectId, activeVuln.id, editingCommentId, editingCommentContent.trim());
            setVulnComments((prev) => prev.map((comment) => (comment.id === updated.id ? updated : comment)));
            setEditCommentOpen(false);
            setEditingCommentId(null);
            setEditingCommentContent("");
        }
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось обновить комментарий"));
        }
        finally {
            setVulnBusy(false);
        }
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
                        const canManageComment = user?.id === comment.user_id;
                        return (_jsx(ListItem, { alignItems: "flex-start", sx: canManageComment
                                ? {
                                    "&:hover .comment-row-actions, &:focus-within .comment-row-actions": {
                                        opacity: 1,
                                        pointerEvents: "auto",
                                    },
                                }
                                : undefined, children: _jsxs(Stack, { spacing: 0.75, sx: { width: "100%" }, children: [_jsxs(Stack, { direction: "row", justifyContent: "space-between", alignItems: "center", spacing: 2, children: [_jsxs(Stack, { direction: "row", alignItems: "center", spacing: 1.25, minWidth: 0, children: [_jsx(Avatar, { src: comment.avatar_url || undefined, alt: comment.username, sx: { width: 28, height: 28, fontSize: "0.8rem", bgcolor: "rgba(126,224,255,0.18)" }, children: comment.username.slice(0, 1).toUpperCase() }), _jsx(Typography, { fontWeight: 700, color: "text.primary", noWrap: true, children: comment.username })] }), _jsxs(Stack, { direction: "row", alignItems: "center", spacing: 0, sx: { flexShrink: 0 }, children: [_jsx(Typography, { variant: "caption", color: "text.secondary", sx: { whiteSpace: "nowrap", textAlign: "right", minWidth: "7.75rem", pr: 0.5 }, children: formatCommentTimestamp(comment.created_at) }), _jsx(Box, { sx: { width: 36, display: "flex", justifyContent: "flex-end", flexShrink: 0 }, children: canManageComment ? (_jsx(IconButton, { className: "comment-row-actions", size: "small", onClick: (event) => openCommentActionsMenu(event, comment), sx: {
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
                    }), vulnComments.length === 0 && _jsx(Typography, { color: "text.secondary", children: "\u041A\u043E\u043C\u043C\u0435\u043D\u0442\u0430\u0440\u0438\u0435\u0432 \u043F\u043E\u043A\u0430 \u043D\u0435\u0442." })] }), _jsx(TextField, { label: "\u041A\u043E\u043C\u043C\u0435\u043D\u0442\u0430\u0440\u0438\u0439 (@username \u0442\u043E\u043B\u044C\u043A\u043E \u0434\u043B\u044F \u0443\u0447\u0430\u0441\u0442\u043D\u0438\u043A\u043E\u0432 \u043F\u0440\u043E\u0435\u043A\u0442\u0430)", multiline: true, minRows: 3, value: newComment, onChange: (e) => setNewComment(e.target.value) }), _jsx(Stack, { direction: "row", justifyContent: "flex-end", children: _jsx(Button, { variant: "contained", disabled: !newComment.trim() || vulnBusy, onClick: () => void addCommentToActiveVuln(), children: "\u0414\u043E\u0431\u0430\u0432\u0438\u0442\u044C \u043A\u043E\u043C\u043C\u0435\u043D\u0442\u0430\u0440\u0438\u0439" }) }), _jsxs(Menu, { anchorEl: commentActionsAnchorEl, open: Boolean(commentActionsAnchorEl), onClose: closeCommentActionsMenu, anchorOrigin: { vertical: "bottom", horizontal: "right" }, transformOrigin: { vertical: "top", horizontal: "right" }, children: [_jsxs(MenuItem, { onClick: () => {
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
    const submitImport = async () => {
        if (!projectId || !importFile) {
            return;
        }
        setImporting(true);
        setError(null);
        try {
            const result = await importProjectData(projectId, importFile);
            setImportSummary(result);
            await loadProjectData();
            await loadHostAssets();
        }
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось импортировать JSON-данные проекта"));
        }
        finally {
            setImporting(false);
        }
    };
    const downloadReport = async (format) => {
        if (!projectId) {
            return;
        }
        setReportLoadingFormat(format);
        setError(null);
        try {
            const blob = await generateProjectReport(projectId, format);
            const fileNameBase = (projectName || "project-report").replace(/[^\w.-]+/g, "_");
            const objectUrl = URL.createObjectURL(blob);
            const anchor = document.createElement("a");
            anchor.href = objectUrl;
            anchor.download = `${fileNameBase}.${format}`;
            document.body.appendChild(anchor);
            anchor.click();
            anchor.remove();
            URL.revokeObjectURL(objectUrl);
        }
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось сформировать отчёт"));
        }
        finally {
            setReportLoadingFormat(null);
        }
    };
    const actionsMenuOpen = Boolean(actionsAnchorEl);
    const openActionsMenu = (event) => {
        setActionsAnchorEl(event.currentTarget);
    };
    const closeActionsMenu = () => {
        setActionsAnchorEl(null);
    };
    const closeHostsMenu = () => {
        setHostsMenuAnchorEl(null);
    };
    const closeMembersMenu = () => {
        setMembersMenuAnchorEl(null);
    };
    const openExtendDialog = () => {
        setError(null);
        setExtendEndDate(projectEndDate ?? "");
        setExtendDialogOpen(true);
    };
    const openStatusDialog = () => {
        setError(null);
        setPendingProjectStatus(projectStatus);
        setStatusDialogOpen(true);
    };
    const openProjectEditDialog = () => {
        setError(null);
        setProjectDraftName(projectName);
        setProjectDraftStartDate(projectStartDate ?? "");
        setProjectDraftEndDate(projectEndDate ?? "");
        setProjectEditDialogOpen(true);
    };
    const startProjectDescriptionEdit = () => {
        setError(null);
        setProjectDraftDescription(projectDescription);
        setProjectDescriptionEditOpen(true);
    };
    const cancelProjectDescriptionEdit = () => {
        setProjectDraftDescription(projectDescription);
        setProjectDescriptionEditOpen(false);
    };
    const applyQuickExtension = (days) => {
        const baseDate = parseIsoDateOnly(extendEndDate || projectEndDate) ?? new Date();
        baseDate.setDate(baseDate.getDate() + days);
        setExtendEndDate(toDateInputValue(baseDate));
    };
    const submitProjectExtension = async () => {
        if (!projectId || !extendEndDate) {
            return;
        }
        if (projectStartDate && extendEndDate < projectStartDate) {
            setError("Новая дата окончания не может быть раньше даты начала проекта");
            return;
        }
        if (projectEndDate && extendEndDate <= projectEndDate) {
            setError("Новая дата окончания должна быть позже текущей даты окончания");
            return;
        }
        setExtendingProject(true);
        setError(null);
        try {
            await updateProject(projectId, { end_date: extendEndDate });
            setExtendDialogOpen(false);
            await loadProjectData();
        }
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось продлить срок проекта"));
        }
        finally {
            setExtendingProject(false);
        }
    };
    const submitProjectEdit = async () => {
        if (!projectId) {
            return;
        }
        const normalizedName = projectDraftName.trim();
        if (!normalizedName) {
            setError("Название проекта не может быть пустым");
            return;
        }
        if (projectDraftStartDate && projectDraftEndDate && projectDraftEndDate < projectDraftStartDate) {
            setError("Дата окончания проекта не может быть раньше даты начала");
            return;
        }
        setProjectSaving(true);
        setError(null);
        try {
            await updateProject(projectId, {
                name: normalizedName,
                start_date: projectDraftStartDate || undefined,
                end_date: projectDraftEndDate || undefined,
            });
            setProjectEditDialogOpen(false);
            await loadProjectData();
        }
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось обновить проект"));
        }
        finally {
            setProjectSaving(false);
        }
    };
    const submitProjectDescription = async () => {
        if (!projectId) {
            return;
        }
        setProjectSaving(true);
        setError(null);
        try {
            await updateProject(projectId, { description: projectDraftDescription.trim() });
            setProjectDescriptionEditOpen(false);
            await loadProjectData();
        }
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось обновить описание проекта"));
        }
        finally {
            setProjectSaving(false);
        }
    };
    const updateProjectStatus = async (nextStatus) => {
        if (!projectId || nextStatus === projectStatus) {
            return;
        }
        setError(null);
        try {
            await updateProject(projectId, { status: nextStatus });
            setProjectStatus(nextStatus);
            await loadProjectData();
        }
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось обновить статус проекта"));
        }
    };
    const submitProjectStatus = async () => {
        await updateProjectStatus(pendingProjectStatus);
        setStatusDialogOpen(false);
    };
    const openMembersDialog = async () => {
        if (!projectId) {
            return;
        }
        setError(null);
        setSelectedAvailableMemberIds([]);
        setMemberSearchQuery("");
        setMembersDialogOpen(true);
        if (user?.role !== "admin") {
            return;
        }
        try {
            const usersResponse = await getUsers(1, 200);
            setUsersCatalog(usersResponse.items);
        }
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось загрузить список пользователей для управления участниками."));
        }
    };
    const openRemoveMembersDialog = () => {
        setSelectedMemberIds([]);
        setRemoveMembersDialogOpen(true);
    };
    const openRemoveHostsDialog = () => {
        setSelectedHostIds([]);
        setRemoveHostsDialogOpen(true);
    };
    const addMembersToProject = async () => {
        if (!projectId || selectedAvailableMemberIds.length === 0) {
            return;
        }
        setMembersBusy(true);
        setError(null);
        try {
            await Promise.all(selectedAvailableMemberIds.map((userId) => addProjectMember(projectId, userId)));
            setSelectedAvailableMemberIds([]);
            setMembersDialogOpen(false);
            await loadProjectData();
        }
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось добавить пользователей в проект."));
        }
        finally {
            setMembersBusy(false);
        }
    };
    const removeSelectedMembersFromProject = async () => {
        if (!projectId || selectedMemberIds.length === 0) {
            return;
        }
        setMembersBusy(true);
        setError(null);
        try {
            await Promise.all(selectedMemberIds.map((memberUserId) => removeProjectMember(projectId, memberUserId)));
            setSelectedMemberIds([]);
            setRemoveMembersDialogOpen(false);
            await loadProjectData();
        }
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось удалить выбранных участников из проекта."));
        }
        finally {
            setMembersBusy(false);
        }
    };
    const removeSelectedHosts = async () => {
        if (!projectId || selectedHostIds.length === 0) {
            return;
        }
        setError(null);
        try {
            await Promise.all(selectedHostIds.map((selectedHostId) => deleteHost(projectId, selectedHostId)));
            setSelectedHostIds([]);
            setRemoveHostsDialogOpen(false);
            await loadProjectData();
        }
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось удалить выбранные хосты."));
        }
    };
    return (_jsxs(Stack, { spacing: 2.5, children: [_jsxs(Stack, { direction: "row", justifyContent: "space-between", alignItems: "center", children: [_jsxs(Box, { children: [_jsx(Typography, { variant: "overline", color: "primary.main", sx: { letterSpacing: 1.4, fontWeight: 700 }, children: "Project Workspace" }), _jsx(Typography, { variant: "h4", fontWeight: 700, children: projectName ? `Проект: ${projectName}` : "Проект" })] }), _jsx(IconButton, { onClick: openActionsMenu, sx: { border: "1px solid rgba(126,224,255,0.2)", width: 42, height: 42, backgroundColor: "rgba(15,27,45,0.72)" }, children: _jsx(MoreVertIcon, {}) })] }), _jsxs(Menu, { anchorEl: actionsAnchorEl, open: actionsMenuOpen, onClose: closeActionsMenu, anchorOrigin: { vertical: "bottom", horizontal: "right" }, transformOrigin: { vertical: "top", horizontal: "right" }, children: [user?.role === "admin" && (_jsxs(MenuItem, { onClick: () => {
                            closeActionsMenu();
                            openProjectEditDialog();
                        }, children: [_jsx(EditIcon, { fontSize: "small", sx: { mr: 1 } }), "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u043F\u0440\u043E\u0435\u043A\u0442"] })), _jsxs(MenuItem, { onClick: () => {
                            closeActionsMenu();
                            setImportOpen(true);
                        }, children: [_jsx(UploadFileIcon, { fontSize: "small", sx: { mr: 1 } }), "\u0418\u043C\u043F\u043E\u0440\u0442 JSON"] }), _jsxs(MenuItem, { onClick: () => {
                            closeActionsMenu();
                            setExportOpen(true);
                        }, children: [_jsx(DownloadIcon, { fontSize: "small", sx: { mr: 1 } }), "\u042D\u043A\u0441\u043F\u043E\u0440\u0442"] }), user?.role === "admin" && (_jsxs(MenuItem, { onClick: () => {
                            closeActionsMenu();
                            openStatusDialog();
                        }, children: [_jsx(FlagIcon, { fontSize: "small", sx: { mr: 1 } }), "\u0421\u0442\u0430\u0442\u0443\u0441 \u043F\u0440\u043E\u0435\u043A\u0442\u0430"] })), user?.role === "admin" && (_jsxs(MenuItem, { onClick: () => {
                            closeActionsMenu();
                            openExtendDialog();
                        }, children: [_jsx(AccessTimeIcon, { fontSize: "small", sx: { mr: 1 } }), "\u041F\u0440\u043E\u0434\u043B\u0438\u0442\u044C \u043F\u0440\u043E\u0435\u043A\u0442"] }))] }), _jsxs(Stack, { direction: { xs: "column", md: "row" }, spacing: 2, children: [_jsx(ProjectTreeNav, { hosts: hosts, selectedHostId: selectedHostId, selectedSection: selectedSection, isCollapsed: isSidebarCollapsed, portsCount: ports.length, endpointsCount: normalizedEndpoints.length, vulnerabilitiesCount: vulnerabilities.length, hostStatsById: hostStatsById, autoExpandSelectedHost: false, onToggleCollapsed: () => setSidebarCollapsed((v) => !v), onSelectSection: setSelectedSection, onSelectProjectOverview: () => setSelectedSection("overview"), onSelectHost: setSelectedHostId, onOpenHost: (hostId, section) => navigate(`/projects/${projectId}/hosts/${hostId}`, { state: { section } }) }), _jsxs(Stack, { flex: 1, spacing: 2, children: [selectedSection !== "overview" && (_jsx(Card, { sx: { border: "1px solid rgba(126,224,255,0.14)" }, children: _jsx(CardContent, { children: _jsxs(Typography, { variant: "h6", fontWeight: 700, children: [selectedSection === "hosts" && `Хост: ${hostLabel}`, selectedSection === "ports" && `Порты хоста: ${hostLabel}`, selectedSection === "endpoints" && `Эндпоинты хоста: ${hostLabel}`, selectedSection === "vulns" && `Уязвимости хоста: ${hostLabel}`] }) }) })), selectedSection === "overview" && (_jsxs(Stack, { spacing: 2, children: [_jsx(Card, { sx: { border: "1px solid rgba(126,224,255,0.14)" }, children: _jsxs(CardContent, { children: [_jsx(Stack, { direction: { xs: "column", md: "row" }, justifyContent: "space-between", spacing: 1, alignItems: { md: "center" }, children: _jsxs(Stack, { direction: "row", spacing: 1, alignItems: "center", flexWrap: "wrap", children: [_jsx(Typography, { variant: "h6", fontWeight: 700, children: "\u0422\u0430\u0439\u043C\u043B\u0430\u0439\u043D \u043F\u0440\u043E\u0435\u043A\u0442\u0430" }), _jsx(Chip, { size: "small", color: projectTimeMetrics.statusTone === "neutral" ? "default" : projectTimeMetrics.statusTone, label: projectTimeMetrics.statusLabel }), projectTimeMetrics.daysLeft !== null && (_jsx(Chip, { size: "small", variant: "outlined", label: projectTimeMetrics.daysLeft >= 0
                                                                    ? `${projectTimeMetrics.daysLeft} дн. осталось`
                                                                    : `${Math.abs(projectTimeMetrics.daysLeft)} дн. просрочки` }))] }) }), _jsx(Box, { sx: { mt: 1.5 }, children: timelineBar.ready ? (_jsxs(_Fragment, { children: [_jsx(Box, { sx: {
                                                                    display: "grid",
                                                                    gridTemplateColumns: `repeat(${timelineBar.totalDays}, minmax(12px, 1fr))`,
                                                                    gap: 0.5,
                                                                    p: 1,
                                                                    border: "1px solid rgba(126,224,255,0.12)",
                                                                    borderRadius: 0,
                                                                    backgroundColor: "rgba(8,17,31,0.34)",
                                                                }, children: timelineBar.cells.map((cell, index) => (_jsx(Box, { sx: {
                                                                        height: 16,
                                                                        border: cell.isToday ? "1px solid rgba(76,175,80,0.95)" : "1px solid rgba(126,224,255,0.16)",
                                                                        backgroundColor: cell.bgColor,
                                                                        boxShadow: cell.isToday ? "0 0 0 1px rgba(76,175,80,0.35)" : "none",
                                                                    } }, `timeline-day-${index}`))) }), _jsxs(Stack, { direction: "row", justifyContent: "space-between", mt: 1, children: [_jsxs(Typography, { variant: "caption", color: "text.secondary", children: ["Start: ", timelineBar.startLabel] }), _jsxs(Typography, { variant: "caption", color: "text.secondary", children: ["End: ", timelineBar.endLabel] })] })] })) : (_jsx(Typography, { variant: "body2", color: "text.secondary", children: "\u0421\u0442\u0430\u043D\u0434\u0430\u0440\u0442\u043D\u044B\u0439 \u0441\u0440\u043E\u043A \u043F\u0440\u043E\u0435\u043A\u0442\u0430: 14 \u0434\u043D\u0435\u0439. \u0423\u043A\u0430\u0436\u0438\u0442\u0435 \u0434\u0430\u0442\u0443 \u043D\u0430\u0447\u0430\u043B\u0430 \u0438 \u043E\u043A\u043E\u043D\u0447\u0430\u043D\u0438\u044F, \u0447\u0442\u043E\u0431\u044B \u043E\u0442\u043E\u0431\u0440\u0430\u0437\u0438\u0442\u044C \u0448\u043A\u0430\u043B\u0443 \u043F\u043E \u0434\u043D\u044F\u043C." })) })] }) }), _jsxs(Grid, { container: true, spacing: 2, children: [_jsx(Grid, { size: { xs: 12, md: 6 }, children: _jsxs(Card, { sx: {
                                                        position: "relative",
                                                        border: "1px solid rgba(126,224,255,0.14)",
                                                        height: "100%",
                                                        "& .overview-card-action": {
                                                            opacity: 0,
                                                            pointerEvents: "none",
                                                            transition: "opacity 0.18s ease",
                                                        },
                                                        "&:hover .overview-card-action": {
                                                            opacity: 1,
                                                            pointerEvents: "auto",
                                                        },
                                                    }, children: [_jsx(IconButton, { size: "small", className: "overview-card-action", onClick: (event) => setHostsMenuAnchorEl(event.currentTarget), sx: {
                                                                position: "absolute",
                                                                top: 10,
                                                                right: 10,
                                                                color: "text.secondary",
                                                                backgroundColor: "transparent",
                                                                "&:hover": {
                                                                    backgroundColor: "rgba(126,224,255,0.08)",
                                                                    color: "text.primary",
                                                                },
                                                            }, children: _jsx(MoreVertIcon, { fontSize: "small" }) }), _jsxs(CardContent, { children: [_jsx(Typography, { color: "text.secondary", mb: 1, children: "\u0425\u043E\u0441\u0442\u044B \u043F\u0440\u043E\u0435\u043A\u0442\u0430" }), _jsx(Typography, { variant: "h4", fontWeight: 700, children: hosts.length }), _jsx(Stack, { spacing: 0.8, mt: 1, sx: { maxHeight: 160, overflowY: "auto" }, children: hosts.length > 0 ? (hosts.map((host) => (_jsx(Box, { sx: { px: 1.2, py: 0.9, border: "1px solid rgba(126,224,255,0.10)", borderRadius: 0, backgroundColor: "rgba(8,17,31,0.28)" }, children: _jsx(Typography, { variant: "body2", color: "text.primary", children: host.hostname || host.ip_address || "unknown-host" }) }, host.id)))) : (_jsx(Typography, { color: "text.secondary", children: "\u0425\u043E\u0441\u0442\u044B \u043D\u0435 \u0434\u043E\u0431\u0430\u0432\u043B\u0435\u043D\u044B" })) })] })] }) }), _jsx(Grid, { size: { xs: 12, md: 6 }, children: _jsxs(Card, { sx: {
                                                        position: "relative",
                                                        border: "1px solid rgba(126,224,255,0.14)",
                                                        height: "100%",
                                                        "& .overview-card-action": {
                                                            opacity: 0,
                                                            pointerEvents: "none",
                                                            transition: "opacity 0.18s ease",
                                                        },
                                                        "&:hover .overview-card-action": {
                                                            opacity: 1,
                                                            pointerEvents: "auto",
                                                        },
                                                    }, children: [user?.role === "admin" && (_jsx(IconButton, { size: "small", className: "overview-card-action", onClick: (event) => setMembersMenuAnchorEl(event.currentTarget), sx: {
                                                                position: "absolute",
                                                                top: 10,
                                                                right: 10,
                                                                color: "text.secondary",
                                                                backgroundColor: "transparent",
                                                                "&:hover": {
                                                                    backgroundColor: "rgba(126,224,255,0.08)",
                                                                    color: "text.primary",
                                                                },
                                                            }, children: _jsx(MoreVertIcon, { fontSize: "small" }) })), _jsxs(CardContent, { sx: { height: "100%" }, children: [_jsx(Typography, { color: "text.secondary", mb: 1, children: "\u0423\u0447\u0430\u0441\u0442\u043D\u0438\u043A\u0438 \u043F\u0440\u043E\u0435\u043A\u0442\u0430" }), _jsx(Typography, { variant: "h4", fontWeight: 700, mb: 1, children: projectMembers.length }), _jsx(Stack, { spacing: 0.8, sx: { maxHeight: 160, overflowY: "auto" }, children: projectMembers.length > 0 ? (projectMembers.map((member) => (_jsx(Box, { sx: { px: 1.2, py: 0.9, border: "1px solid rgba(126,224,255,0.10)", borderRadius: 0, backgroundColor: "rgba(8,17,31,0.28)" }, children: _jsxs(Typography, { variant: "body2", color: "text.primary", children: [member.username, " (", member.role, ")"] }) }, member.user_id)))) : (_jsx(Typography, { color: "text.secondary", children: "\u0423\u0447\u0430\u0441\u0442\u043D\u0438\u043A\u0438 \u043D\u0435 \u0434\u043E\u0431\u0430\u0432\u043B\u0435\u043D\u044B" })) })] })] }) })] }), _jsxs(Menu, { anchorEl: hostsMenuAnchorEl, open: Boolean(hostsMenuAnchorEl), onClose: closeHostsMenu, anchorOrigin: { vertical: "bottom", horizontal: "right" }, transformOrigin: { vertical: "top", horizontal: "right" }, children: [_jsx(MenuItem, { onClick: () => {
                                                    closeHostsMenu();
                                                    setHostOpen(true);
                                                }, children: "\u0414\u043E\u0431\u0430\u0432\u0438\u0442\u044C \u0445\u043E\u0441\u0442" }), _jsx(MenuItem, { onClick: () => {
                                                    closeHostsMenu();
                                                    openRemoveHostsDialog();
                                                }, disabled: hosts.length === 0, children: "\u0423\u0434\u0430\u043B\u0438\u0442\u044C \u0445\u043E\u0441\u0442\u044B" })] }), _jsxs(Menu, { anchorEl: membersMenuAnchorEl, open: Boolean(membersMenuAnchorEl), onClose: closeMembersMenu, anchorOrigin: { vertical: "bottom", horizontal: "right" }, transformOrigin: { vertical: "top", horizontal: "right" }, children: [_jsx(MenuItem, { onClick: () => {
                                                    closeMembersMenu();
                                                    void openMembersDialog();
                                                }, children: "\u0414\u043E\u0431\u0430\u0432\u0438\u0442\u044C \u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u0435\u0439" }), _jsx(MenuItem, { onClick: () => {
                                                    closeMembersMenu();
                                                    openRemoveMembersDialog();
                                                }, disabled: projectMembers.length === 0, children: "\u0423\u0434\u0430\u043B\u0438\u0442\u044C \u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u0435\u0439" })] }), _jsx(Card, { sx: {
                                            position: "relative",
                                            border: "1px solid rgba(126,224,255,0.14)",
                                            "& .project-description-edit-action": {
                                                opacity: 0,
                                                pointerEvents: "none",
                                                transition: "opacity 0.18s ease",
                                            },
                                            "&:hover .project-description-edit-action": {
                                                opacity: 1,
                                                pointerEvents: "auto",
                                            },
                                        }, children: _jsxs(CardContent, { children: [_jsxs(Stack, { direction: "row", justifyContent: "space-between", alignItems: "flex-start", spacing: 1, mb: 1, children: [_jsx(Typography, { variant: "h6", fontWeight: 700, children: "\u041E\u043F\u0438\u0441\u0430\u043D\u0438\u0435 \u043F\u0440\u043E\u0435\u043A\u0442\u0430" }), user?.role === "admin" && !projectDescriptionEditOpen && (_jsx(IconButton, { size: "small", className: "project-description-edit-action", onClick: startProjectDescriptionEdit, children: _jsx(EditIcon, { fontSize: "small" }) }))] }), projectDescriptionEditOpen ? (_jsxs(Stack, { spacing: 1.5, children: [_jsx(TextField, { fullWidth: true, multiline: true, minRows: 4, value: projectDraftDescription, onChange: (event) => setProjectDraftDescription(event.target.value), placeholder: "\u0412\u0432\u0435\u0434\u0438\u0442\u0435 \u043E\u043F\u0438\u0441\u0430\u043D\u0438\u0435 \u043F\u0440\u043E\u0435\u043A\u0442\u0430" }), _jsxs(Stack, { direction: "row", spacing: 1, justifyContent: "flex-end", children: [_jsx(Button, { onClick: cancelProjectDescriptionEdit, disabled: projectSaving, children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", onClick: () => void submitProjectDescription(), disabled: projectSaving, children: "\u0421\u043E\u0445\u0440\u0430\u043D\u0438\u0442\u044C" })] })] })) : (_jsx(Typography, { color: "text.secondary", whiteSpace: "pre-wrap", children: projectDescription || "Описание проекта не заполнено" }))] }) })] })), selectedSection === "hosts" && (_jsx(Card, { sx: { border: "1px solid rgba(126,224,255,0.14)" }, children: _jsx(CardContent, { children: _jsx(Stack, { spacing: 1.2, children: hosts.map((host) => (_jsx(Box, { sx: { border: "1px solid rgba(126,224,255,0.12)", p: 1.6, borderRadius: 0, cursor: "pointer", backgroundColor: "rgba(8,17,31,0.24)" }, onClick: () => navigate(`/projects/${projectId}/hosts/${host.id}`), children: _jsx(Typography, { children: host.hostname || host.ip_address || "unknown-host" }) }, host.id))) }) }) })), selectedSection === "ports" && (_jsx(Card, { sx: { border: "1px solid rgba(126,224,255,0.14)" }, children: _jsx(CardContent, { children: _jsxs(Stack, { spacing: 1.2, children: [ports.map((port) => (_jsx(Box, { sx: { border: "1px solid rgba(126,224,255,0.12)", p: 1.5, borderRadius: 0, backgroundColor: "rgba(8,17,31,0.24)" }, children: _jsxs(Stack, { direction: "row", spacing: 1, alignItems: "center", children: [_jsxs(Typography, { fontWeight: 600, children: [port.port_number, "/", port.protocol] }), _jsx(Chip, { size: "small", label: port.state })] }) }, port.id))), ports.length === 0 && (_jsx(Typography, { color: "text.secondary", children: "\u041F\u043E\u0440\u0442\u044B \u043D\u0435 \u0434\u043E\u0431\u0430\u0432\u043B\u0435\u043D\u044B. \u0412\u044B\u0431\u0435\u0440\u0438\u0442\u0435 \u0445\u043E\u0441\u0442 \u0438 \u0434\u043E\u0431\u0430\u0432\u044C\u0442\u0435 \u043F\u0435\u0440\u0432\u044B\u0439 \u043F\u043E\u0440\u0442." }))] }) }) })), selectedSection === "endpoints" && (_jsx(Card, { sx: { border: "1px solid rgba(126,224,255,0.14)" }, children: _jsx(CardContent, { children: _jsxs(Stack, { spacing: 1.2, children: [normalizedEndpoints.map((endpoint) => (_jsxs(Box, { sx: { border: "1px solid rgba(126,224,255,0.12)", p: 1.5, borderRadius: 0, backgroundColor: "rgba(8,17,31,0.24)" }, children: [_jsxs(Stack, { direction: "row", spacing: 1, alignItems: "center", children: [_jsx(Chip, { size: "small", label: endpoint.method || "ANY" }), _jsx(Typography, { fontWeight: 600, children: endpoint.path })] }), _jsx(Typography, { variant: "body2", color: "text.secondary", mt: 0.8, children: endpoint.description || "Описание не указано" })] }, endpoint.id))), normalizedEndpoints.length === 0 && (_jsx(Typography, { color: "text.secondary", children: "\u042D\u043D\u0434\u043F\u043E\u0438\u043D\u0442\u044B \u043D\u0435 \u0434\u043E\u0431\u0430\u0432\u043B\u0435\u043D\u044B. \u0412\u044B\u0431\u0435\u0440\u0438\u0442\u0435 \u0445\u043E\u0441\u0442 \u0438 \u0434\u043E\u0431\u0430\u0432\u044C\u0442\u0435 \u043F\u0435\u0440\u0432\u044B\u0439 \u044D\u043D\u0434\u043F\u043E\u0438\u043D\u0442." }))] }) }) })), selectedSection === "vulns" && (_jsx(Card, { sx: { border: "1px solid rgba(126,224,255,0.14)" }, children: _jsxs(CardContent, { children: [_jsx(Stack, { direction: "row", spacing: 1, mb: 2, flexWrap: "wrap", children: Object.entries(vulnerabilities.reduce((acc, item) => {
                                                acc[item.severity] += 1;
                                                return acc;
                                            }, { critical: 0, high: 0, medium: 0, low: 0, info: 0 })).map(([severity, value]) => (_jsx(Chip, { label: `${severity}: ${value}` }, severity))) }), _jsxs(Stack, { spacing: 1.2, children: [vulnerabilities.map((item) => (_jsx(Box, { sx: { border: "1px solid rgba(126,224,255,0.12)", p: 1.5, borderRadius: 0, backgroundColor: "rgba(8,17,31,0.24)" }, children: _jsxs(Stack, { spacing: 1, children: [_jsx(Typography, { children: item.title }), _jsxs(Stack, { direction: "row", spacing: 1, flexWrap: "wrap", useFlexGap: true, children: [item.cwe_id && _jsx(Chip, { label: item.cwe_id, size: "small", variant: "outlined" }), item.cvss_version && _jsx(Chip, { label: `CVSS ${item.cvss_version} ${item.cvss_score ?? "-"}`, size: "small", variant: "outlined" }), _jsx(Chip, { label: item.severity, size: "small", sx: severityChipSx[item.severity] }), _jsx(Chip, { label: item.status, size: "small", sx: vulnerabilityStatusChipSx[item.status] })] }), _jsx(Typography, { color: "text.secondary", variant: "body2", children: item.impact || "Влияние не указано" }), _jsx(Box, { children: _jsx(Button, { size: "small", variant: "outlined", onClick: () => {
                                                                        if (projectId && selectedHostId) {
                                                                            navigate(`/projects/${projectId}/hosts/${selectedHostId}/vulnerabilities/${item.id}`, {
                                                                                state: { section: "vulns" },
                                                                            });
                                                                        }
                                                                    }, disabled: vulnBusy || !projectId || !selectedHostId, children: "\u041E\u0442\u043A\u0440\u044B\u0442\u044C" }) })] }) }, item.id))), vulnerabilities.length === 0 && _jsx(Typography, { color: "text.secondary", children: "\u0414\u043B\u044F \u0432\u044B\u0431\u0440\u0430\u043D\u043D\u043E\u0433\u043E \u0445\u043E\u0441\u0442\u0430 \u0443\u044F\u0437\u0432\u0438\u043C\u043E\u0441\u0442\u0438 \u043D\u0435 \u043F\u0440\u0438\u0432\u044F\u0437\u0430\u043D\u044B." })] })] }) }))] })] }), _jsxs(Dialog, { open: hostOpen, onClose: () => setHostOpen(false), fullWidth: true, children: [_jsx(DialogTitle, { children: "\u0414\u043E\u0431\u0430\u0432\u0438\u0442\u044C \u0445\u043E\u0441\u0442" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [_jsx(TextField, { label: "IP-\u0430\u0434\u0440\u0435\u0441", value: hostIp, onChange: (e) => setHostIp(e.target.value) }), _jsx(TextField, { label: "Hostname", value: hostName, onChange: (e) => setHostName(e.target.value) }), _jsx(TextField, { label: "\u041E\u043F\u0438\u0441\u0430\u043D\u0438\u0435", multiline: true, minRows: 3, value: hostNotes, onChange: (e) => setHostNotes(e.target.value) })] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setHostOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", disabled: !hostIp && !hostName, onClick: () => void submitHost(), children: "\u0421\u043E\u0445\u0440\u0430\u043D\u0438\u0442\u044C" })] })] }), _jsxs(Dialog, { open: removeHostsDialogOpen, onClose: () => setRemoveHostsDialogOpen(false), fullWidth: true, maxWidth: "sm", children: [_jsx(DialogTitle, { children: "\u0423\u0434\u0430\u043B\u0438\u0442\u044C \u0445\u043E\u0441\u0442\u044B" }), _jsx(DialogContent, { children: _jsx(Stack, { spacing: 1, sx: { mt: 1 }, children: _jsxs(List, { dense: true, disablePadding: true, children: [hosts.map((host) => {
                                        const checked = selectedHostIds.includes(host.id);
                                        return (_jsx(ListItem, { secondaryAction: _jsx(Checkbox, { edge: "end", checked: checked, onChange: (event) => setSelectedHostIds((prev) => event.target.checked ? [...prev, host.id] : prev.filter((item) => item !== host.id)) }), children: _jsx(ListItemText, { primary: host.hostname || host.ip_address || "unknown-host", secondary: host.ip_address || host.hostname || "" }) }, host.id));
                                    }), hosts.length === 0 && _jsx(Typography, { color: "text.secondary", children: "\u0425\u043E\u0441\u0442\u044B \u043F\u043E\u043A\u0430 \u043D\u0435 \u0434\u043E\u0431\u0430\u0432\u043B\u0435\u043D\u044B." })] }) }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setRemoveHostsDialogOpen(false), children: "\u0417\u0430\u043A\u0440\u044B\u0442\u044C" }), _jsx(Button, { color: "error", variant: "contained", startIcon: _jsx(DeleteOutlineIcon, {}), disabled: selectedHostIds.length === 0, onClick: () => void removeSelectedHosts(), children: "\u0423\u0434\u0430\u043B\u0438\u0442\u044C" })] })] }), _jsxs(Dialog, { open: extendDialogOpen, onClose: () => setExtendDialogOpen(false), fullWidth: true, maxWidth: "xs", children: [_jsx(DialogTitle, { children: "\u041F\u0440\u043E\u0434\u043B\u0438\u0442\u044C \u043F\u0440\u043E\u0435\u043A\u0442" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 1.5, sx: { mt: 1 }, children: [_jsxs(Typography, { variant: "body2", color: "text.secondary", children: ["\u0422\u0435\u043A\u0443\u0449\u0430\u044F \u0434\u0430\u0442\u0430 \u043E\u043A\u043E\u043D\u0447\u0430\u043D\u0438\u044F: ", projectEndDate || "не задана"] }), _jsx(TextField, { label: "\u041D\u043E\u0432\u0430\u044F \u0434\u0430\u0442\u0430 \u043E\u043A\u043E\u043D\u0447\u0430\u043D\u0438\u044F", type: "date", value: extendEndDate, onChange: (event) => setExtendEndDate(event.target.value), InputLabelProps: { shrink: true } }), _jsxs(Stack, { direction: "row", spacing: 1, children: [_jsx(Button, { size: "small", variant: "text", onClick: () => applyQuickExtension(7), children: "+7 \u0434\u043D\u0435\u0439" }), _jsx(Button, { size: "small", variant: "text", onClick: () => applyQuickExtension(14), children: "+14 \u0434\u043D\u0435\u0439" }), _jsx(Button, { size: "small", variant: "text", onClick: () => applyQuickExtension(30), children: "+30 \u0434\u043D\u0435\u0439" })] })] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setExtendDialogOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", disabled: !extendEndDate || extendingProject, onClick: () => void submitProjectExtension(), children: "\u041F\u0440\u043E\u0434\u043B\u0438\u0442\u044C" })] })] }), _jsxs(Dialog, { open: projectEditDialogOpen, onClose: () => setProjectEditDialogOpen(false), fullWidth: true, maxWidth: "sm", children: [_jsx(DialogTitle, { children: "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u043F\u0440\u043E\u0435\u043A\u0442" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [_jsx(TextField, { label: "\u041D\u0430\u0437\u0432\u0430\u043D\u0438\u0435", value: projectDraftName, onChange: (event) => setProjectDraftName(event.target.value) }), _jsx(TextField, { label: "\u0414\u0430\u0442\u0430 \u043D\u0430\u0447\u0430\u043B\u0430", type: "date", value: projectDraftStartDate, onChange: (event) => setProjectDraftStartDate(event.target.value), InputLabelProps: { shrink: true } }), _jsx(TextField, { label: "\u0414\u0430\u0442\u0430 \u043E\u043A\u043E\u043D\u0447\u0430\u043D\u0438\u044F", type: "date", value: projectDraftEndDate, onChange: (event) => setProjectDraftEndDate(event.target.value), InputLabelProps: { shrink: true } })] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setProjectEditDialogOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", onClick: () => void submitProjectEdit(), disabled: projectSaving || !projectDraftName.trim(), children: "\u0421\u043E\u0445\u0440\u0430\u043D\u0438\u0442\u044C" })] })] }), _jsxs(Dialog, { open: statusDialogOpen, onClose: () => setStatusDialogOpen(false), fullWidth: true, maxWidth: "xs", children: [_jsx(DialogTitle, { children: "\u0421\u0442\u0430\u0442\u0443\u0441 \u043F\u0440\u043E\u0435\u043A\u0442\u0430" }), _jsx(DialogContent, { children: _jsx(Stack, { spacing: 2, sx: { mt: 1 }, children: _jsx(TextField, { select: true, label: "\u0421\u0442\u0430\u0442\u0443\u0441 \u043F\u0440\u043E\u0435\u043A\u0442\u0430", value: pendingProjectStatus, onChange: (event) => setPendingProjectStatus(event.target.value), fullWidth: true, children: PROJECT_STATUS_ORDER.map((status) => (_jsx(MenuItem, { value: status, children: PROJECT_STATUS_LABELS[status] }, status))) }) }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setStatusDialogOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", onClick: () => void submitProjectStatus(), disabled: pendingProjectStatus === projectStatus, children: "\u0421\u043E\u0445\u0440\u0430\u043D\u0438\u0442\u044C" })] })] }), _jsxs(Dialog, { open: vulnDetailOpen, onClose: () => {
                    setVulnEditMode(false);
                    setVulnDetailOpen(false);
                }, fullWidth: true, maxWidth: "lg", children: [_jsx(DialogTitle, { children: "\u041A\u0430\u0440\u0442\u043E\u0447\u043A\u0430 \u0443\u044F\u0437\u0432\u0438\u043C\u043E\u0441\u0442\u0438" }), _jsx(DialogContent, { children: !activeVuln ? (_jsx(Typography, { color: "text.secondary", children: "\u0423\u044F\u0437\u0432\u0438\u043C\u043E\u0441\u0442\u044C \u043D\u0435 \u0432\u044B\u0431\u0440\u0430\u043D\u0430." })) : (_jsxs(Stack, { spacing: 2, sx: { mt: 0.5 }, children: [_jsxs(Grid, { container: true, spacing: 2, children: [_jsx(Grid, { size: { xs: 12, md: 7 }, children: _jsx(TextField, { label: "\u041D\u0430\u0437\u0432\u0430\u043D\u0438\u0435", fullWidth: true, value: activeVuln.title, onChange: (e) => setActiveVuln((prev) => (prev ? { ...prev, title: e.target.value } : prev)), slotProps: { input: { readOnly: !vulnEditMode } } }) }), _jsx(Grid, { size: { xs: 12, md: 3 }, children: _jsx(TextField, { label: "CWE ID", fullWidth: true, value: activeVuln.cwe_id || "", onChange: (e) => setActiveVuln((prev) => (prev ? { ...prev, cwe_id: e.target.value || null } : prev)), slotProps: { input: { readOnly: !vulnEditMode } } }) }), _jsx(Grid, { size: { xs: 12, md: 2 }, children: vulnEditMode ? (_jsxs(TextField, { select: true, label: "\u0421\u0442\u0430\u0442\u0443\u0441", fullWidth: true, value: activeVuln.status, onChange: (e) => setActiveVuln((prev) => (prev ? { ...prev, status: e.target.value } : prev)), children: [_jsx(MenuItem, { value: "open", children: "open" }), _jsx(MenuItem, { value: "in_progress", children: "in_progress" }), _jsx(MenuItem, { value: "fixed", children: "fixed" }), _jsx(MenuItem, { value: "wont_fix", children: "wont_fix" }), _jsx(MenuItem, { value: "accepted_risk", children: "accepted_risk" })] })) : (_jsx(TextField, { label: "\u0421\u0442\u0430\u0442\u0443\u0441", fullWidth: true, value: activeVuln.status, slotProps: { input: { readOnly: true } } })) }), _jsx(Grid, { size: { xs: 12, md: 2 }, children: _jsx(TextField, { label: "CVSS score", type: "number", fullWidth: true, value: activeVuln.cvss_score ?? "", slotProps: { input: { readOnly: true } } }) }), _jsx(Grid, { size: { xs: 12, md: 2 }, children: _jsx(TextField, { label: "\u041A\u0440\u0438\u0442\u0438\u0447\u043D\u043E\u0441\u0442\u044C", fullWidth: true, value: activeVuln.severity, slotProps: { input: { readOnly: true } } }) }), _jsx(Grid, { size: { xs: 12, md: 8 }, children: _jsx(TextField, { label: "CVSS vector", fullWidth: true, value: activeVuln.cvss_vector || "", onChange: (e) => setActiveVuln((prev) => (prev ? { ...prev, ...buildAutoCvssFields(e.target.value || null) } : prev)), slotProps: { input: { readOnly: !vulnEditMode } } }) }), _jsx(Grid, { size: { xs: 12 }, children: _jsx(VulnerabilityStagesEditor, { stages: activeVuln.workflow_steps || [], endpoints: normalizedEndpoints, hostLabel: selectedHost?.hostname || selectedHost?.ip_address || undefined, busy: vulnBusy, editable: vulnEditMode, onChange: (nextStages) => setActiveVuln((prev) => prev
                                                    ? {
                                                        ...prev,
                                                        workflow_steps: nextStages,
                                                    }
                                                    : prev), onUploadImage: async (_stageId, file) => {
                                                    if (!projectId || !activeVuln) {
                                                        return null;
                                                    }
                                                    try {
                                                        const uploadedFile = await uploadVulnerabilityFile(projectId, activeVuln.id, file);
                                                        setActiveVuln((prev) => prev
                                                            ? {
                                                                ...prev,
                                                                files: [uploadedFile, ...prev.files.filter((fileMeta) => fileMeta.id !== uploadedFile.id)],
                                                            }
                                                            : prev);
                                                        return `![${uploadedFile.original_name}](/api/v1/files/${uploadedFile.id}/download)`;
                                                    }
                                                    catch {
                                                        setError("Не удалось загрузить картинку этапа");
                                                        return null;
                                                    }
                                                } }) }), _jsx(Grid, { size: { xs: 12 }, children: vulnEditMode ? (_jsx(TextField, { label: "\u0412\u043B\u0438\u044F\u043D\u0438\u0435", fullWidth: true, multiline: true, minRows: 2, value: activeVuln.impact || "", onChange: (e) => setActiveVuln((prev) => (prev ? { ...prev, impact: e.target.value || null } : prev)) })) : (_jsxs(_Fragment, { children: [_jsx(Typography, { variant: "subtitle2", sx: { mb: 0.75 }, children: "\u0412\u043B\u0438\u044F\u043D\u0438\u0435" }), renderMarkdownPreview(activeVuln.impact, "Влияние не указано.")] })) }), _jsx(Grid, { size: { xs: 12 }, children: vulnEditMode ? (_jsx(TextField, { label: "\u0420\u0435\u043A\u043E\u043C\u0435\u043D\u0434\u0430\u0446\u0438\u0438", fullWidth: true, multiline: true, minRows: 2, value: activeVuln.recommendations || "", onChange: (e) => setActiveVuln((prev) => (prev ? { ...prev, recommendations: e.target.value || null } : prev)) })) : (_jsxs(_Fragment, { children: [_jsx(Typography, { variant: "subtitle2", sx: { mb: 0.75 }, children: "\u0420\u0435\u043A\u043E\u043C\u0435\u043D\u0434\u0430\u0446\u0438\u0438" }), renderMarkdownPreview(activeVuln.recommendations, "Рекомендации не указаны.")] })) }), vulnEditMode && (_jsx(Grid, { size: { xs: 12 }, children: _jsxs(Stack, { direction: { xs: "column", sm: "row" }, justifyContent: "flex-end", spacing: 1.5, children: [_jsx(Button, { variant: "outlined", onClick: () => activeVuln && void loadVulnerabilityDetails(activeVuln.id), children: "\u041E\u0442\u043C\u0435\u043D\u0438\u0442\u044C" }), _jsx(Button, { variant: "contained", size: "large", sx: { minWidth: 180 }, onClick: () => void saveActiveVulnerability(), disabled: !activeVuln || vulnBusy, children: "\u0421\u043E\u0445\u0440\u0430\u043D\u0438\u0442\u044C" })] }) }))] }), _jsx(Divider, {}), renderCommentsSection()] })) }), _jsxs(DialogActions, { sx: { px: 3, pb: 3, pt: 1.5 }, children: [_jsx(Button, { onClick: () => {
                                    setVulnEditMode(false);
                                    setVulnDetailOpen(false);
                                }, children: "\u0417\u0430\u043A\u0440\u044B\u0442\u044C" }), !vulnEditMode && (_jsx(Tooltip, { title: "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C", children: _jsx("span", { children: _jsx(IconButton, { onClick: () => setVulnEditMode(true), disabled: !activeVuln, sx: { color: "text.secondary", "&:hover": { backgroundColor: "rgba(126,224,255,0.08)", color: "text.primary" } }, children: _jsx(EditIcon, { fontSize: "small" }) }) }) }))] })] }), _jsxs(Dialog, { open: editCommentOpen, onClose: () => setEditCommentOpen(false), fullWidth: true, maxWidth: "sm", children: [_jsx(DialogTitle, { children: "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u043A\u043E\u043C\u043C\u0435\u043D\u0442\u0430\u0440\u0438\u0439" }), _jsx(DialogContent, { children: _jsx(TextField, { fullWidth: true, multiline: true, minRows: 4, sx: { mt: 1 }, label: "\u041A\u043E\u043C\u043C\u0435\u043D\u0442\u0430\u0440\u0438\u0439", value: editingCommentContent, onChange: (event) => setEditingCommentContent(event.target.value) }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setEditCommentOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", disabled: !editingCommentContent.trim() || vulnBusy, onClick: () => void saveCommentEdit(), children: "\u0421\u043E\u0445\u0440\u0430\u043D\u0438\u0442\u044C" })] })] }), _jsxs(Dialog, { open: exportOpen, onClose: () => setExportOpen(false), fullWidth: true, maxWidth: "xs", children: [_jsx(DialogTitle, { children: "\u042D\u043A\u0441\u043F\u043E\u0440\u0442 \u043E\u0442\u0447\u0451\u0442\u0430" }), _jsx(DialogContent, { children: _jsx(Stack, { spacing: 2, sx: { mt: 1 }, children: _jsxs(TextField, { select: true, label: "\u0424\u043E\u0440\u043C\u0430\u0442", value: exportFormat, onChange: (e) => setExportFormat(e.target.value), children: [_jsx(MenuItem, { value: "md", children: "Markdown (.md)" }), _jsx(MenuItem, { value: "pdf", children: "PDF (.pdf)" }), _jsx(MenuItem, { value: "docx", children: "DOCX (.docx)" })] }) }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setExportOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", startIcon: _jsx(DownloadIcon, {}), disabled: reportLoadingFormat !== null, onClick: () => void downloadReport(exportFormat), children: "\u0421\u043A\u0430\u0447\u0430\u0442\u044C" })] })] }), _jsxs(Dialog, { open: importOpen, onClose: () => setImportOpen(false), fullWidth: true, children: [_jsx(DialogTitle, { children: "\u0418\u043C\u043F\u043E\u0440\u0442 \u0441\u0442\u0440\u0443\u043A\u0442\u0443\u0440\u044B \u043F\u0440\u043E\u0435\u043A\u0442\u0430 (JSON)" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [_jsxs(Button, { component: "label", variant: "outlined", startIcon: _jsx(UploadFileIcon, {}), children: [importFile ? `Файл: ${importFile.name}` : "Выбрать JSON-файл", _jsx("input", { hidden: true, type: "file", accept: "application/json,.json", onChange: (event) => {
                                                const selected = event.target.files?.[0] ?? null;
                                                setImportFile(selected);
                                            } })] }), importSummary && (_jsxs(Box, { sx: { border: "1px solid rgba(126,224,255,0.16)", p: 1.5 }, children: [_jsx(Typography, { variant: "subtitle2", fontWeight: 700, mb: 0.5, children: "\u0420\u0435\u0437\u0443\u043B\u044C\u0442\u0430\u0442 \u043F\u043E\u0441\u043B\u0435\u0434\u043D\u0435\u0433\u043E \u0438\u043C\u043F\u043E\u0440\u0442\u0430" }), _jsxs(Typography, { variant: "body2", color: "text.secondary", children: ["hosts: ", importSummary.hosts_created, ", ports: ", importSummary.ports_created, ", services: ", importSummary.services_created, ", endpoints: ", importSummary.endpoints_created] }), importSummary.errors.length > 0 && (_jsxs(Typography, { variant: "body2", color: "warning.main", mt: 0.5, children: ["\u041E\u0448\u0438\u0431\u043A\u0438: ", importSummary.errors.join("; ")] }))] }))] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setImportOpen(false), children: "\u0417\u0430\u043A\u0440\u044B\u0442\u044C" }), _jsx(Button, { variant: "contained", disabled: !importFile || importing, onClick: () => void submitImport(), children: "\u0418\u043C\u043F\u043E\u0440\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C" })] })] }), _jsxs(Dialog, { open: membersDialogOpen, onClose: () => setMembersDialogOpen(false), fullWidth: true, maxWidth: "md", children: [_jsx(DialogTitle, { children: "\u0414\u043E\u0431\u0430\u0432\u0438\u0442\u044C \u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u0435\u0439 \u0432 \u043F\u0440\u043E\u0435\u043A\u0442" }), _jsx(DialogContent, { children: _jsx(Stack, { spacing: 2, sx: { mt: 1 }, children: user?.role === "admin" && (_jsxs(_Fragment, { children: [_jsx(TextField, { label: "\u041F\u043E\u0438\u0441\u043A \u043F\u043E username", value: memberSearchQuery, onChange: (event) => setMemberSearchQuery(event.target.value), placeholder: "\u041D\u0430\u043F\u0440\u0438\u043C\u0435\u0440, alice", fullWidth: true }), _jsx(Typography, { variant: "subtitle2", color: "text.secondary", children: "\u041E\u0442\u043C\u0435\u0447\u0435\u043D\u043D\u044B\u0435 \u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u0438 \u0443\u0436\u0435 \u0441\u043E\u0441\u0442\u043E\u044F\u0442 \u0432 \u043F\u0440\u043E\u0435\u043A\u0442\u0435" }), _jsxs(List, { dense: true, disablePadding: true, sx: {
                                            maxHeight: 360,
                                            overflowY: "auto",
                                            border: "1px solid rgba(126,224,255,0.12)",
                                            backgroundColor: "rgba(8,17,31,0.2)",
                                            px: 1,
                                        }, children: [membersDialogUsers.map((candidate) => {
                                                const checked = candidate.inProject || selectedAvailableMemberIds.includes(candidate.id);
                                                return (_jsx(ListItem, { secondaryAction: _jsx(Checkbox, { edge: "end", checked: checked, disabled: candidate.inProject, sx: candidate.inProject
                                                            ? {
                                                                color: "primary.main",
                                                                "&.Mui-checked": {
                                                                    color: "primary.main",
                                                                },
                                                            }
                                                            : undefined, onChange: (event) => setSelectedAvailableMemberIds((prev) => event.target.checked ? [...prev, candidate.id] : prev.filter((item) => item !== candidate.id)) }), children: _jsx(ListItemText, { primary: `${candidate.username} (${candidate.role})`, secondary: candidate.inProject ? `${candidate.email} • уже в проекте` : candidate.email }) }, candidate.id));
                                            }), membersDialogUsers.length === 0 && (_jsx(Typography, { color: "text.secondary", sx: { px: 1, py: 1.5 }, children: "\u041F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u0438 \u043F\u043E \u044D\u0442\u043E\u043C\u0443 \u0437\u0430\u043F\u0440\u043E\u0441\u0443 \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D\u044B." }))] }), _jsx(Stack, { direction: "row", justifyContent: "flex-end", children: _jsx(Button, { variant: "contained", disabled: selectedAvailableMemberIds.length === 0 || membersBusy, onClick: () => void addMembersToProject(), children: "\u0414\u043E\u0431\u0430\u0432\u0438\u0442\u044C \u0432\u044B\u0431\u0440\u0430\u043D\u043D\u044B\u0445" }) })] })) }) }), _jsx(DialogActions, { children: _jsx(Button, { onClick: () => setMembersDialogOpen(false), children: "\u0417\u0430\u043A\u0440\u044B\u0442\u044C" }) })] }), _jsxs(Dialog, { open: removeMembersDialogOpen, onClose: () => setRemoveMembersDialogOpen(false), fullWidth: true, maxWidth: "md", children: [_jsx(DialogTitle, { children: "\u0423\u0434\u0430\u043B\u0438\u0442\u044C \u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u0435\u0439 \u0438\u0437 \u043F\u0440\u043E\u0435\u043A\u0442\u0430" }), _jsx(DialogContent, { children: _jsx(Stack, { spacing: 1.5, sx: { mt: 1 }, children: _jsxs(List, { dense: true, disablePadding: true, children: [projectMembers.map((member) => {
                                        const checked = selectedMemberIds.includes(member.user_id);
                                        return (_jsx(ListItem, { secondaryAction: _jsx(Checkbox, { edge: "end", checked: checked, onChange: (event) => setSelectedMemberIds((prev) => event.target.checked ? [...prev, member.user_id] : prev.filter((item) => item !== member.user_id)) }), children: _jsx(ListItemText, { primary: `${member.username} (${member.role})`, secondary: member.email }) }, member.user_id));
                                    }), projectMembers.length === 0 && _jsx(Typography, { color: "text.secondary", children: "\u0423\u0447\u0430\u0441\u0442\u043D\u0438\u043A\u0438 \u043F\u043E\u043A\u0430 \u043D\u0435 \u0434\u043E\u0431\u0430\u0432\u043B\u0435\u043D\u044B." })] }) }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setRemoveMembersDialogOpen(false), children: "\u0417\u0430\u043A\u0440\u044B\u0442\u044C" }), _jsx(Button, { color: "error", variant: "contained", startIcon: _jsx(DeleteOutlineIcon, {}), disabled: selectedMemberIds.length === 0 || membersBusy, onClick: () => void removeSelectedMembersFromProject(), children: "\u0423\u0434\u0430\u043B\u0438\u0442\u044C" })] })] })] }));
}
