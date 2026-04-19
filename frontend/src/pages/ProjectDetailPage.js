import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import AddIcon from "@mui/icons-material/Add";
import AccessTimeIcon from "@mui/icons-material/AccessTime";
import AttachFileIcon from "@mui/icons-material/AttachFile";
import DeleteOutlineIcon from "@mui/icons-material/DeleteOutline";
import DownloadIcon from "@mui/icons-material/Download";
import EditIcon from "@mui/icons-material/Edit";
import MoreVertIcon from "@mui/icons-material/MoreVert";
import OpenInNewIcon from "@mui/icons-material/OpenInNew";
import PersonAddAlt1Icon from "@mui/icons-material/PersonAddAlt1";
import UploadFileIcon from "@mui/icons-material/UploadFile";
import { Alert, Box, Button, Card, CardContent, Chip, Dialog, DialogActions, DialogContent, DialogTitle, Divider, Grid2 as Grid, IconButton, List, ListItem, ListItemText, Menu, MenuItem, Stack, TextField, Typography, } from "@mui/material";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { addVulnerabilityAsset, createHost, createVulnerabilityComment, deleteVulnerabilityAsset, addProjectMember, deleteVulnerability, deleteVulnerabilityComment, deleteVulnerabilityFile, generateProjectReport, getEndpoints, getHostVulnerabilities, getHosts, getPorts, getServices, getProjectMembers, getUsers, getProject, getVulnerability, importProjectData, listVulnerabilityComments, listVulnerabilityFiles, removeProjectMember, updateProject, updateVulnerabilityComment, updateVulnerability, uploadVulnerabilityFile, } from "../api";
import { ProjectTreeNav } from "../components/ProjectTreeNav";
import { useAuthStore } from "../store";
const DAY_IN_MS = 24 * 60 * 60 * 1000;
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
export function ProjectDetailPage() {
    const { projectId } = useParams();
    const navigate = useNavigate();
    const user = useAuthStore((s) => s.user);
    const [hosts, setHosts] = useState([]);
    const [ports, setPorts] = useState([]);
    const [endpoints, setEndpoints] = useState([]);
    const [vulnerabilities, setVulnerabilities] = useState([]);
    const [error, setError] = useState(null);
    const [selectedHostId, setSelectedHostId] = useState(null);
    const [selectedSection, setSelectedSection] = useState("overview");
    const [isSidebarCollapsed, setSidebarCollapsed] = useState(false);
    const [projectName, setProjectName] = useState("");
    const [projectDescription, setProjectDescription] = useState("");
    const [projectStartDate, setProjectStartDate] = useState(null);
    const [projectEndDate, setProjectEndDate] = useState(null);
    const [projectMembers, setProjectMembers] = useState([]);
    const [usersCatalog, setUsersCatalog] = useState([]);
    const [membersDialogOpen, setMembersDialogOpen] = useState(false);
    const [selectedMemberUserId, setSelectedMemberUserId] = useState("");
    const [membersBusy, setMembersBusy] = useState(false);
    const [hostStatsById, setHostStatsById] = useState({});
    const [importOpen, setImportOpen] = useState(false);
    const [importFile, setImportFile] = useState(null);
    const [importing, setImporting] = useState(false);
    const [importSummary, setImportSummary] = useState(null);
    const [reportLoadingFormat, setReportLoadingFormat] = useState(null);
    const [actionsAnchorEl, setActionsAnchorEl] = useState(null);
    const [exportOpen, setExportOpen] = useState(false);
    const [exportFormat, setExportFormat] = useState("pdf");
    const [extendDialogOpen, setExtendDialogOpen] = useState(false);
    const [extendEndDate, setExtendEndDate] = useState("");
    const [extendingProject, setExtendingProject] = useState(false);
    const storagePrefix = projectId ? `project-detail:${projectId}` : null;
    const [hostOpen, setHostOpen] = useState(false);
    const [hostIp, setHostIp] = useState("");
    const [hostName, setHostName] = useState("");
    const [hostStatus, setHostStatus] = useState("unknown");
    const [hostNotes, setHostNotes] = useState("");
    const [vulnDetailOpen, setVulnDetailOpen] = useState(false);
    const [activeVuln, setActiveVuln] = useState(null);
    const [vulnFiles, setVulnFiles] = useState([]);
    const [vulnComments, setVulnComments] = useState([]);
    const [assetHosts, setAssetHosts] = useState([]);
    const [assetPorts, setAssetPorts] = useState([]);
    const [assetEndpoints, setAssetEndpoints] = useState([]);
    const [assetServices, setAssetServices] = useState([]);
    const [linkAssetType, setLinkAssetType] = useState("host");
    const [linkAssetId, setLinkAssetId] = useState("");
    const [newComment, setNewComment] = useState("");
    const [vulnBusy, setVulnBusy] = useState(false);
    const [editCommentOpen, setEditCommentOpen] = useState(false);
    const [editingCommentId, setEditingCommentId] = useState(null);
    const [editingCommentContent, setEditingCommentContent] = useState("");
    const availableUsers = useMemo(() => usersCatalog.filter((candidate) => !projectMembers.some((member) => member.user_id === candidate.id)), [projectMembers, usersCatalog]);
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
            setProjectStartDate(projectResp.start_date);
            setProjectEndDate(projectResp.end_date);
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
        catch {
            setError("Не удалось загрузить данные проекта");
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
        catch {
            setError("Не удалось загрузить структуру выбранного хоста");
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
                statusLabel: "Стандартный срок: 14 дней",
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
    }, [projectStartDate, projectEndDate]);
    const timelineBar = useMemo(() => {
        const startRaw = parseIsoDateOnly(projectStartDate);
        const endRaw = parseIsoDateOnly(projectEndDate);
        const start = startRaw ?? (endRaw ? new Date(endRaw.getTime() - 14 * DAY_IN_MS) : null);
        const end = endRaw ?? (startRaw ? new Date(startRaw.getTime() + 14 * DAY_IN_MS) : null);
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        if (!start || !end || end.getTime() <= start.getTime()) {
            return {
                ready: false,
            };
        }
        const totalDays = Math.max(1, Math.ceil((end.getTime() - start.getTime()) / DAY_IN_MS));
        const elapsedInclusive = Math.floor((today.getTime() - start.getTime()) / DAY_IN_MS) + 1;
        const passedDays = Math.max(0, Math.min(totalDays, elapsedInclusive));
        const reportStartIndex = Math.max(0, totalDays - 2);
        const cells = Array.from({ length: totalDays }, (_, index) => {
            const isElapsed = index < passedDays;
            const isReportWindow = index >= reportStartIndex;
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
            return { bgColor };
        });
        return {
            ready: true,
            totalDays,
            cells,
            startLabel: start.toLocaleDateString("ru-RU"),
            endLabel: end.toLocaleDateString("ru-RU"),
        };
    }, [projectStartDate, projectEndDate]);
    const submitHost = async () => {
        if (!projectId) {
            return;
        }
        await createHost(projectId, {
            ip_address: hostIp || undefined,
            hostname: hostName || undefined,
            notes: hostNotes || undefined,
            status: hostStatus,
        });
        setHostOpen(false);
        setHostIp("");
        setHostName("");
        setHostNotes("");
        setHostStatus("unknown");
        await loadProjectData();
    };
    const selectedHost = hosts.find((host) => host.id === selectedHostId) ?? null;
    const hostLabel = selectedHost ? selectedHost.hostname || selectedHost.ip_address || "unknown-host" : "Хост не выбран";
    useEffect(() => {
        // #region agent log
        fetch("http://127.0.0.1:7847/ingest/092a8b93-589d-44d5-a2a5-67f255084dee", {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "a74592" },
            body: JSON.stringify({
                sessionId: "a74592",
                runId: "vuln-card-pre",
                hypothesisId: "H4",
                location: "ProjectDetailPage.tsx:vuln-dialog-state",
                message: "Project vulnerability dialog state changed",
                data: { vulnDetailOpen, activeVulnId: activeVuln?.id ?? null, selectedHostId: selectedHostId ?? null },
                timestamp: Date.now(),
            }),
        }).catch(() => { });
        // #endregion
    }, [vulnDetailOpen, activeVuln?.id, selectedHostId]);
    const loadHostAssetsCatalog = async () => {
        if (!projectId || !selectedHostId || !selectedHost) {
            // #region agent log
            fetch("http://127.0.0.1:7847/ingest/092a8b93-589d-44d5-a2a5-67f255084dee", {
                method: "POST",
                headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "a74592" },
                body: JSON.stringify({
                    sessionId: "a74592",
                    runId: "vuln-card-pre",
                    hypothesisId: "H3",
                    location: "ProjectDetailPage.tsx:loadHostAssetsCatalog:empty",
                    message: "Project host assets catalog skipped due to missing host context",
                    data: { projectId: projectId ?? null, selectedHostId: selectedHostId ?? null, hasSelectedHost: Boolean(selectedHost) },
                    timestamp: Date.now(),
                }),
            }).catch(() => { });
            // #endregion
            setAssetHosts([]);
            setAssetPorts([]);
            setAssetEndpoints([]);
            setAssetServices([]);
            return;
        }
        const [hostPorts, hostEndpoints] = await Promise.all([getPorts(projectId, selectedHostId), getEndpoints(projectId, selectedHostId)]);
        const hostServices = (await Promise.all(hostPorts.map(async (port) => await getServices(projectId, selectedHostId, port.id)))).flat();
        // #region agent log
        fetch("http://127.0.0.1:7847/ingest/092a8b93-589d-44d5-a2a5-67f255084dee", {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "a74592" },
            body: JSON.stringify({
                sessionId: "a74592",
                runId: "vuln-card-pre",
                hypothesisId: "H3",
                location: "ProjectDetailPage.tsx:loadHostAssetsCatalog:success",
                message: "Project host assets catalog loaded",
                data: { selectedHostId, portsCount: hostPorts.length, endpointsCount: hostEndpoints.length, servicesCount: hostServices.length },
                timestamp: Date.now(),
            }),
        }).catch(() => { });
        // #endregion
        setAssetHosts([selectedHost]);
        setAssetPorts(hostPorts);
        setAssetEndpoints(hostEndpoints);
        setAssetServices(hostServices);
    };
    const loadVulnerabilityDetails = async (vulnerabilityId) => {
        if (!projectId) {
            return;
        }
        setVulnBusy(true);
        setError(null);
        try {
            // #region agent log
            fetch("http://127.0.0.1:7847/ingest/092a8b93-589d-44d5-a2a5-67f255084dee", {
                method: "POST",
                headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "a74592" },
                body: JSON.stringify({
                    sessionId: "a74592",
                    runId: "vuln-card-pre",
                    hypothesisId: "H2",
                    location: "ProjectDetailPage.tsx:loadVulnerabilityDetails:start",
                    message: "Project vulnerability details load started",
                    data: { projectId, vulnerabilityId, selectedHostId: selectedHostId ?? null },
                    timestamp: Date.now(),
                }),
            }).catch(() => { });
            // #endregion
            const [vulnDetail, files, commentsPage] = await Promise.all([
                getVulnerability(projectId, vulnerabilityId),
                listVulnerabilityFiles(projectId, vulnerabilityId),
                listVulnerabilityComments(projectId, vulnerabilityId),
            ]);
            setActiveVuln(vulnDetail);
            setVulnFiles(files);
            setVulnComments(commentsPage.items);
            await loadHostAssetsCatalog();
            // #region agent log
            fetch("http://127.0.0.1:7847/ingest/092a8b93-589d-44d5-a2a5-67f255084dee", {
                method: "POST",
                headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "a74592" },
                body: JSON.stringify({
                    sessionId: "a74592",
                    runId: "vuln-card-pre",
                    hypothesisId: "H4",
                    location: "ProjectDetailPage.tsx:loadVulnerabilityDetails:success",
                    message: "Project vulnerability details loaded",
                    data: { vulnerabilityId, filesCount: files.length, commentsCount: commentsPage.items.length, assetsCount: vulnDetail.assets.length },
                    timestamp: Date.now(),
                }),
            }).catch(() => { });
            // #endregion
            setVulnDetailOpen(true);
        }
        catch (error) {
            // #region agent log
            fetch("http://127.0.0.1:7847/ingest/092a8b93-589d-44d5-a2a5-67f255084dee", {
                method: "POST",
                headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "a74592" },
                body: JSON.stringify({
                    sessionId: "a74592",
                    runId: "vuln-card-pre",
                    hypothesisId: "H2",
                    location: "ProjectDetailPage.tsx:loadVulnerabilityDetails:error",
                    message: "Project vulnerability details load failed",
                    data: {
                        vulnerabilityId,
                        errorMessage: error instanceof Error ? error.message : "unknown",
                        responseStatus: typeof error === "object" && error !== null && "response" in error
                            ? (error.response?.status ?? null)
                            : null,
                    },
                    timestamp: Date.now(),
                }),
            }).catch(() => { });
            // #endregion
            setError("Не удалось загрузить карточку уязвимости");
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
                description: activeVuln.description || undefined,
                severity: activeVuln.severity,
                status: activeVuln.status,
                cvss_version: activeVuln.cvss_version || undefined,
                cvss_score: activeVuln.cvss_score ?? undefined,
                cvss_vector: activeVuln.cvss_vector || undefined,
                cwe_id: activeVuln.cwe_id || undefined,
                steps_to_reproduce: activeVuln.steps_to_reproduce || undefined,
                impact: activeVuln.impact || undefined,
                recommendations: activeVuln.recommendations || undefined,
            });
            setActiveVuln((prev) => (prev ? { ...prev, ...updated } : prev));
            await loadHostAssets();
        }
        catch {
            setError("Не удалось сохранить уязвимость");
        }
        finally {
            setVulnBusy(false);
        }
    };
    const removeActiveVulnerability = async () => {
        if (!projectId || !activeVuln) {
            return;
        }
        setVulnBusy(true);
        setError(null);
        try {
            await deleteVulnerability(projectId, activeVuln.id);
            setVulnDetailOpen(false);
            setActiveVuln(null);
            await loadHostAssets();
        }
        catch {
            setError("Не удалось удалить уязвимость");
        }
        finally {
            setVulnBusy(false);
        }
    };
    const uploadFileToActiveVuln = async (file) => {
        if (!projectId || !activeVuln || !file) {
            return;
        }
        setVulnBusy(true);
        try {
            await uploadVulnerabilityFile(projectId, activeVuln.id, file);
            const files = await listVulnerabilityFiles(projectId, activeVuln.id);
            setVulnFiles(files);
        }
        catch {
            setError("Не удалось загрузить файл");
        }
        finally {
            setVulnBusy(false);
        }
    };
    const removeVulnerabilityFile = async (fileId) => {
        if (!projectId || !activeVuln) {
            return;
        }
        setVulnBusy(true);
        try {
            await deleteVulnerabilityFile(projectId, activeVuln.id, fileId);
            const files = await listVulnerabilityFiles(projectId, activeVuln.id);
            setVulnFiles(files);
        }
        catch {
            setError("Не удалось удалить файл");
        }
        finally {
            setVulnBusy(false);
        }
    };
    const linkAssetOptions = useMemo(() => {
        if (linkAssetType === "host") {
            return assetHosts.map((host) => ({
                id: host.id,
                label: `Host: ${host.hostname || host.ip_address || host.id}`,
            }));
        }
        if (linkAssetType === "port") {
            return assetPorts.map((port) => ({
                id: port.id,
                label: `Port: ${port.port_number}/${port.protocol}`,
            }));
        }
        if (linkAssetType === "service") {
            return assetServices.map((service) => ({
                id: service.id,
                label: `Service: ${service.name}${service.version ? ` ${service.version}` : ""}`,
            }));
        }
        return assetEndpoints.map((endpoint) => ({
            id: endpoint.id,
            label: `Endpoint: ${(endpoint.method || "ANY").toUpperCase()} ${endpoint.path}`,
        }));
    }, [assetEndpoints, assetHosts, assetPorts, assetServices, linkAssetType]);
    const resolveAssetLabel = (assetType, assetId) => {
        if (assetType === "host") {
            const host = assetHosts.find((item) => item.id === assetId);
            return host ? `Host: ${host.hostname || host.ip_address || host.id}` : `host:${assetId}`;
        }
        if (assetType === "port") {
            const port = assetPorts.find((item) => item.id === assetId);
            return port ? `Port: ${port.port_number}/${port.protocol}` : `port:${assetId}`;
        }
        if (assetType === "service") {
            const service = assetServices.find((item) => item.id === assetId);
            return service ? `Service: ${service.name}${service.version ? ` ${service.version}` : ""}` : `service:${assetId}`;
        }
        const endpoint = assetEndpoints.find((item) => item.id === assetId);
        return endpoint ? `Endpoint: ${(endpoint.method || "ANY").toUpperCase()} ${endpoint.path}` : `endpoint:${assetId}`;
    };
    const addAssetLinkToActiveVuln = async () => {
        if (!projectId || !activeVuln || !linkAssetId) {
            return;
        }
        setVulnBusy(true);
        setError(null);
        try {
            await addVulnerabilityAsset(projectId, activeVuln.id, {
                asset_type: linkAssetType,
                asset_id: linkAssetId,
            });
            await loadVulnerabilityDetails(activeVuln.id);
            setLinkAssetId("");
        }
        catch {
            setError("Не удалось привязать актив к уязвимости");
        }
        finally {
            setVulnBusy(false);
        }
    };
    const removeAssetLinkFromActiveVuln = async (assetLinkId) => {
        if (!projectId || !activeVuln) {
            return;
        }
        setVulnBusy(true);
        setError(null);
        try {
            await deleteVulnerabilityAsset(projectId, activeVuln.id, assetLinkId);
            await loadVulnerabilityDetails(activeVuln.id);
        }
        catch {
            setError("Не удалось удалить привязку актива");
        }
        finally {
            setVulnBusy(false);
        }
    };
    const addCommentToActiveVuln = async () => {
        if (!projectId || !activeVuln || !newComment.trim()) {
            return;
        }
        setVulnBusy(true);
        try {
            await createVulnerabilityComment(projectId, activeVuln.id, newComment.trim());
            const commentsPage = await listVulnerabilityComments(projectId, activeVuln.id);
            setVulnComments(commentsPage.items);
            setNewComment("");
        }
        catch {
            setError("Не удалось добавить комментарий");
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
            const commentsPage = await listVulnerabilityComments(projectId, activeVuln.id);
            setVulnComments(commentsPage.items);
        }
        catch {
            setError("Не удалось удалить комментарий");
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
            await updateVulnerabilityComment(projectId, activeVuln.id, editingCommentId, editingCommentContent.trim());
            const commentsPage = await listVulnerabilityComments(projectId, activeVuln.id);
            setVulnComments(commentsPage.items);
            setEditCommentOpen(false);
            setEditingCommentId(null);
            setEditingCommentContent("");
        }
        catch {
            setError("Не удалось обновить комментарий");
        }
        finally {
            setVulnBusy(false);
        }
    };
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
        catch {
            setError("Не удалось импортировать JSON-данные проекта");
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
        catch {
            setError("Не удалось сформировать отчёт");
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
    const openExtendDialog = () => {
        setError(null);
        setExtendEndDate(projectEndDate ?? "");
        setExtendDialogOpen(true);
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
        catch {
            setError("Не удалось продлить срок проекта");
        }
        finally {
            setExtendingProject(false);
        }
    };
    const openMembersDialog = async () => {
        if (!projectId) {
            return;
        }
        setError(null);
        setMembersDialogOpen(true);
        if (user?.role !== "admin") {
            return;
        }
        try {
            const usersResponse = await getUsers(1, 200);
            setUsersCatalog(usersResponse.items);
        }
        catch {
            setError("Не удалось загрузить список пользователей для управления участниками.");
        }
    };
    const addMemberToProject = async () => {
        if (!projectId || !selectedMemberUserId) {
            return;
        }
        setMembersBusy(true);
        setError(null);
        try {
            await addProjectMember(projectId, selectedMemberUserId);
            setSelectedMemberUserId("");
            await loadProjectData();
        }
        catch {
            setError("Не удалось добавить участника в проект.");
        }
        finally {
            setMembersBusy(false);
        }
    };
    const removeMemberFromProject = async (memberUserId) => {
        if (!projectId) {
            return;
        }
        setMembersBusy(true);
        setError(null);
        try {
            await removeProjectMember(projectId, memberUserId);
            await loadProjectData();
        }
        catch {
            setError("Не удалось удалить участника из проекта.");
        }
        finally {
            setMembersBusy(false);
        }
    };
    return (_jsxs(Stack, { spacing: 2.5, children: [error && _jsx(Alert, { severity: "error", children: error }), _jsxs(Stack, { direction: "row", justifyContent: "space-between", alignItems: "center", children: [_jsxs(Box, { children: [_jsx(Typography, { variant: "overline", color: "primary.main", sx: { letterSpacing: 1.4, fontWeight: 700 }, children: "Project Workspace" }), _jsx(Typography, { variant: "h4", fontWeight: 700, children: projectName ? `Проект: ${projectName}` : "Проект" })] }), _jsx(IconButton, { onClick: openActionsMenu, sx: { border: "1px solid rgba(126,224,255,0.2)", width: 42, height: 42, backgroundColor: "rgba(15,27,45,0.72)" }, children: _jsx(MoreVertIcon, {}) })] }), _jsxs(Menu, { anchorEl: actionsAnchorEl, open: actionsMenuOpen, onClose: closeActionsMenu, anchorOrigin: { vertical: "bottom", horizontal: "right" }, transformOrigin: { vertical: "top", horizontal: "right" }, children: [_jsxs(MenuItem, { onClick: () => {
                            closeActionsMenu();
                            setImportOpen(true);
                        }, children: [_jsx(UploadFileIcon, { fontSize: "small", sx: { mr: 1 } }), "\u0418\u043C\u043F\u043E\u0440\u0442 JSON"] }), _jsxs(MenuItem, { onClick: () => {
                            closeActionsMenu();
                            setExportOpen(true);
                        }, children: [_jsx(DownloadIcon, { fontSize: "small", sx: { mr: 1 } }), "\u042D\u043A\u0441\u043F\u043E\u0440\u0442"] }), user?.role === "admin" && (_jsxs(MenuItem, { onClick: () => {
                            closeActionsMenu();
                            openExtendDialog();
                        }, children: [_jsx(AccessTimeIcon, { fontSize: "small", sx: { mr: 1 } }), "\u041F\u0440\u043E\u0434\u043B\u0438\u0442\u044C \u043F\u0440\u043E\u0435\u043A\u0442"] }))] }), _jsxs(Stack, { direction: { xs: "column", md: "row" }, spacing: 2, children: [_jsx(ProjectTreeNav, { hosts: hosts, selectedHostId: selectedHostId, selectedSection: selectedSection, isCollapsed: isSidebarCollapsed, portsCount: ports.length, endpointsCount: endpoints.length, vulnerabilitiesCount: vulnerabilities.length, hostStatsById: hostStatsById, autoExpandSelectedHost: false, onToggleCollapsed: () => setSidebarCollapsed((v) => !v), onSelectSection: setSelectedSection, onSelectProjectOverview: () => setSelectedSection("overview"), onSelectHost: setSelectedHostId, onOpenHost: (hostId) => navigate(`/projects/${projectId}/hosts/${hostId}`) }), _jsxs(Stack, { flex: 1, spacing: 2, children: [selectedSection !== "overview" && (_jsx(Card, { sx: { border: "1px solid rgba(126,224,255,0.14)" }, children: _jsx(CardContent, { children: _jsxs(Typography, { variant: "h6", fontWeight: 700, children: [selectedSection === "hosts" && `Хост: ${hostLabel}`, selectedSection === "ports" && `Порты хоста: ${hostLabel}`, selectedSection === "endpoints" && `Эндпоинты хоста: ${hostLabel}`, selectedSection === "vulns" && `Уязвимости хоста: ${hostLabel}`] }) }) })), selectedSection === "overview" && (_jsxs(Stack, { spacing: 2, children: [_jsx(Card, { sx: { border: "1px solid rgba(126,224,255,0.14)" }, children: _jsxs(CardContent, { children: [_jsxs(Stack, { direction: { xs: "column", md: "row" }, justifyContent: "space-between", spacing: 1, alignItems: { md: "center" }, children: [_jsxs(Stack, { direction: "row", spacing: 1, alignItems: "center", flexWrap: "wrap", children: [_jsx(Typography, { variant: "h6", fontWeight: 700, children: "\u0422\u0430\u0439\u043C\u043B\u0430\u0439\u043D \u043F\u0440\u043E\u0435\u043A\u0442\u0430" }), _jsx(Chip, { size: "small", color: projectTimeMetrics.statusTone === "neutral" ? "default" : projectTimeMetrics.statusTone, label: projectTimeMetrics.statusLabel }), projectTimeMetrics.daysLeft !== null && (_jsx(Chip, { size: "small", variant: "outlined", label: projectTimeMetrics.daysLeft >= 0
                                                                        ? `${projectTimeMetrics.daysLeft} дн. осталось`
                                                                        : `${Math.abs(projectTimeMetrics.daysLeft)} дн. просрочки` }))] }), user?.role === "admin" && (_jsx(Button, { size: "small", variant: "outlined", startIcon: _jsx(AccessTimeIcon, {}), onClick: openExtendDialog, children: "\u041F\u0440\u043E\u0434\u043B\u0438\u0442\u044C" }))] }), _jsx(Box, { sx: { mt: 1.5 }, children: timelineBar.ready ? (_jsxs(_Fragment, { children: [_jsx(Box, { sx: {
                                                                    display: "grid",
                                                                    gridTemplateColumns: `repeat(${timelineBar.totalDays}, minmax(12px, 1fr))`,
                                                                    gap: 0.5,
                                                                    p: 1,
                                                                    border: "1px solid rgba(126,224,255,0.12)",
                                                                    borderRadius: 0,
                                                                    backgroundColor: "rgba(8,17,31,0.34)",
                                                                }, children: timelineBar.cells.map((cell, index) => (_jsx(Box, { sx: {
                                                                        height: 16,
                                                                        border: "1px solid rgba(126,224,255,0.16)",
                                                                        backgroundColor: cell.bgColor,
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
                                                    }, children: [_jsx(IconButton, { size: "small", className: "overview-card-action", onClick: () => setHostOpen(true), sx: {
                                                                position: "absolute",
                                                                top: 10,
                                                                right: 10,
                                                                border: "1px solid rgba(126,224,255,0.18)",
                                                                backgroundColor: "rgba(15,27,45,0.88)",
                                                            }, children: _jsx(AddIcon, { fontSize: "small" }) }), _jsxs(CardContent, { children: [_jsx(Typography, { color: "text.secondary", mb: 1, children: "\u0425\u043E\u0441\u0442\u044B \u043F\u0440\u043E\u0435\u043A\u0442\u0430" }), _jsx(Typography, { variant: "h4", fontWeight: 700, children: hosts.length }), _jsx(Stack, { spacing: 0.8, mt: 1, sx: { maxHeight: 160, overflowY: "auto", pr: 0.5 }, children: hosts.length > 0 ? (hosts.map((host) => (_jsx(Box, { sx: { px: 1.2, py: 0.9, border: "1px solid rgba(126,224,255,0.10)", borderRadius: 0, backgroundColor: "rgba(8,17,31,0.28)" }, children: _jsx(Typography, { variant: "body2", color: "text.primary", children: host.hostname || host.ip_address || "unknown-host" }) }, host.id)))) : (_jsx(Typography, { color: "text.secondary", children: "\u0425\u043E\u0441\u0442\u044B \u043D\u0435 \u0434\u043E\u0431\u0430\u0432\u043B\u0435\u043D\u044B" })) })] })] }) }), _jsx(Grid, { size: { xs: 12, md: 6 }, children: _jsxs(Card, { sx: {
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
                                                    }, children: [user?.role === "admin" && (_jsx(IconButton, { size: "small", className: "overview-card-action", onClick: () => void openMembersDialog(), sx: {
                                                                position: "absolute",
                                                                top: 10,
                                                                right: 10,
                                                                border: "1px solid rgba(126,224,255,0.18)",
                                                                backgroundColor: "rgba(15,27,45,0.88)",
                                                            }, children: _jsx(AddIcon, { fontSize: "small" }) })), _jsxs(CardContent, { sx: { height: "100%" }, children: [_jsx(Typography, { color: "text.secondary", mb: 1, children: "\u0423\u0447\u0430\u0441\u0442\u043D\u0438\u043A\u0438 \u043F\u0440\u043E\u0435\u043A\u0442\u0430" }), _jsx(Typography, { variant: "h4", fontWeight: 700, mb: 1, children: projectMembers.length }), _jsx(Stack, { spacing: 0.8, sx: { maxHeight: 160, overflowY: "auto", pr: 0.5 }, children: projectMembers.length > 0 ? (projectMembers.map((member) => (_jsx(Box, { sx: { px: 1.2, py: 0.9, border: "1px solid rgba(126,224,255,0.10)", borderRadius: 0, backgroundColor: "rgba(8,17,31,0.28)" }, children: _jsxs(Typography, { variant: "body2", color: "text.primary", children: [member.username, " (", member.role, ")"] }) }, member.user_id)))) : (_jsx(Typography, { color: "text.secondary", children: "\u0423\u0447\u0430\u0441\u0442\u043D\u0438\u043A\u0438 \u043D\u0435 \u0434\u043E\u0431\u0430\u0432\u043B\u0435\u043D\u044B" })) })] })] }) })] }), _jsx(Card, { sx: { border: "1px solid rgba(126,224,255,0.14)" }, children: _jsxs(CardContent, { children: [_jsx(Typography, { variant: "h6", fontWeight: 700, mb: 1, children: "\u041E\u043F\u0438\u0441\u0430\u043D\u0438\u0435 \u043F\u0440\u043E\u0435\u043A\u0442\u0430" }), _jsx(Typography, { color: "text.secondary", whiteSpace: "pre-wrap", children: projectDescription || "Описание проекта не заполнено" })] }) })] })), selectedSection === "hosts" && (_jsx(Card, { sx: { border: "1px solid rgba(126,224,255,0.14)" }, children: _jsx(CardContent, { children: _jsx(Stack, { spacing: 1.2, children: hosts.map((host) => (_jsxs(Box, { sx: { border: "1px solid rgba(126,224,255,0.12)", p: 1.6, borderRadius: 0, cursor: "pointer", backgroundColor: "rgba(8,17,31,0.24)" }, onClick: () => navigate(`/projects/${projectId}/hosts/${host.id}`), children: [_jsx(Typography, { children: host.hostname || host.ip_address || "unknown-host" }), _jsxs(Typography, { variant: "body2", color: "text.secondary", children: ["\u0421\u0442\u0430\u0442\u0443\u0441: ", host.status] })] }, host.id))) }) }) })), selectedSection === "ports" && (_jsx(Card, { sx: { border: "1px solid rgba(126,224,255,0.14)" }, children: _jsx(CardContent, { children: _jsxs(Stack, { spacing: 1.2, children: [ports.map((port) => (_jsx(Box, { sx: { border: "1px solid rgba(126,224,255,0.12)", p: 1.5, borderRadius: 0, backgroundColor: "rgba(8,17,31,0.24)" }, children: _jsxs(Stack, { direction: "row", spacing: 1, alignItems: "center", children: [_jsxs(Typography, { fontWeight: 600, children: [port.port_number, "/", port.protocol] }), _jsx(Chip, { size: "small", label: port.state })] }) }, port.id))), ports.length === 0 && (_jsx(Typography, { color: "text.secondary", children: "\u041F\u043E\u0440\u0442\u044B \u043D\u0435 \u0434\u043E\u0431\u0430\u0432\u043B\u0435\u043D\u044B. \u0412\u044B\u0431\u0435\u0440\u0438\u0442\u0435 \u0445\u043E\u0441\u0442 \u0438 \u0434\u043E\u0431\u0430\u0432\u044C\u0442\u0435 \u043F\u0435\u0440\u0432\u044B\u0439 \u043F\u043E\u0440\u0442." }))] }) }) })), selectedSection === "endpoints" && (_jsx(Card, { sx: { border: "1px solid rgba(126,224,255,0.14)" }, children: _jsx(CardContent, { children: _jsxs(Stack, { spacing: 1.2, children: [endpoints.map((endpoint) => (_jsxs(Box, { sx: { border: "1px solid rgba(126,224,255,0.12)", p: 1.5, borderRadius: 0, backgroundColor: "rgba(8,17,31,0.24)" }, children: [_jsxs(Stack, { direction: "row", spacing: 1, alignItems: "center", children: [_jsx(Chip, { size: "small", label: endpoint.method || "ANY" }), _jsx(Typography, { fontWeight: 600, children: endpoint.path })] }), _jsx(Typography, { variant: "body2", color: "text.secondary", mt: 0.8, children: endpoint.description || "Описание не указано" })] }, endpoint.id))), endpoints.length === 0 && (_jsx(Typography, { color: "text.secondary", children: "\u042D\u043D\u0434\u043F\u043E\u0438\u043D\u0442\u044B \u043D\u0435 \u0434\u043E\u0431\u0430\u0432\u043B\u0435\u043D\u044B. \u0412\u044B\u0431\u0435\u0440\u0438\u0442\u0435 \u0445\u043E\u0441\u0442 \u0438 \u0434\u043E\u0431\u0430\u0432\u044C\u0442\u0435 \u043F\u0435\u0440\u0432\u044B\u0439 \u044D\u043D\u0434\u043F\u043E\u0438\u043D\u0442." }))] }) }) })), selectedSection === "vulns" && (_jsx(Card, { sx: { border: "1px solid rgba(126,224,255,0.14)" }, children: _jsxs(CardContent, { children: [_jsx(Stack, { direction: "row", spacing: 1, mb: 2, flexWrap: "wrap", children: Object.entries(vulnerabilities.reduce((acc, item) => {
                                                acc[item.severity] += 1;
                                                return acc;
                                            }, { critical: 0, high: 0, medium: 0, low: 0, info: 0 })).map(([severity, value]) => (_jsx(Chip, { label: `${severity}: ${value}` }, severity))) }), _jsxs(Stack, { spacing: 1.2, children: [vulnerabilities.map((item) => (_jsxs(Box, { sx: { border: "1px solid rgba(126,224,255,0.12)", p: 1.5, borderRadius: 0, backgroundColor: "rgba(8,17,31,0.24)" }, children: [_jsxs(Stack, { direction: "row", justifyContent: "space-between", alignItems: "center", children: [_jsx(Typography, { children: item.title }), _jsx(Button, { size: "small", variant: "outlined", onClick: () => void loadVulnerabilityDetails(item.id), disabled: vulnBusy, children: "\u041E\u0442\u043A\u0440\u044B\u0442\u044C" })] }), _jsxs(Stack, { direction: "row", spacing: 1, mt: 1, flexWrap: "wrap", children: [_jsx(Chip, { label: item.severity, size: "small", sx: severityChipSx[item.severity] }), _jsx(Chip, { label: item.status, size: "small", sx: vulnerabilityStatusChipSx[item.status] })] })] }, item.id))), vulnerabilities.length === 0 && _jsx(Typography, { color: "text.secondary", children: "\u0414\u043B\u044F \u0432\u044B\u0431\u0440\u0430\u043D\u043D\u043E\u0433\u043E \u0445\u043E\u0441\u0442\u0430 \u0443\u044F\u0437\u0432\u0438\u043C\u043E\u0441\u0442\u0438 \u043D\u0435 \u043F\u0440\u0438\u0432\u044F\u0437\u0430\u043D\u044B." })] })] }) }))] })] }), _jsxs(Dialog, { open: hostOpen, onClose: () => setHostOpen(false), fullWidth: true, children: [_jsx(DialogTitle, { children: "\u0414\u043E\u0431\u0430\u0432\u0438\u0442\u044C \u0445\u043E\u0441\u0442" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [_jsx(TextField, { label: "IP-\u0430\u0434\u0440\u0435\u0441", value: hostIp, onChange: (e) => setHostIp(e.target.value) }), _jsx(TextField, { label: "Hostname", value: hostName, onChange: (e) => setHostName(e.target.value) }), _jsxs(TextField, { select: true, label: "\u0421\u0442\u0430\u0442\u0443\u0441", value: hostStatus, onChange: (e) => setHostStatus(e.target.value), children: [_jsx(MenuItem, { value: "up", children: "up" }), _jsx(MenuItem, { value: "down", children: "down" }), _jsx(MenuItem, { value: "unknown", children: "unknown" })] }), _jsx(TextField, { label: "\u041E\u043F\u0438\u0441\u0430\u043D\u0438\u0435", multiline: true, minRows: 3, value: hostNotes, onChange: (e) => setHostNotes(e.target.value) })] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setHostOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", disabled: !hostIp && !hostName, onClick: () => void submitHost(), children: "\u0421\u043E\u0445\u0440\u0430\u043D\u0438\u0442\u044C" })] })] }), _jsxs(Dialog, { open: extendDialogOpen, onClose: () => setExtendDialogOpen(false), fullWidth: true, maxWidth: "xs", children: [_jsx(DialogTitle, { children: "\u041F\u0440\u043E\u0434\u043B\u0438\u0442\u044C \u043F\u0440\u043E\u0435\u043A\u0442" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 1.5, sx: { mt: 1 }, children: [_jsxs(Typography, { variant: "body2", color: "text.secondary", children: ["\u0422\u0435\u043A\u0443\u0449\u0430\u044F \u0434\u0430\u0442\u0430 \u043E\u043A\u043E\u043D\u0447\u0430\u043D\u0438\u044F: ", projectEndDate || "не задана"] }), _jsx(TextField, { label: "\u041D\u043E\u0432\u0430\u044F \u0434\u0430\u0442\u0430 \u043E\u043A\u043E\u043D\u0447\u0430\u043D\u0438\u044F", type: "date", value: extendEndDate, onChange: (event) => setExtendEndDate(event.target.value), InputLabelProps: { shrink: true } }), _jsxs(Stack, { direction: "row", spacing: 1, children: [_jsx(Button, { size: "small", variant: "text", onClick: () => applyQuickExtension(7), children: "+7 \u0434\u043D\u0435\u0439" }), _jsx(Button, { size: "small", variant: "text", onClick: () => applyQuickExtension(14), children: "+14 \u0434\u043D\u0435\u0439" }), _jsx(Button, { size: "small", variant: "text", onClick: () => applyQuickExtension(30), children: "+30 \u0434\u043D\u0435\u0439" })] })] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setExtendDialogOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", disabled: !extendEndDate || extendingProject, onClick: () => void submitProjectExtension(), children: "\u041F\u0440\u043E\u0434\u043B\u0438\u0442\u044C" })] })] }), _jsxs(Dialog, { open: vulnDetailOpen, onClose: () => setVulnDetailOpen(false), fullWidth: true, maxWidth: "lg", children: [_jsx(DialogTitle, { children: "\u041A\u0430\u0440\u0442\u043E\u0447\u043A\u0430 \u0443\u044F\u0437\u0432\u0438\u043C\u043E\u0441\u0442\u0438" }), _jsx(DialogContent, { children: !activeVuln ? (_jsx(Typography, { color: "text.secondary", children: "\u0423\u044F\u0437\u0432\u0438\u043C\u043E\u0441\u0442\u044C \u043D\u0435 \u0432\u044B\u0431\u0440\u0430\u043D\u0430." })) : (_jsxs(Stack, { spacing: 2, sx: { mt: 0.5 }, children: [_jsxs(Grid, { container: true, spacing: 2, children: [_jsx(Grid, { size: { xs: 12, md: 8 }, children: _jsx(TextField, { label: "\u041D\u0430\u0437\u0432\u0430\u043D\u0438\u0435", fullWidth: true, value: activeVuln.title, onChange: (e) => setActiveVuln((prev) => (prev ? { ...prev, title: e.target.value } : prev)) }) }), _jsx(Grid, { size: { xs: 12, md: 2 }, children: _jsxs(TextField, { select: true, label: "\u041A\u0440\u0438\u0442\u0438\u0447\u043D\u043E\u0441\u0442\u044C", fullWidth: true, value: activeVuln.severity, onChange: (e) => setActiveVuln((prev) => (prev ? { ...prev, severity: e.target.value } : prev)), children: [_jsx(MenuItem, { value: "critical", children: "critical" }), _jsx(MenuItem, { value: "high", children: "high" }), _jsx(MenuItem, { value: "medium", children: "medium" }), _jsx(MenuItem, { value: "low", children: "low" }), _jsx(MenuItem, { value: "info", children: "info" })] }) }), _jsx(Grid, { size: { xs: 12, md: 2 }, children: _jsxs(TextField, { select: true, label: "\u0421\u0442\u0430\u0442\u0443\u0441", fullWidth: true, value: activeVuln.status, onChange: (e) => setActiveVuln((prev) => (prev ? { ...prev, status: e.target.value } : prev)), children: [_jsx(MenuItem, { value: "open", children: "open" }), _jsx(MenuItem, { value: "in_progress", children: "in_progress" }), _jsx(MenuItem, { value: "fixed", children: "fixed" }), _jsx(MenuItem, { value: "wont_fix", children: "wont_fix" }), _jsx(MenuItem, { value: "accepted_risk", children: "accepted_risk" })] }) }), _jsx(Grid, { size: { xs: 12 }, children: _jsx(TextField, { label: "\u041E\u043F\u0438\u0441\u0430\u043D\u0438\u0435", fullWidth: true, multiline: true, minRows: 3, value: activeVuln.description || "", onChange: (e) => setActiveVuln((prev) => (prev ? { ...prev, description: e.target.value || null } : prev)) }) }), _jsx(Grid, { size: { xs: 12, md: 3 }, children: _jsxs(TextField, { select: true, label: "CVSS \u0432\u0435\u0440\u0441\u0438\u044F", fullWidth: true, value: activeVuln.cvss_version || "", onChange: (e) => setActiveVuln((prev) => (prev ? { ...prev, cvss_version: e.target.value || null } : prev)), children: [_jsx(MenuItem, { value: "", children: "-" }), _jsx(MenuItem, { value: "3.1", children: "3.1" }), _jsx(MenuItem, { value: "4.0", children: "4.0" })] }) }), _jsx(Grid, { size: { xs: 12, md: 3 }, children: _jsx(TextField, { label: "CVSS score", type: "number", fullWidth: true, value: activeVuln.cvss_score ?? "", onChange: (e) => {
                                                    const value = e.target.value;
                                                    setActiveVuln((prev) => (prev ? { ...prev, cvss_score: value === "" ? null : Number(value) } : prev));
                                                } }) }), _jsx(Grid, { size: { xs: 12, md: 6 }, children: _jsx(TextField, { label: "CVSS vector", fullWidth: true, value: activeVuln.cvss_vector || "", onChange: (e) => setActiveVuln((prev) => (prev ? { ...prev, cvss_vector: e.target.value || null } : prev)) }) }), _jsx(Grid, { size: { xs: 12 }, children: _jsx(TextField, { label: "CWE ID", fullWidth: true, value: activeVuln.cwe_id || "", onChange: (e) => setActiveVuln((prev) => (prev ? { ...prev, cwe_id: e.target.value || null } : prev)) }) }), _jsx(Grid, { size: { xs: 12 }, children: _jsx(TextField, { label: "\u0428\u0430\u0433\u0438 \u0432\u043E\u0441\u043F\u0440\u043E\u0438\u0437\u0432\u0435\u0434\u0435\u043D\u0438\u044F", fullWidth: true, multiline: true, minRows: 2, value: activeVuln.steps_to_reproduce || "", onChange: (e) => setActiveVuln((prev) => (prev ? { ...prev, steps_to_reproduce: e.target.value || null } : prev)) }) }), _jsx(Grid, { size: { xs: 12 }, children: _jsx(TextField, { label: "\u0412\u043B\u0438\u044F\u043D\u0438\u0435", fullWidth: true, multiline: true, minRows: 2, value: activeVuln.impact || "", onChange: (e) => setActiveVuln((prev) => (prev ? { ...prev, impact: e.target.value || null } : prev)) }) }), _jsx(Grid, { size: { xs: 12 }, children: _jsx(TextField, { label: "\u0420\u0435\u043A\u043E\u043C\u0435\u043D\u0434\u0430\u0446\u0438\u0438", fullWidth: true, multiline: true, minRows: 2, value: activeVuln.recommendations || "", onChange: (e) => setActiveVuln((prev) => (prev ? { ...prev, recommendations: e.target.value || null } : prev)) }) })] }), _jsx(Divider, {}), _jsxs(Stack, { spacing: 1, children: [_jsxs(Typography, { variant: "subtitle1", fontWeight: 700, children: ["\u041F\u0440\u0438\u0432\u044F\u0437\u0430\u043D\u043D\u044B\u0435 \u0430\u043A\u0442\u0438\u0432\u044B (", activeVuln.assets.length, ")"] }), _jsxs(Stack, { direction: { xs: "column", md: "row" }, spacing: 1, children: [_jsxs(TextField, { select: true, label: "\u0422\u0438\u043F \u0430\u043A\u0442\u0438\u0432\u0430", value: linkAssetType, onChange: (event) => {
                                                        setLinkAssetType(event.target.value);
                                                        setLinkAssetId("");
                                                    }, sx: { minWidth: 180 }, children: [_jsx(MenuItem, { value: "host", children: "host" }), _jsx(MenuItem, { value: "port", children: "port" }), _jsx(MenuItem, { value: "service", children: "service" }), _jsx(MenuItem, { value: "endpoint", children: "endpoint" })] }), _jsx(TextField, { select: true, label: "\u0410\u043A\u0442\u0438\u0432", value: linkAssetId, onChange: (event) => setLinkAssetId(event.target.value), fullWidth: true, disabled: linkAssetOptions.length === 0, children: linkAssetOptions.map((option) => (_jsx(MenuItem, { value: option.id, children: option.label }, option.id))) }), _jsx(Button, { variant: "outlined", disabled: !linkAssetId || vulnBusy, onClick: () => void addAssetLinkToActiveVuln(), children: "\u041F\u0440\u0438\u0432\u044F\u0437\u0430\u0442\u044C" })] }), _jsxs(Stack, { direction: "row", spacing: 1, flexWrap: "wrap", children: [activeVuln.assets.map((assetLink) => (_jsx(Chip, { label: resolveAssetLabel(assetLink.asset_type, assetLink.asset_id), onDelete: () => void removeAssetLinkFromActiveVuln(assetLink.id) }, assetLink.id))), activeVuln.assets.length === 0 && _jsx(Typography, { color: "text.secondary", children: "\u0421\u0432\u044F\u0437\u0430\u043D\u043D\u044B\u0435 \u0430\u043A\u0442\u0438\u0432\u044B \u043F\u043E\u043A\u0430 \u043D\u0435 \u0434\u043E\u0431\u0430\u0432\u043B\u0435\u043D\u044B." })] })] }), _jsx(Divider, {}), _jsxs(Stack, { spacing: 1, children: [_jsxs(Typography, { variant: "subtitle1", fontWeight: 700, children: ["\u0424\u0430\u0439\u043B\u044B (", vulnFiles.length, ")"] }), _jsxs(Button, { component: "label", variant: "outlined", startIcon: _jsx(AttachFileIcon, {}), children: ["\u0417\u0430\u0433\u0440\u0443\u0437\u0438\u0442\u044C \u0444\u0430\u0439\u043B", _jsx("input", { hidden: true, type: "file", onChange: (e) => void uploadFileToActiveVuln(e.target.files?.[0] ?? null) })] }), _jsxs(List, { dense: true, disablePadding: true, children: [vulnFiles.map((file) => (_jsx(ListItem, { secondaryAction: _jsxs(Stack, { direction: "row", spacing: 0.5, children: [_jsx(IconButton, { size: "small", component: "a", href: `/api/v1/files/${file.id}/download`, target: "_blank", rel: "noreferrer", children: _jsx(OpenInNewIcon, { fontSize: "small" }) }), _jsx(IconButton, { size: "small", onClick: () => void removeVulnerabilityFile(file.id), children: _jsx(DeleteOutlineIcon, { fontSize: "small" }) })] }), children: _jsx(ListItemText, { primary: file.original_name, secondary: `${file.content_type} • ${Math.round(file.size_bytes / 1024)} KB` }) }, file.id))), vulnFiles.length === 0 && _jsx(Typography, { color: "text.secondary", children: "\u0424\u0430\u0439\u043B\u044B \u043D\u0435 \u0437\u0430\u0433\u0440\u0443\u0436\u0435\u043D\u044B." })] })] }), _jsx(Divider, {}), _jsxs(Stack, { spacing: 1, children: [_jsxs(Typography, { variant: "subtitle1", fontWeight: 700, children: ["\u041A\u043E\u043C\u043C\u0435\u043D\u0442\u0430\u0440\u0438\u0438 (", vulnComments.length, ")"] }), _jsx(TextField, { label: "\u041D\u043E\u0432\u044B\u0439 \u043A\u043E\u043C\u043C\u0435\u043D\u0442\u0430\u0440\u0438\u0439 (\u043F\u043E\u0434\u0434\u0435\u0440\u0436\u043A\u0430 @username)", multiline: true, minRows: 2, value: newComment, onChange: (e) => setNewComment(e.target.value) }), _jsx(Button, { variant: "contained", disabled: !newComment.trim(), onClick: () => void addCommentToActiveVuln(), children: "\u0414\u043E\u0431\u0430\u0432\u0438\u0442\u044C \u043A\u043E\u043C\u043C\u0435\u043D\u0442\u0430\u0440\u0438\u0439" }), _jsxs(List, { dense: true, disablePadding: true, children: [vulnComments.map((comment) => (_jsx(ListItem, { alignItems: "flex-start", secondaryAction: (user?.role === "admin" || user?.id === comment.user_id) ? (_jsxs(Stack, { direction: "row", spacing: 0.5, children: [_jsx(IconButton, { size: "small", onClick: () => openCommentEdit(comment), children: _jsx(EditIcon, { fontSize: "small" }) }), _jsx(IconButton, { size: "small", onClick: () => void removeCommentFromActiveVuln(comment.id), children: _jsx(DeleteOutlineIcon, { fontSize: "small" }) })] })) : null, children: _jsx(ListItemText, { primary: `${comment.username} • ${new Date(comment.created_at).toLocaleString()}`, secondary: comment.content }) }, comment.id))), vulnComments.length === 0 && _jsx(Typography, { color: "text.secondary", children: "\u041A\u043E\u043C\u043C\u0435\u043D\u0442\u0430\u0440\u0438\u0435\u0432 \u043F\u043E\u043A\u0430 \u043D\u0435\u0442." })] })] })] })) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setVulnDetailOpen(false), children: "\u0417\u0430\u043A\u0440\u044B\u0442\u044C" }), _jsx(Button, { color: "error", variant: "outlined", onClick: () => void removeActiveVulnerability(), disabled: !activeVuln || vulnBusy, children: "\u0423\u0434\u0430\u043B\u0438\u0442\u044C" }), _jsx(Button, { variant: "contained", onClick: () => void saveActiveVulnerability(), disabled: !activeVuln || vulnBusy, children: "\u0421\u043E\u0445\u0440\u0430\u043D\u0438\u0442\u044C" })] })] }), _jsxs(Dialog, { open: editCommentOpen, onClose: () => setEditCommentOpen(false), fullWidth: true, maxWidth: "sm", children: [_jsx(DialogTitle, { children: "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u043A\u043E\u043C\u043C\u0435\u043D\u0442\u0430\u0440\u0438\u0439" }), _jsx(DialogContent, { children: _jsx(TextField, { fullWidth: true, multiline: true, minRows: 4, sx: { mt: 1 }, label: "\u041A\u043E\u043C\u043C\u0435\u043D\u0442\u0430\u0440\u0438\u0439", value: editingCommentContent, onChange: (event) => setEditingCommentContent(event.target.value) }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setEditCommentOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", disabled: !editingCommentContent.trim() || vulnBusy, onClick: () => void saveCommentEdit(), children: "\u0421\u043E\u0445\u0440\u0430\u043D\u0438\u0442\u044C" })] })] }), _jsxs(Dialog, { open: exportOpen, onClose: () => setExportOpen(false), fullWidth: true, maxWidth: "xs", children: [_jsx(DialogTitle, { children: "\u042D\u043A\u0441\u043F\u043E\u0440\u0442 \u043E\u0442\u0447\u0451\u0442\u0430" }), _jsx(DialogContent, { children: _jsx(Stack, { spacing: 2, sx: { mt: 1 }, children: _jsxs(TextField, { select: true, label: "\u0424\u043E\u0440\u043C\u0430\u0442", value: exportFormat, onChange: (e) => setExportFormat(e.target.value), children: [_jsx(MenuItem, { value: "md", children: "Markdown (.md)" }), _jsx(MenuItem, { value: "pdf", children: "PDF (.pdf)" }), _jsx(MenuItem, { value: "docx", children: "DOCX (.docx)" })] }) }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setExportOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", startIcon: _jsx(DownloadIcon, {}), disabled: reportLoadingFormat !== null, onClick: () => void downloadReport(exportFormat), children: "\u0421\u043A\u0430\u0447\u0430\u0442\u044C" })] })] }), _jsxs(Dialog, { open: importOpen, onClose: () => setImportOpen(false), fullWidth: true, children: [_jsx(DialogTitle, { children: "\u0418\u043C\u043F\u043E\u0440\u0442 \u0441\u0442\u0440\u0443\u043A\u0442\u0443\u0440\u044B \u043F\u0440\u043E\u0435\u043A\u0442\u0430 (JSON)" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [_jsxs(Button, { component: "label", variant: "outlined", startIcon: _jsx(UploadFileIcon, {}), children: [importFile ? `Файл: ${importFile.name}` : "Выбрать JSON-файл", _jsx("input", { hidden: true, type: "file", accept: "application/json,.json", onChange: (event) => {
                                                const selected = event.target.files?.[0] ?? null;
                                                setImportFile(selected);
                                            } })] }), importSummary && (_jsxs(Box, { sx: { border: "1px solid rgba(126,224,255,0.16)", p: 1.5 }, children: [_jsx(Typography, { variant: "subtitle2", fontWeight: 700, mb: 0.5, children: "\u0420\u0435\u0437\u0443\u043B\u044C\u0442\u0430\u0442 \u043F\u043E\u0441\u043B\u0435\u0434\u043D\u0435\u0433\u043E \u0438\u043C\u043F\u043E\u0440\u0442\u0430" }), _jsxs(Typography, { variant: "body2", color: "text.secondary", children: ["hosts: ", importSummary.hosts_created, ", ports: ", importSummary.ports_created, ", services: ", importSummary.services_created, ", endpoints: ", importSummary.endpoints_created] }), importSummary.errors.length > 0 && (_jsxs(Typography, { variant: "body2", color: "warning.main", mt: 0.5, children: ["\u041E\u0448\u0438\u0431\u043A\u0438: ", importSummary.errors.join("; ")] }))] }))] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setImportOpen(false), children: "\u0417\u0430\u043A\u0440\u044B\u0442\u044C" }), _jsx(Button, { variant: "contained", disabled: !importFile || importing, onClick: () => void submitImport(), children: "\u0418\u043C\u043F\u043E\u0440\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C" })] })] }), _jsxs(Dialog, { open: membersDialogOpen, onClose: () => setMembersDialogOpen(false), fullWidth: true, maxWidth: "md", children: [_jsx(DialogTitle, { children: "\u0423\u0447\u0430\u0441\u0442\u043D\u0438\u043A\u0438 \u043F\u0440\u043E\u0435\u043A\u0442\u0430" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [user?.role === "admin" && (_jsxs(Stack, { direction: { xs: "column", md: "row" }, spacing: 1, children: [_jsx(TextField, { select: true, fullWidth: true, label: "\u0414\u043E\u0431\u0430\u0432\u0438\u0442\u044C \u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u044F", value: selectedMemberUserId, onChange: (event) => setSelectedMemberUserId(event.target.value), children: availableUsers.map((candidate) => (_jsxs(MenuItem, { value: candidate.id, children: [candidate.username, " (", candidate.role, ")"] }, candidate.id))) }), _jsx(Button, { variant: "contained", startIcon: _jsx(PersonAddAlt1Icon, {}), disabled: !selectedMemberUserId || membersBusy, onClick: () => void addMemberToProject(), children: "\u0414\u043E\u0431\u0430\u0432\u0438\u0442\u044C" })] })), _jsxs(List, { dense: true, disablePadding: true, children: [projectMembers.map((member) => (_jsx(ListItem, { secondaryAction: user?.role === "admin" ? (_jsx(IconButton, { size: "small", onClick: () => void removeMemberFromProject(member.user_id), disabled: membersBusy, children: _jsx(DeleteOutlineIcon, { fontSize: "small" }) })) : null, children: _jsx(ListItemText, { primary: `${member.username} (${member.role})`, secondary: member.email }) }, member.user_id))), projectMembers.length === 0 && _jsx(Typography, { color: "text.secondary", children: "\u0423\u0447\u0430\u0441\u0442\u043D\u0438\u043A\u0438 \u043F\u043E\u043A\u0430 \u043D\u0435 \u0434\u043E\u0431\u0430\u0432\u043B\u0435\u043D\u044B." })] })] }) }), _jsx(DialogActions, { children: _jsx(Button, { onClick: () => setMembersDialogOpen(false), children: "\u0417\u0430\u043A\u0440\u044B\u0442\u044C" }) })] })] }));
}
