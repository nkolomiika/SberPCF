import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import AddIcon from "@mui/icons-material/Add";
import AttachFileIcon from "@mui/icons-material/AttachFile";
import DeleteOutlineIcon from "@mui/icons-material/DeleteOutline";
import DownloadIcon from "@mui/icons-material/Download";
import EditIcon from "@mui/icons-material/Edit";
import MoreVertIcon from "@mui/icons-material/MoreVert";
import OpenInNewIcon from "@mui/icons-material/OpenInNew";
import UploadFileIcon from "@mui/icons-material/UploadFile";
import { Alert, Box, Button, Card, CardContent, Chip, Dialog, DialogActions, DialogContent, DialogTitle, Divider, Grid2 as Grid, IconButton, List, ListItem, ListItemText, Menu, MenuItem, Stack, TextField, Typography, } from "@mui/material";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { createHost, createVulnerabilityComment, deleteVulnerability, deleteVulnerabilityComment, deleteVulnerabilityFile, generateProjectReport, getEndpoints, getHostVulnerabilities, getHosts, getPorts, getProjectMembers, getProjects, getVulnerability, importProjectData, listVulnerabilityComments, listVulnerabilityFiles, updateHost, updateVulnerability, uploadVulnerabilityFile, } from "../api";
import { ProjectTreeNav } from "../components/ProjectTreeNav";
import { useAuthStore } from "../store";
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
    const [projectMembers, setProjectMembers] = useState([]);
    const [hostStatsById, setHostStatsById] = useState({});
    const [importOpen, setImportOpen] = useState(false);
    const [importFile, setImportFile] = useState(null);
    const [importing, setImporting] = useState(false);
    const [importSummary, setImportSummary] = useState(null);
    const [reportLoadingFormat, setReportLoadingFormat] = useState(null);
    const [actionsAnchorEl, setActionsAnchorEl] = useState(null);
    const [exportOpen, setExportOpen] = useState(false);
    const [exportFormat, setExportFormat] = useState("pdf");
    const [hostOpen, setHostOpen] = useState(false);
    const [hostIp, setHostIp] = useState("");
    const [hostName, setHostName] = useState("");
    const [hostStatus, setHostStatus] = useState("unknown");
    const [hostNotes, setHostNotes] = useState("");
    const [editHostOpen, setEditHostOpen] = useState(false);
    const [vulnDetailOpen, setVulnDetailOpen] = useState(false);
    const [activeVuln, setActiveVuln] = useState(null);
    const [vulnFiles, setVulnFiles] = useState([]);
    const [vulnComments, setVulnComments] = useState([]);
    const [newComment, setNewComment] = useState("");
    const [vulnBusy, setVulnBusy] = useState(false);
    const loadProjectData = useCallback(async () => {
        if (!projectId) {
            return;
        }
        try {
            const [hostsResp, projectsResp, membersResp] = await Promise.all([
                getHosts(projectId),
                getProjects(1, 100),
                getProjectMembers(projectId),
            ]);
            setHosts(hostsResp.items);
            setProjectMembers(membersResp);
            const currentProject = projectsResp.items.find((project) => project.id === projectId);
            setProjectName(currentProject?.name ?? projectId);
            setProjectDescription(currentProject?.description ?? "");
            setSelectedHostId((previousHostId) => {
                if (previousHostId && hostsResp.items.some((host) => host.id === previousHostId)) {
                    return previousHostId;
                }
                return hostsResp.items[0]?.id ?? null;
            });
        }
        catch {
            setError("Не удалось загрузить данные проекта");
        }
    }, [projectId]);
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
    const openEditHost = () => {
        if (!selectedHost) {
            setError("Сначала выберите хост в структуре проекта");
            return;
        }
        setHostIp(selectedHost.ip_address || "");
        setHostName(selectedHost.hostname || "");
        setHostStatus(selectedHost.status);
        setHostNotes(selectedHost.notes || "");
        setEditHostOpen(true);
    };
    const submitHostEdit = async () => {
        if (!projectId || !selectedHost) {
            return;
        }
        await updateHost(projectId, selectedHost.id, {
            ip_address: hostIp || undefined,
            hostname: hostName || undefined,
            status: hostStatus,
            notes: hostNotes || undefined,
        });
        setEditHostOpen(false);
        await loadProjectData();
        await loadHostAssets();
    };
    const loadVulnerabilityDetails = async (vulnerabilityId) => {
        if (!projectId) {
            return;
        }
        setVulnBusy(true);
        setError(null);
        try {
            const [vulnDetail, files, commentsPage] = await Promise.all([
                getVulnerability(projectId, vulnerabilityId),
                listVulnerabilityFiles(projectId, vulnerabilityId),
                listVulnerabilityComments(projectId, vulnerabilityId),
            ]);
            setActiveVuln(vulnDetail);
            setVulnFiles(files);
            setVulnComments(commentsPage.items);
            setVulnDetailOpen(true);
        }
        catch {
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
    return (_jsxs(Stack, { spacing: 2.5, children: [error && _jsx(Alert, { severity: "error", children: error }), _jsxs(Stack, { direction: "row", justifyContent: "space-between", alignItems: "center", children: [_jsx(Box, { children: _jsx(Typography, { variant: "h4", fontWeight: 700, children: projectName ? `Проект: ${projectName}` : "Проект" }) }), _jsx(IconButton, { onClick: openActionsMenu, sx: { border: "1px solid rgba(126,224,255,0.2)", borderRadius: 2 }, children: _jsx(MoreVertIcon, {}) })] }), _jsxs(Menu, { anchorEl: actionsAnchorEl, open: actionsMenuOpen, onClose: closeActionsMenu, anchorOrigin: { vertical: "bottom", horizontal: "right" }, transformOrigin: { vertical: "top", horizontal: "right" }, children: [_jsxs(MenuItem, { onClick: () => {
                            closeActionsMenu();
                            setHostOpen(true);
                        }, children: [_jsx(AddIcon, { fontSize: "small", sx: { mr: 1 } }), "\u0414\u043E\u0431\u0430\u0432\u0438\u0442\u044C \u0445\u043E\u0441\u0442"] }), _jsxs(MenuItem, { disabled: !selectedHost, onClick: () => {
                            closeActionsMenu();
                            openEditHost();
                        }, children: [_jsx(EditIcon, { fontSize: "small", sx: { mr: 1 } }), "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u0445\u043E\u0441\u0442"] }), _jsxs(MenuItem, { onClick: () => {
                            closeActionsMenu();
                            setImportOpen(true);
                        }, children: [_jsx(UploadFileIcon, { fontSize: "small", sx: { mr: 1 } }), "\u0418\u043C\u043F\u043E\u0440\u0442 JSON"] }), _jsxs(MenuItem, { onClick: () => {
                            closeActionsMenu();
                            setExportOpen(true);
                        }, children: [_jsx(DownloadIcon, { fontSize: "small", sx: { mr: 1 } }), "\u042D\u043A\u0441\u043F\u043E\u0440\u0442"] })] }), _jsxs(Stack, { direction: { xs: "column", md: "row" }, spacing: 2, children: [_jsx(ProjectTreeNav, { hosts: hosts, selectedHostId: selectedHostId, selectedSection: selectedSection, isCollapsed: isSidebarCollapsed, portsCount: ports.length, endpointsCount: endpoints.length, vulnerabilitiesCount: vulnerabilities.length, hostStatsById: hostStatsById, autoExpandSelectedHost: false, onToggleCollapsed: () => setSidebarCollapsed((v) => !v), onSelectSection: setSelectedSection, onSelectProjectOverview: () => setSelectedSection("overview"), onSelectHost: setSelectedHostId, onOpenHost: (hostId) => navigate(`/projects/${projectId}/hosts/${hostId}`) }), _jsxs(Stack, { flex: 1, spacing: 2, children: [selectedSection !== "overview" && (_jsx(Card, { sx: { border: "1px solid rgba(126,224,255,0.18)", borderRadius: 0 }, children: _jsxs(CardContent, { children: [_jsxs(Typography, { variant: "h6", fontWeight: 700, children: [selectedSection === "hosts" && `Хост: ${hostLabel}`, selectedSection === "ports" && `Порты хоста: ${hostLabel}`, selectedSection === "endpoints" && `Эндпоинты хоста: ${hostLabel}`, selectedSection === "vulns" && `Уязвимости хоста: ${hostLabel}`] }), _jsx(Typography, { variant: "body2", color: "text.secondary", children: "\u0421\u043B\u0435\u0432\u0430 \u2014 \u0434\u0440\u0435\u0432\u043E\u0432\u0438\u0434\u043D\u0430\u044F \u043D\u0430\u0432\u0438\u0433\u0430\u0446\u0438\u044F \u043F\u043E \u043F\u0440\u043E\u0435\u043A\u0442\u0443, \u043A\u0430\u043A \u0432 wiki-\u0441\u0442\u0440\u0430\u043D\u0438\u0446\u0430\u0445." })] }) })), selectedSection === "overview" && (_jsxs(Stack, { spacing: 2, children: [_jsx(Card, { sx: { border: "1px solid rgba(126,224,255,0.16)", borderRadius: 0 }, children: _jsxs(CardContent, { children: [_jsx(Typography, { variant: "h6", fontWeight: 700, mb: 1, children: "\u041E\u043F\u0438\u0441\u0430\u043D\u0438\u0435 \u043F\u0440\u043E\u0435\u043A\u0442\u0430" }), _jsx(Typography, { color: "text.secondary", children: projectDescription || "Описание проекта не заполнено" })] }) }), _jsxs(Grid, { container: true, spacing: 2, children: [_jsx(Grid, { size: { xs: 12, md: 6 }, children: _jsx(Card, { sx: { border: "1px solid rgba(126,224,255,0.16)", borderRadius: 0, height: "100%" }, children: _jsxs(CardContent, { children: [_jsx(Typography, { color: "text.secondary", children: "\u0425\u043E\u0441\u0442\u043E\u0432" }), _jsx(Typography, { variant: "h4", fontWeight: 700, children: hosts.length })] }) }) }), _jsx(Grid, { size: { xs: 12, md: 6 }, children: _jsx(Card, { sx: { border: "1px solid rgba(126,224,255,0.16)", borderRadius: 0, height: "100%" }, children: _jsxs(CardContent, { sx: { height: "100%" }, children: [_jsx(Typography, { color: "text.secondary", mb: 1, children: "\u0423\u0447\u0430\u0441\u0442\u043D\u0438\u043A\u0438 \u043F\u0440\u043E\u0435\u043A\u0442\u0430" }), _jsx(Stack, { spacing: 0.5, children: projectMembers.length > 0 ? (projectMembers.map((member) => (_jsxs(Typography, { variant: "body2", children: [member.username, " (", member.role, ")"] }, member.user_id)))) : (_jsx(Typography, { color: "text.secondary", children: "\u0423\u0447\u0430\u0441\u0442\u043D\u0438\u043A\u0438 \u043D\u0435 \u0434\u043E\u0431\u0430\u0432\u043B\u0435\u043D\u044B" })) })] }) }) })] })] })), selectedSection === "hosts" && (_jsx(Card, { sx: { border: "1px solid rgba(126,224,255,0.16)", borderRadius: 0 }, children: _jsx(CardContent, { children: _jsx(Stack, { spacing: 1.2, children: hosts.map((host) => (_jsxs(Box, { sx: { border: "1px solid rgba(126,224,255,0.16)", p: 1.5, borderRadius: 0, cursor: "pointer" }, onClick: () => navigate(`/projects/${projectId}/hosts/${host.id}`), children: [_jsx(Typography, { children: host.hostname || host.ip_address || "unknown-host" }), _jsxs(Typography, { variant: "body2", color: "text.secondary", children: ["\u0421\u0442\u0430\u0442\u0443\u0441: ", host.status] })] }, host.id))) }) }) })), selectedSection === "ports" && (_jsx(Card, { sx: { border: "1px solid rgba(126,224,255,0.16)", borderRadius: 0 }, children: _jsx(CardContent, { children: _jsxs(Stack, { spacing: 1.2, children: [ports.map((port) => (_jsx(Box, { sx: { border: "1px solid rgba(126,224,255,0.16)", p: 1.5, borderRadius: 0 }, children: _jsxs(Stack, { direction: "row", spacing: 1, alignItems: "center", children: [_jsxs(Typography, { fontWeight: 600, children: [port.port_number, "/", port.protocol] }), _jsx(Chip, { size: "small", label: port.state })] }) }, port.id))), ports.length === 0 && (_jsx(Typography, { color: "text.secondary", children: "\u041F\u043E\u0440\u0442\u044B \u043D\u0435 \u0434\u043E\u0431\u0430\u0432\u043B\u0435\u043D\u044B. \u0412\u044B\u0431\u0435\u0440\u0438\u0442\u0435 \u0445\u043E\u0441\u0442 \u0438 \u0434\u043E\u0431\u0430\u0432\u044C\u0442\u0435 \u043F\u0435\u0440\u0432\u044B\u0439 \u043F\u043E\u0440\u0442." }))] }) }) })), selectedSection === "endpoints" && (_jsx(Card, { sx: { border: "1px solid rgba(126,224,255,0.16)", borderRadius: 0 }, children: _jsx(CardContent, { children: _jsxs(Stack, { spacing: 1.2, children: [endpoints.map((endpoint) => (_jsxs(Box, { sx: { border: "1px solid rgba(126,224,255,0.16)", p: 1.5, borderRadius: 0 }, children: [_jsxs(Stack, { direction: "row", spacing: 1, alignItems: "center", children: [_jsx(Chip, { size: "small", label: endpoint.method || "ANY" }), _jsx(Typography, { fontWeight: 600, children: endpoint.path })] }), _jsx(Typography, { variant: "body2", color: "text.secondary", mt: 0.8, children: endpoint.description || "Описание не указано" })] }, endpoint.id))), endpoints.length === 0 && (_jsx(Typography, { color: "text.secondary", children: "\u042D\u043D\u0434\u043F\u043E\u0438\u043D\u0442\u044B \u043D\u0435 \u0434\u043E\u0431\u0430\u0432\u043B\u0435\u043D\u044B. \u0412\u044B\u0431\u0435\u0440\u0438\u0442\u0435 \u0445\u043E\u0441\u0442 \u0438 \u0434\u043E\u0431\u0430\u0432\u044C\u0442\u0435 \u043F\u0435\u0440\u0432\u044B\u0439 \u044D\u043D\u0434\u043F\u043E\u0438\u043D\u0442." }))] }) }) })), selectedSection === "vulns" && (_jsx(Card, { sx: { border: "1px solid rgba(126,224,255,0.16)", borderRadius: 0 }, children: _jsxs(CardContent, { children: [_jsx(Stack, { direction: "row", spacing: 1, mb: 2, flexWrap: "wrap", children: Object.entries(severityStats).map(([severity, value]) => (_jsx(Chip, { label: `${severity}: ${value}` }, severity))) }), _jsxs(Stack, { spacing: 1.2, children: [vulnerabilities.map((item) => (_jsxs(Box, { sx: { border: "1px solid rgba(126,224,255,0.16)", p: 1.5, borderRadius: 0 }, children: [_jsxs(Stack, { direction: "row", justifyContent: "space-between", alignItems: "center", children: [_jsx(Typography, { children: item.title }), _jsx(Button, { size: "small", variant: "outlined", onClick: () => void loadVulnerabilityDetails(item.id), disabled: vulnBusy, children: "\u041E\u0442\u043A\u0440\u044B\u0442\u044C" })] }), _jsxs(Stack, { direction: "row", spacing: 1, mt: 1, flexWrap: "wrap", children: [_jsx(Chip, { label: item.severity, size: "small", sx: severityChipSx[item.severity] }), _jsx(Chip, { label: item.status, size: "small", sx: vulnerabilityStatusChipSx[item.status] })] })] }, item.id))), vulnerabilities.length === 0 && (_jsx(Typography, { color: "text.secondary", children: "\u0414\u043B\u044F \u0432\u044B\u0431\u0440\u0430\u043D\u043D\u043E\u0433\u043E \u0445\u043E\u0441\u0442\u0430 \u0443\u044F\u0437\u0432\u0438\u043C\u043E\u0441\u0442\u0438 \u043D\u0435 \u043F\u0440\u0438\u0432\u044F\u0437\u0430\u043D\u044B." }))] })] }) }))] })] }), _jsxs(Dialog, { open: hostOpen, onClose: () => setHostOpen(false), fullWidth: true, children: [_jsx(DialogTitle, { children: "\u0414\u043E\u0431\u0430\u0432\u0438\u0442\u044C \u0445\u043E\u0441\u0442" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [_jsx(TextField, { label: "IP-\u0430\u0434\u0440\u0435\u0441", value: hostIp, onChange: (e) => setHostIp(e.target.value) }), _jsx(TextField, { label: "Hostname", value: hostName, onChange: (e) => setHostName(e.target.value) }), _jsxs(TextField, { select: true, label: "\u0421\u0442\u0430\u0442\u0443\u0441", value: hostStatus, onChange: (e) => setHostStatus(e.target.value), children: [_jsx(MenuItem, { value: "up", children: "up" }), _jsx(MenuItem, { value: "down", children: "down" }), _jsx(MenuItem, { value: "unknown", children: "unknown" })] }), _jsx(TextField, { label: "\u041E\u043F\u0438\u0441\u0430\u043D\u0438\u0435", multiline: true, minRows: 3, value: hostNotes, onChange: (e) => setHostNotes(e.target.value) })] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setHostOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", disabled: !hostIp && !hostName, onClick: () => void submitHost(), children: "\u0421\u043E\u0445\u0440\u0430\u043D\u0438\u0442\u044C" })] })] }), _jsxs(Dialog, { open: editHostOpen, onClose: () => setEditHostOpen(false), fullWidth: true, children: [_jsx(DialogTitle, { children: "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u0445\u043E\u0441\u0442" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [_jsx(TextField, { label: "IP-\u0430\u0434\u0440\u0435\u0441", value: hostIp, onChange: (e) => setHostIp(e.target.value) }), _jsx(TextField, { label: "Hostname", value: hostName, onChange: (e) => setHostName(e.target.value) }), _jsxs(TextField, { select: true, label: "\u0421\u0442\u0430\u0442\u0443\u0441", value: hostStatus, onChange: (e) => setHostStatus(e.target.value), children: [_jsx(MenuItem, { value: "up", children: "up" }), _jsx(MenuItem, { value: "down", children: "down" }), _jsx(MenuItem, { value: "unknown", children: "unknown" })] }), _jsx(TextField, { label: "\u041E\u043F\u0438\u0441\u0430\u043D\u0438\u0435", multiline: true, minRows: 3, value: hostNotes, onChange: (e) => setHostNotes(e.target.value) })] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setEditHostOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", disabled: !hostIp && !hostName, onClick: () => void submitHostEdit(), children: "\u0421\u043E\u0445\u0440\u0430\u043D\u0438\u0442\u044C" })] })] }), _jsxs(Dialog, { open: vulnDetailOpen, onClose: () => setVulnDetailOpen(false), fullWidth: true, maxWidth: "lg", children: [_jsx(DialogTitle, { children: "\u041A\u0430\u0440\u0442\u043E\u0447\u043A\u0430 \u0443\u044F\u0437\u0432\u0438\u043C\u043E\u0441\u0442\u0438" }), _jsx(DialogContent, { children: !activeVuln ? (_jsx(Typography, { color: "text.secondary", children: "\u0423\u044F\u0437\u0432\u0438\u043C\u043E\u0441\u0442\u044C \u043D\u0435 \u0432\u044B\u0431\u0440\u0430\u043D\u0430." })) : (_jsxs(Stack, { spacing: 2, sx: { mt: 0.5 }, children: [_jsxs(Grid, { container: true, spacing: 2, children: [_jsx(Grid, { size: { xs: 12, md: 8 }, children: _jsx(TextField, { label: "\u041D\u0430\u0437\u0432\u0430\u043D\u0438\u0435", fullWidth: true, value: activeVuln.title, onChange: (e) => setActiveVuln((prev) => (prev ? { ...prev, title: e.target.value } : prev)) }) }), _jsx(Grid, { size: { xs: 12, md: 2 }, children: _jsxs(TextField, { select: true, label: "\u041A\u0440\u0438\u0442\u0438\u0447\u043D\u043E\u0441\u0442\u044C", fullWidth: true, value: activeVuln.severity, onChange: (e) => setActiveVuln((prev) => (prev ? { ...prev, severity: e.target.value } : prev)), children: [_jsx(MenuItem, { value: "critical", children: "critical" }), _jsx(MenuItem, { value: "high", children: "high" }), _jsx(MenuItem, { value: "medium", children: "medium" }), _jsx(MenuItem, { value: "low", children: "low" }), _jsx(MenuItem, { value: "info", children: "info" })] }) }), _jsx(Grid, { size: { xs: 12, md: 2 }, children: _jsxs(TextField, { select: true, label: "\u0421\u0442\u0430\u0442\u0443\u0441", fullWidth: true, value: activeVuln.status, onChange: (e) => setActiveVuln((prev) => (prev ? { ...prev, status: e.target.value } : prev)), children: [_jsx(MenuItem, { value: "open", children: "open" }), _jsx(MenuItem, { value: "in_progress", children: "in_progress" }), _jsx(MenuItem, { value: "fixed", children: "fixed" }), _jsx(MenuItem, { value: "wont_fix", children: "wont_fix" }), _jsx(MenuItem, { value: "accepted_risk", children: "accepted_risk" })] }) }), _jsx(Grid, { size: { xs: 12 }, children: _jsx(TextField, { label: "\u041E\u043F\u0438\u0441\u0430\u043D\u0438\u0435", fullWidth: true, multiline: true, minRows: 3, value: activeVuln.description || "", onChange: (e) => setActiveVuln((prev) => (prev ? { ...prev, description: e.target.value || null } : prev)) }) }), _jsx(Grid, { size: { xs: 12, md: 3 }, children: _jsxs(TextField, { select: true, label: "CVSS \u0432\u0435\u0440\u0441\u0438\u044F", fullWidth: true, value: activeVuln.cvss_version || "", onChange: (e) => setActiveVuln((prev) => (prev ? { ...prev, cvss_version: e.target.value || null } : prev)), children: [_jsx(MenuItem, { value: "", children: "-" }), _jsx(MenuItem, { value: "3.1", children: "3.1" }), _jsx(MenuItem, { value: "4.0", children: "4.0" })] }) }), _jsx(Grid, { size: { xs: 12, md: 3 }, children: _jsx(TextField, { label: "CVSS score", type: "number", fullWidth: true, value: activeVuln.cvss_score ?? "", onChange: (e) => {
                                                    const value = e.target.value;
                                                    setActiveVuln((prev) => (prev ? { ...prev, cvss_score: value === "" ? null : Number(value) } : prev));
                                                } }) }), _jsx(Grid, { size: { xs: 12, md: 6 }, children: _jsx(TextField, { label: "CVSS vector", fullWidth: true, value: activeVuln.cvss_vector || "", onChange: (e) => setActiveVuln((prev) => (prev ? { ...prev, cvss_vector: e.target.value || null } : prev)) }) }), _jsx(Grid, { size: { xs: 12 }, children: _jsx(TextField, { label: "CWE ID", fullWidth: true, value: activeVuln.cwe_id || "", onChange: (e) => setActiveVuln((prev) => (prev ? { ...prev, cwe_id: e.target.value || null } : prev)) }) }), _jsx(Grid, { size: { xs: 12 }, children: _jsx(TextField, { label: "\u0428\u0430\u0433\u0438 \u0432\u043E\u0441\u043F\u0440\u043E\u0438\u0437\u0432\u0435\u0434\u0435\u043D\u0438\u044F", fullWidth: true, multiline: true, minRows: 2, value: activeVuln.steps_to_reproduce || "", onChange: (e) => setActiveVuln((prev) => (prev ? { ...prev, steps_to_reproduce: e.target.value || null } : prev)) }) }), _jsx(Grid, { size: { xs: 12 }, children: _jsx(TextField, { label: "\u0412\u043B\u0438\u044F\u043D\u0438\u0435", fullWidth: true, multiline: true, minRows: 2, value: activeVuln.impact || "", onChange: (e) => setActiveVuln((prev) => (prev ? { ...prev, impact: e.target.value || null } : prev)) }) }), _jsx(Grid, { size: { xs: 12 }, children: _jsx(TextField, { label: "\u0420\u0435\u043A\u043E\u043C\u0435\u043D\u0434\u0430\u0446\u0438\u0438", fullWidth: true, multiline: true, minRows: 2, value: activeVuln.recommendations || "", onChange: (e) => setActiveVuln((prev) => (prev ? { ...prev, recommendations: e.target.value || null } : prev)) }) })] }), _jsx(Divider, {}), _jsxs(Stack, { spacing: 1, children: [_jsxs(Typography, { variant: "subtitle1", fontWeight: 700, children: ["\u0424\u0430\u0439\u043B\u044B (", vulnFiles.length, ")"] }), _jsxs(Button, { component: "label", variant: "outlined", startIcon: _jsx(AttachFileIcon, {}), children: ["\u0417\u0430\u0433\u0440\u0443\u0437\u0438\u0442\u044C \u0444\u0430\u0439\u043B", _jsx("input", { hidden: true, type: "file", onChange: (e) => void uploadFileToActiveVuln(e.target.files?.[0] ?? null) })] }), _jsxs(List, { dense: true, disablePadding: true, children: [vulnFiles.map((file) => (_jsx(ListItem, { secondaryAction: _jsxs(Stack, { direction: "row", spacing: 0.5, children: [_jsx(IconButton, { size: "small", component: "a", href: `/api/v1/files/${file.id}/download`, target: "_blank", rel: "noreferrer", children: _jsx(OpenInNewIcon, { fontSize: "small" }) }), _jsx(IconButton, { size: "small", onClick: () => void removeVulnerabilityFile(file.id), children: _jsx(DeleteOutlineIcon, { fontSize: "small" }) })] }), children: _jsx(ListItemText, { primary: file.original_name, secondary: `${file.content_type} • ${Math.round(file.size_bytes / 1024)} KB` }) }, file.id))), vulnFiles.length === 0 && _jsx(Typography, { color: "text.secondary", children: "\u0424\u0430\u0439\u043B\u044B \u043D\u0435 \u0437\u0430\u0433\u0440\u0443\u0436\u0435\u043D\u044B." })] })] }), _jsx(Divider, {}), _jsxs(Stack, { spacing: 1, children: [_jsxs(Typography, { variant: "subtitle1", fontWeight: 700, children: ["\u041A\u043E\u043C\u043C\u0435\u043D\u0442\u0430\u0440\u0438\u0438 (", vulnComments.length, ")"] }), _jsx(TextField, { label: "\u041D\u043E\u0432\u044B\u0439 \u043A\u043E\u043C\u043C\u0435\u043D\u0442\u0430\u0440\u0438\u0439 (\u043F\u043E\u0434\u0434\u0435\u0440\u0436\u043A\u0430 @username)", multiline: true, minRows: 2, value: newComment, onChange: (e) => setNewComment(e.target.value) }), _jsx(Button, { variant: "contained", disabled: !newComment.trim(), onClick: () => void addCommentToActiveVuln(), children: "\u0414\u043E\u0431\u0430\u0432\u0438\u0442\u044C \u043A\u043E\u043C\u043C\u0435\u043D\u0442\u0430\u0440\u0438\u0439" }), _jsxs(List, { dense: true, disablePadding: true, children: [vulnComments.map((comment) => (_jsx(ListItem, { alignItems: "flex-start", secondaryAction: (user?.role === "admin" || user?.id === comment.user_id) && (_jsx(IconButton, { size: "small", onClick: () => void removeCommentFromActiveVuln(comment.id), children: _jsx(DeleteOutlineIcon, { fontSize: "small" }) })), children: _jsx(ListItemText, { primary: `${comment.username} • ${new Date(comment.created_at).toLocaleString()}`, secondary: comment.content }) }, comment.id))), vulnComments.length === 0 && _jsx(Typography, { color: "text.secondary", children: "\u041A\u043E\u043C\u043C\u0435\u043D\u0442\u0430\u0440\u0438\u0435\u0432 \u043F\u043E\u043A\u0430 \u043D\u0435\u0442." })] })] })] })) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setVulnDetailOpen(false), children: "\u0417\u0430\u043A\u0440\u044B\u0442\u044C" }), _jsx(Button, { color: "error", variant: "outlined", onClick: () => void removeActiveVulnerability(), disabled: !activeVuln || vulnBusy, children: "\u0423\u0434\u0430\u043B\u0438\u0442\u044C" }), _jsx(Button, { variant: "contained", onClick: () => void saveActiveVulnerability(), disabled: !activeVuln || vulnBusy, children: "\u0421\u043E\u0445\u0440\u0430\u043D\u0438\u0442\u044C" })] })] }), _jsxs(Dialog, { open: exportOpen, onClose: () => setExportOpen(false), fullWidth: true, maxWidth: "xs", children: [_jsx(DialogTitle, { children: "\u042D\u043A\u0441\u043F\u043E\u0440\u0442 \u043E\u0442\u0447\u0451\u0442\u0430" }), _jsx(DialogContent, { children: _jsx(Stack, { spacing: 2, sx: { mt: 1 }, children: _jsxs(TextField, { select: true, label: "\u0424\u043E\u0440\u043C\u0430\u0442", value: exportFormat, onChange: (e) => setExportFormat(e.target.value), children: [_jsx(MenuItem, { value: "md", children: "Markdown (.md)" }), _jsx(MenuItem, { value: "pdf", children: "PDF (.pdf)" }), _jsx(MenuItem, { value: "docx", children: "DOCX (.docx)" })] }) }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setExportOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", startIcon: _jsx(DownloadIcon, {}), disabled: reportLoadingFormat !== null, onClick: () => void downloadReport(exportFormat), children: "\u0421\u043A\u0430\u0447\u0430\u0442\u044C" })] })] }), _jsxs(Dialog, { open: importOpen, onClose: () => setImportOpen(false), fullWidth: true, children: [_jsx(DialogTitle, { children: "\u0418\u043C\u043F\u043E\u0440\u0442 \u0441\u0442\u0440\u0443\u043A\u0442\u0443\u0440\u044B \u043F\u0440\u043E\u0435\u043A\u0442\u0430 (JSON)" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [_jsxs(Button, { component: "label", variant: "outlined", startIcon: _jsx(UploadFileIcon, {}), children: [importFile ? `Файл: ${importFile.name}` : "Выбрать JSON-файл", _jsx("input", { hidden: true, type: "file", accept: "application/json,.json", onChange: (event) => {
                                                const selected = event.target.files?.[0] ?? null;
                                                setImportFile(selected);
                                            } })] }), importSummary && (_jsxs(Box, { sx: { border: "1px solid rgba(126,224,255,0.16)", p: 1.5 }, children: [_jsx(Typography, { variant: "subtitle2", fontWeight: 700, mb: 0.5, children: "\u0420\u0435\u0437\u0443\u043B\u044C\u0442\u0430\u0442 \u043F\u043E\u0441\u043B\u0435\u0434\u043D\u0435\u0433\u043E \u0438\u043C\u043F\u043E\u0440\u0442\u0430" }), _jsxs(Typography, { variant: "body2", color: "text.secondary", children: ["hosts: ", importSummary.hosts_created, ", ports: ", importSummary.ports_created, ", services: ", importSummary.services_created, ", endpoints: ", importSummary.endpoints_created] }), importSummary.errors.length > 0 && (_jsxs(Typography, { variant: "body2", color: "warning.main", mt: 0.5, children: ["\u041E\u0448\u0438\u0431\u043A\u0438: ", importSummary.errors.join("; ")] }))] }))] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setImportOpen(false), children: "\u0417\u0430\u043A\u0440\u044B\u0442\u044C" }), _jsx(Button, { variant: "contained", disabled: !importFile || importing, onClick: () => void submitImport(), children: "\u0418\u043C\u043F\u043E\u0440\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C" })] })] })] }));
}
