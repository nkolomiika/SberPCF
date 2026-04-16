import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import DeleteIcon from "@mui/icons-material/Delete";
import EditIcon from "@mui/icons-material/Edit";
import AddIcon from "@mui/icons-material/Add";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import MoreVertIcon from "@mui/icons-material/MoreVert";
import UploadFileIcon from "@mui/icons-material/UploadFile";
import { Alert, Box, Button, Card, CardContent, Chip, Collapse, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, Grid2 as Grid, IconButton, Menu, MenuItem, Stack, TextField, Tooltip, Typography, } from "@mui/material";
import { useCallback, useEffect, useState } from "react";
import { load as parseYaml } from "js-yaml";
import ReactMarkdown from "react-markdown";
import { useNavigate, useParams } from "react-router-dom";
import { addVulnerabilityAsset, createEndpoint, createPort, createService, createVulnerability, deleteEndpoint, deleteHost, deletePort, deleteService, deleteVulnerability, getServices, getHost, getHosts, getHostVulnerabilities, updateEndpoint, updateHost, updatePort, updateService, updateVulnerability, } from "../api";
import { ProjectTreeNav } from "../components/ProjectTreeNav";
export function HostDetailPage() {
    const { projectId, hostId } = useParams();
    const navigate = useNavigate();
    const [host, setHost] = useState(null);
    const [hosts, setHosts] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [infoMessage, setInfoMessage] = useState(null);
    const [vulnerabilities, setVulnerabilities] = useState([]);
    const [selectedSection, setSelectedSection] = useState("overview");
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
    const [editingEndpointDescription, setEditingEndpointDescription] = useState("");
    const [editingEndpointRequestRaw, setEditingEndpointRequestRaw] = useState("");
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
    const [creatingEndpointDescription, setCreatingEndpointDescription] = useState("");
    const [creatingEndpointRequestRaw, setCreatingEndpointRequestRaw] = useState("");
    const [swaggerImporting, setSwaggerImporting] = useState(false);
    const [isCreateVulnerabilityOpen, setCreateVulnerabilityOpen] = useState(false);
    const [creatingVulnerabilityTitle, setCreatingVulnerabilityTitle] = useState("");
    const [creatingVulnerabilityDescription, setCreatingVulnerabilityDescription] = useState("");
    const [creatingVulnerabilitySeverity, setCreatingVulnerabilitySeverity] = useState("medium");
    const [creatingVulnerabilityStatus, setCreatingVulnerabilityStatus] = useState("open");
    const [hostActionsAnchorEl, setHostActionsAnchorEl] = useState(null);
    const [isEditHostOpen, setEditHostOpen] = useState(false);
    const [editingHostIp, setEditingHostIp] = useState("");
    const [editingHostName, setEditingHostName] = useState("");
    const [editingHostStatus, setEditingHostStatus] = useState("unknown");
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
        catch {
            setError("Не удалось загрузить страницу хоста.");
        }
        finally {
            setLoading(false);
        }
    }, [hostId, projectId]);
    useEffect(() => {
        void loadHost();
    }, [loadHost]);
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
        setEditingHostStatus(host.status);
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
                status: editingHostStatus,
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
        catch {
            setError("Не удалось обновить информацию о хосте.");
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
    const buildEndpointRawRequest = (endpoint) => {
        const method = endpoint.method ?? "GET";
        const hostHeader = host?.hostname || host?.ip_address || "example.local";
        return `${method} ${endpoint.path} HTTP/1.1\nHost: ${hostHeader}\n\n`;
    };
    const buildEndpointCurl = (endpoint) => {
        const method = endpoint.method ?? "GET";
        const hostTarget = host?.hostname || host?.ip_address || "example.local";
        return `curl -X ${method} "http://${hostTarget}${endpoint.path}"`;
    };
    const copyEndpointRequest = async (format) => {
        if (!activeEndpoint) {
            return;
        }
        const text = format === "curl" ? buildEndpointCurl(activeEndpoint) : buildEndpointRawRequest(activeEndpoint);
        await navigator.clipboard.writeText(text);
        closeEndpointActions();
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
    const parseRawHttpRequest = (rawRequest) => {
        const firstLine = rawRequest.replace("\r", "").split("\n").map((line) => line.trim()).find(Boolean);
        if (!firstLine) {
            return null;
        }
        const requestLineMatch = firstLine.match(/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP\/\d(?:\.\d)?$/i);
        if (!requestLineMatch) {
            return null;
        }
        return {
            method: requestLineMatch[1].toUpperCase(),
            path: requestLineMatch[2],
        };
    };
    const applyParsedRequestToCreateEndpoint = (rawRequest) => {
        setCreatingEndpointRequestRaw(rawRequest);
        const parsed = parseRawHttpRequest(rawRequest);
        if (!parsed) {
            return;
        }
        setCreatingEndpointMethod(parsed.method);
        setCreatingEndpointPath(parsed.path);
    };
    const applyParsedRequestToEditEndpoint = (rawRequest) => {
        setEditingEndpointRequestRaw(rawRequest);
        const parsed = parseRawHttpRequest(rawRequest);
        if (!parsed) {
            return;
        }
        setEditingEndpointMethod(parsed.method);
        setEditingEndpointPath(parsed.path);
    };
    const openEndpointEdit = (endpoint) => {
        setEditingEndpointId(endpoint.id);
        setEditingEndpointPath(endpoint.path);
        setEditingEndpointMethod(endpoint.method || "GET");
        setEditingEndpointDescription(endpoint.description || "");
        setEditingEndpointRequestRaw("");
        setEditEndpointOpen(true);
    };
    const saveEndpointEdit = async () => {
        if (!projectId || !hostId || !editingEndpointId) {
            return;
        }
        await updateEndpoint(projectId, hostId, editingEndpointId, {
            path: editingEndpointPath,
            method: editingEndpointMethod,
            description: editingEndpointDescription || undefined,
            request_raw: editingEndpointRequestRaw.trim() || undefined,
        });
        setEditEndpointOpen(false);
        setEditingEndpointRequestRaw("");
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
        await createEndpoint(projectId, hostId, {
            path: creatingEndpointPath.trim() || undefined,
            method: creatingEndpointMethod,
            description: creatingEndpointDescription.trim() || undefined,
            request_raw: creatingEndpointRequestRaw.trim() || undefined,
        });
        setCreateEndpointOpen(false);
        setCreatingEndpointPath("");
        setCreatingEndpointMethod("GET");
        setCreatingEndpointDescription("");
        setCreatingEndpointRequestRaw("");
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
            const rawText = await file.text();
            let parsedSpec;
            const lowerCaseName = file.name.toLowerCase();
            const looksLikeYaml = lowerCaseName.endsWith(".yaml") || lowerCaseName.endsWith(".yml");
            try {
                parsedSpec = looksLikeYaml ? parseYaml(rawText) : JSON.parse(rawText);
            }
            catch {
                if (!looksLikeYaml) {
                    try {
                        parsedSpec = parseYaml(rawText);
                    }
                    catch {
                        throw new Error("Swagger/OpenAPI файл должен быть валидным JSON или YAML.");
                    }
                }
                else {
                    throw new Error("Swagger/OpenAPI YAML файл невалиден.");
                }
            }
            if (!parsedSpec || typeof parsedSpec !== "object") {
                throw new Error("Некорректный Swagger/OpenAPI документ.");
            }
            const paths = parsedSpec.paths;
            if (!paths || typeof paths !== "object") {
                throw new Error("В Swagger/OpenAPI документе отсутствует объект paths.");
            }
            const methodOrder = ["get", "post", "put", "patch", "delete", "head", "options"];
            const operations = [];
            Object.entries(paths).forEach(([pathValue, pathItem]) => {
                if (!pathItem || typeof pathItem !== "object") {
                    return;
                }
                methodOrder.forEach((methodName) => {
                    const operation = pathItem[methodName];
                    if (!operation || typeof operation !== "object") {
                        return;
                    }
                    const opInfo = operation;
                    const combinedDescription = [opInfo.summary, opInfo.description].filter(Boolean).join("\n\n");
                    operations.push({
                        method: methodName.toUpperCase(),
                        path: pathValue,
                        description: combinedDescription || undefined,
                    });
                });
            });
            if (!operations.length) {
                throw new Error("В Swagger/OpenAPI документе не найдено методов для импорта.");
            }
            const existingKeys = new Set((host?.endpoints ?? []).map((item) => `${item.method ?? "ANY"}:${item.path}`));
            let created = 0;
            let skipped = 0;
            let failed = 0;
            for (const operation of operations) {
                const key = `${operation.method}:${operation.path}`;
                if (existingKeys.has(key)) {
                    skipped += 1;
                    continue;
                }
                try {
                    await createEndpoint(projectId, hostId, operation);
                    existingKeys.add(key);
                    created += 1;
                }
                catch {
                    failed += 1;
                }
            }
            await loadHost();
            setInfoMessage(`Swagger импорт завершен: добавлено ${created}, пропущено ${skipped}, ошибок ${failed}.`);
        }
        catch (importError) {
            setError(importError instanceof Error ? importError.message : "Не удалось импортировать Swagger/OpenAPI.");
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
        const vulnerability = await createVulnerability(projectId, {
            title: creatingVulnerabilityTitle.trim(),
            description: creatingVulnerabilityDescription.trim() || undefined,
            severity: creatingVulnerabilitySeverity,
            status: creatingVulnerabilityStatus,
        });
        await addVulnerabilityAsset(projectId, vulnerability.id, {
            asset_type: "host",
            asset_id: hostId,
        });
        setCreateVulnerabilityOpen(false);
        setCreatingVulnerabilityTitle("");
        setCreatingVulnerabilityDescription("");
        setCreatingVulnerabilitySeverity("medium");
        setCreatingVulnerabilityStatus("open");
        await loadHost();
    };
    const hostTitle = host?.hostname || host?.ip_address || "unknown-host";
    const portsCount = host?.ports.length ?? 0;
    const endpointsCount = host?.endpoints.length ?? 0;
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
    if (loading) {
        return (_jsx(Box, { display: "flex", justifyContent: "center", py: 6, children: _jsx(CircularProgress, {}) }));
    }
    return (_jsxs(Stack, { spacing: 2.5, children: [error && _jsx(Alert, { severity: "error", children: error }), infoMessage && _jsx(Alert, { severity: "success", children: infoMessage }), _jsxs(Stack, { direction: "row", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 1, children: [_jsx(Stack, { spacing: 0.2, children: _jsxs(Typography, { variant: "h4", fontWeight: 700, children: ["\u0425\u043E\u0441\u0442: ", hostTitle] }) }), _jsx(IconButton, { onClick: openHostActionsMenu, sx: { border: "1px solid rgba(126,224,255,0.2)", borderRadius: 2 }, children: _jsx(MoreVertIcon, {}) })] }), _jsxs(Menu, { anchorEl: hostActionsAnchorEl, open: hostActionsOpen, onClose: closeHostActionsMenu, anchorOrigin: { vertical: "bottom", horizontal: "right" }, transformOrigin: { vertical: "top", horizontal: "right" }, children: [_jsxs(MenuItem, { onClick: openHostEdit, children: [_jsx(EditIcon, { fontSize: "small", sx: { mr: 1 } }), "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u0445\u043E\u0441\u0442"] }), _jsxs(MenuItem, { onClick: () => {
                            closeHostActionsMenu();
                            void removeHost();
                        }, children: [_jsx(DeleteIcon, { fontSize: "small", sx: { mr: 1 } }), "\u0423\u0434\u0430\u043B\u0438\u0442\u044C \u0445\u043E\u0441\u0442"] })] }), _jsxs(Stack, { direction: { xs: "column", md: "row" }, spacing: 2, children: [_jsx(ProjectTreeNav, { hosts: hosts, selectedHostId: hostId ?? null, selectedSection: selectedSection, isCollapsed: isSidebarCollapsed, portsCount: portsCount, endpointsCount: endpointsCount, vulnerabilitiesCount: vulnerabilitiesCount, hostStatsById: hostStatsById, onToggleCollapsed: () => setSidebarCollapsed((v) => !v), onSelectSection: setSelectedSection, onSelectProjectOverview: () => navigate(`/projects/${projectId}`), onSelectHost: (nextHostId) => navigate(`/projects/${projectId}/hosts/${nextHostId}`), onOpenHost: (nextHostId) => navigate(`/projects/${projectId}/hosts/${nextHostId}`) }), _jsxs(Stack, { flex: 1, spacing: 2, children: [_jsxs(Grid, { container: true, spacing: 2, children: [_jsx(Grid, { size: { xs: 12, md: 4 }, children: _jsx(Card, { onClick: () => setSelectedSection("ports"), sx: {
                                                cursor: "pointer",
                                                border: selectedSection === "ports" ? "1px solid rgba(126,224,255,0.45)" : "1px solid rgba(126,224,255,0.16)",
                                                borderRadius: 0,
                                            }, children: _jsxs(CardContent, { children: [_jsx(Typography, { color: "text.secondary", children: "\u041F\u043E\u0440\u0442\u043E\u0432 \u0445\u043E\u0441\u0442\u0430" }), _jsx(Typography, { variant: "h4", fontWeight: 700, children: portsCount })] }) }) }), _jsx(Grid, { size: { xs: 12, md: 4 }, children: _jsx(Card, { onClick: () => setSelectedSection("endpoints"), sx: {
                                                cursor: "pointer",
                                                border: selectedSection === "endpoints" ? "1px solid rgba(126,224,255,0.45)" : "1px solid rgba(126,224,255,0.16)",
                                                borderRadius: 0,
                                            }, children: _jsxs(CardContent, { children: [_jsx(Typography, { color: "text.secondary", children: "\u042D\u043D\u0434\u043F\u043E\u0438\u043D\u0442\u043E\u0432 \u0445\u043E\u0441\u0442\u0430" }), _jsx(Typography, { variant: "h4", fontWeight: 700, children: endpointsCount })] }) }) }), _jsx(Grid, { size: { xs: 12, md: 4 }, children: _jsx(Card, { onClick: () => setSelectedSection("vulns"), sx: {
                                                cursor: "pointer",
                                                border: selectedSection === "vulns" ? "1px solid rgba(126,224,255,0.45)" : "1px solid rgba(126,224,255,0.16)",
                                                borderRadius: 0,
                                            }, children: _jsxs(CardContent, { children: [_jsx(Typography, { color: "text.secondary", children: "\u0423\u044F\u0437\u0432\u0438\u043C\u043E\u0441\u0442\u0435\u0439 \u0445\u043E\u0441\u0442\u0430" }), _jsx(Typography, { variant: "h4", fontWeight: 700, children: vulnerabilitiesCount })] }) }) })] }), selectedSection === "overview" && (_jsx(Stack, { spacing: 2, children: _jsx(Card, { sx: { border: "1px solid rgba(126,224,255,0.16)", borderRadius: 0 }, children: _jsxs(CardContent, { children: [_jsx(Typography, { variant: "h6", fontWeight: 700, mb: 1, children: "\u041E\u043F\u0438\u0441\u0430\u043D\u0438\u0435 \u0445\u043E\u0441\u0442\u0430" }), _jsx(Box, { sx: { border: "1px solid rgba(126,224,255,0.12)", p: 1.5, borderRadius: 0 }, children: _jsx(ReactMarkdown, { children: host?.notes || "_Описание хоста не заполнено_" }) })] }) }) })), selectedSection === "ports" && (_jsx(Card, { sx: { border: "1px solid rgba(126,224,255,0.16)", borderRadius: 0 }, children: _jsxs(CardContent, { children: [_jsxs(Stack, { direction: "row", alignItems: "center", justifyContent: "space-between", mb: 1, children: [_jsx(Typography, { variant: "h6", fontWeight: 700, children: "\u041F\u043E\u0440\u0442\u044B" }), _jsx(Tooltip, { title: "\u0414\u043E\u0431\u0430\u0432\u0438\u0442\u044C \u043F\u043E\u0440\u0442", children: _jsx(IconButton, { size: "small", onClick: () => setCreatePortOpen(true), children: _jsx(AddIcon, { fontSize: "small" }) }) })] }), _jsxs(Stack, { spacing: 1, children: [host?.ports.map((port) => (_jsxs(Stack, { onClick: () => toggleExpandedId(port.id, setExpandedPortIds), sx: {
                                                        border: "1px solid rgba(126,224,255,0.12)",
                                                        p: 1.2,
                                                        borderRadius: 0,
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
                                                                                    }, children: _jsx(AddIcon, { fontSize: "small" }) }) })] }), _jsxs(Stack, { spacing: 0.8, children: [(servicesByPortId[port.id] ?? []).map((service) => (_jsxs(Stack, { direction: "row", justifyContent: "space-between", alignItems: "center", sx: { border: "1px solid rgba(126,224,255,0.12)", p: 0.8, borderRadius: 0 }, children: [_jsxs(Stack, { spacing: 0.2, children: [_jsx(Typography, { variant: "body2", fontWeight: 600, children: service.name }), _jsx(Typography, { variant: "caption", color: "text.secondary", children: service.version || "version n/a" })] }), _jsxs(Stack, { direction: "row", spacing: 0.4, children: [_jsx(Tooltip, { title: "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u0441\u0435\u0440\u0432\u0438\u0441", children: _jsx(IconButton, { size: "small", onClick: (event) => {
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
                                                    }, children: [_jsx(DeleteIcon, { fontSize: "small", sx: { mr: 1 } }), "\u0423\u0434\u0430\u043B\u0438\u0442\u044C"] })] })] }) })), selectedSection === "endpoints" && (_jsx(Card, { sx: { border: "1px solid rgba(126,224,255,0.16)", borderRadius: 0 }, children: _jsxs(CardContent, { children: [_jsxs(Stack, { direction: "row", alignItems: "center", justifyContent: "space-between", mb: 1, children: [_jsx(Typography, { variant: "h6", fontWeight: 700, children: "\u042D\u043D\u0434\u043F\u043E\u0438\u043D\u0442\u044B" }), _jsxs(Stack, { direction: "row", spacing: 0.5, children: [_jsx(Tooltip, { title: "\u0418\u043C\u043F\u043E\u0440\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u0438\u0437 Swagger/OpenAPI (JSON/YAML)", children: _jsxs(IconButton, { size: "small", component: "label", disabled: swaggerImporting, children: [_jsx(UploadFileIcon, { fontSize: "small" }), _jsx("input", { hidden: true, type: "file", accept: "application/json,.json,.yaml,.yml,text/yaml,application/yaml", onChange: (event) => {
                                                                            const selectedFile = event.target.files?.[0] ?? null;
                                                                            void importEndpointsFromSwaggerFile(selectedFile);
                                                                            event.target.value = "";
                                                                        } })] }) }), _jsx(Tooltip, { title: "\u0414\u043E\u0431\u0430\u0432\u0438\u0442\u044C \u044D\u043D\u0434\u043F\u043E\u0438\u043D\u0442", children: _jsx(IconButton, { size: "small", onClick: () => setCreateEndpointOpen(true), children: _jsx(AddIcon, { fontSize: "small" }) }) })] })] }), _jsxs(Stack, { spacing: 1, children: [host?.endpoints.map((endpoint) => (_jsxs(Box, { onClick: () => toggleExpandedId(endpoint.id, setExpandedEndpointIds), sx: {
                                                        border: "1px solid rgba(126,224,255,0.12)",
                                                        p: 1.2,
                                                        borderRadius: 0,
                                                        cursor: "pointer",
                                                        "& .endpoint-actions": {
                                                            opacity: 0,
                                                            pointerEvents: "none",
                                                            transition: "opacity 0.15s ease-in-out",
                                                        },
                                                        "&:hover .endpoint-actions": {
                                                            opacity: 1,
                                                            pointerEvents: "auto",
                                                        },
                                                    }, children: [_jsxs(Stack, { direction: "row", spacing: 1, alignItems: "center", justifyContent: "space-between", children: [_jsxs(Stack, { direction: "row", spacing: 1, alignItems: "center", children: [_jsx(Chip, { size: "small", label: endpoint.method || "ANY" }), _jsx(Typography, { fontWeight: 600, children: endpoint.path })] }), _jsx(Stack, { direction: "row", spacing: 0.4, className: "endpoint-actions", children: _jsx(Tooltip, { title: "\u0414\u0435\u0439\u0441\u0442\u0432\u0438\u044F", children: _jsx(IconButton, { size: "small", onClick: (event) => openEndpointActions(event, endpoint), children: _jsx(MoreVertIcon, { fontSize: "small" }) }) }) })] }), _jsx(Collapse, { in: expandedEndpointIds.includes(endpoint.id), timeout: "auto", unmountOnExit: true, children: _jsx(Typography, { mt: 0.8, color: "text.secondary", variant: "body2", children: endpoint.description || "Описание не указано" }) })] }, endpoint.id))), !host?.endpoints.length && _jsx(Typography, { color: "text.secondary", children: "\u042D\u043D\u0434\u043F\u043E\u0438\u043D\u0442\u044B \u0434\u043B\u044F \u044D\u0442\u043E\u0433\u043E \u0445\u043E\u0441\u0442\u0430 \u043F\u043E\u043A\u0430 \u043D\u0435 \u0434\u043E\u0431\u0430\u0432\u043B\u0435\u043D\u044B." })] }), _jsxs(Menu, { anchorEl: endpointActionsAnchorEl, open: endpointActionsOpen, onClose: closeEndpointActions, anchorOrigin: { vertical: "bottom", horizontal: "right" }, transformOrigin: { vertical: "top", horizontal: "right" }, children: [_jsxs(MenuItem, { onClick: () => {
                                                        if (activeEndpoint) {
                                                            openEndpointEdit(activeEndpoint);
                                                        }
                                                        closeEndpointActions();
                                                    }, children: [_jsx(EditIcon, { fontSize: "small", sx: { mr: 1 } }), "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C"] }), _jsxs(MenuItem, { onClick: () => {
                                                        if (activeEndpoint) {
                                                            void removeEndpoint(activeEndpoint.id);
                                                        }
                                                        closeEndpointActions();
                                                    }, children: [_jsx(DeleteIcon, { fontSize: "small", sx: { mr: 1 } }), "\u0423\u0434\u0430\u043B\u0438\u0442\u044C"] }), _jsxs(MenuItem, { onClick: () => void copyEndpointRequest("curl"), children: [_jsx(ContentCopyIcon, { fontSize: "small", sx: { mr: 1 } }), "\u0421\u043A\u043E\u043F\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u043A\u0430\u043A cURL"] }), _jsxs(MenuItem, { onClick: () => void copyEndpointRequest("raw"), children: [_jsx(ContentCopyIcon, { fontSize: "small", sx: { mr: 1 } }), "\u0421\u043A\u043E\u043F\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u043A\u0430\u043A Raw"] })] })] }) })), selectedSection === "vulns" && (_jsx(Card, { sx: { border: "1px solid rgba(126,224,255,0.16)", borderRadius: 0 }, children: _jsxs(CardContent, { children: [_jsxs(Stack, { direction: "row", alignItems: "center", justifyContent: "space-between", mb: 1, children: [_jsx(Typography, { variant: "h6", fontWeight: 700, children: "\u0423\u044F\u0437\u0432\u0438\u043C\u043E\u0441\u0442\u0438 \u0445\u043E\u0441\u0442\u0430" }), _jsx(Tooltip, { title: "\u0414\u043E\u0431\u0430\u0432\u0438\u0442\u044C \u0443\u044F\u0437\u0432\u0438\u043C\u043E\u0441\u0442\u044C", children: _jsx(IconButton, { size: "small", onClick: () => setCreateVulnerabilityOpen(true), children: _jsx(AddIcon, { fontSize: "small" }) }) })] }), _jsxs(Stack, { spacing: 1, children: [vulnerabilities.map((item) => (_jsxs(Box, { onClick: () => toggleExpandedId(item.id, setExpandedVulnerabilityIds), sx: {
                                                        border: "1px solid rgba(126,224,255,0.12)",
                                                        p: 1.2,
                                                        borderRadius: 0,
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
                                                    }, children: [_jsxs(Stack, { direction: "row", justifyContent: "space-between", alignItems: "center", children: [_jsxs(Stack, { spacing: 0.8, children: [_jsx(Typography, { fontWeight: 600, children: item.title }), _jsxs(Stack, { direction: "row", spacing: 1, children: [_jsx(Chip, { size: "small", label: item.severity, sx: severityChipSx[item.severity] }), _jsx(Chip, { size: "small", label: item.status, sx: vulnerabilityStatusChipSx[item.status] })] })] }), _jsx(Stack, { direction: "row", spacing: 0.4, alignItems: "center", className: "vuln-actions", children: _jsx(Tooltip, { title: "\u0414\u0435\u0439\u0441\u0442\u0432\u0438\u044F", children: _jsx(IconButton, { size: "small", onClick: (event) => openVulnerabilityActions(event, item), children: _jsx(MoreVertIcon, { fontSize: "small" }) }) }) })] }), _jsx(Collapse, { in: expandedVulnerabilityIds.includes(item.id), timeout: "auto", unmountOnExit: true, children: _jsx(Typography, { mt: 0.8, color: "text.secondary", variant: "body2", children: item.description || "Описание не указано" }) })] }, item.id))), !vulnerabilities.length && _jsx(Typography, { color: "text.secondary", children: "\u0423\u044F\u0437\u0432\u0438\u043C\u043E\u0441\u0442\u0438, \u043F\u0440\u0438\u0432\u044F\u0437\u0430\u043D\u043D\u044B\u0435 \u043A \u044D\u0442\u043E\u043C\u0443 \u0445\u043E\u0441\u0442\u0443, \u043F\u043E\u043A\u0430 \u043D\u0435 \u0434\u043E\u0431\u0430\u0432\u043B\u0435\u043D\u044B." })] }), _jsxs(Menu, { anchorEl: vulnerabilityActionsAnchorEl, open: vulnerabilityActionsOpen, onClose: closeVulnerabilityActions, anchorOrigin: { vertical: "bottom", horizontal: "right" }, transformOrigin: { vertical: "top", horizontal: "right" }, children: [_jsxs(MenuItem, { onClick: () => {
                                                        if (activeVulnerability) {
                                                            openVulnerabilityEdit(activeVulnerability);
                                                        }
                                                        closeVulnerabilityActions();
                                                    }, children: [_jsx(EditIcon, { fontSize: "small", sx: { mr: 1 } }), "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C"] }), _jsxs(MenuItem, { onClick: () => {
                                                        if (activeVulnerability) {
                                                            void removeVulnerability(activeVulnerability.id);
                                                        }
                                                        closeVulnerabilityActions();
                                                    }, children: [_jsx(DeleteIcon, { fontSize: "small", sx: { mr: 1 } }), "\u0423\u0434\u0430\u043B\u0438\u0442\u044C"] })] })] }) }))] })] }), _jsxs(Dialog, { open: isEditHostOpen, onClose: () => setEditHostOpen(false), fullWidth: true, children: [_jsx(DialogTitle, { children: "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u0445\u043E\u0441\u0442" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [_jsx(TextField, { label: "IP-\u0430\u0434\u0440\u0435\u0441", value: editingHostIp, onChange: (event) => setEditingHostIp(event.target.value) }), _jsx(TextField, { label: "Hostname", value: editingHostName, onChange: (event) => setEditingHostName(event.target.value) }), _jsxs(TextField, { select: true, label: "\u0421\u0442\u0430\u0442\u0443\u0441", value: editingHostStatus, onChange: (event) => setEditingHostStatus(event.target.value), children: [_jsx(MenuItem, { value: "up", children: "up" }), _jsx(MenuItem, { value: "down", children: "down" }), _jsx(MenuItem, { value: "unknown", children: "unknown" })] }), _jsx(TextField, { multiline: true, minRows: 4, label: "\u041E\u043F\u0438\u0441\u0430\u043D\u0438\u0435", value: editingHostNotes, onChange: (event) => setEditingHostNotes(event.target.value) })] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setEditHostOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", onClick: () => void saveHostInfo(), disabled: !editingHostIp.trim() && !editingHostName.trim(), children: "\u0421\u043E\u0445\u0440\u0430\u043D\u0438\u0442\u044C" })] })] }), _jsxs(Dialog, { open: isEditPortOpen, onClose: () => setEditPortOpen(false), fullWidth: true, children: [_jsx(DialogTitle, { children: "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u043F\u043E\u0440\u0442" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [_jsx(TextField, { label: "\u041D\u043E\u043C\u0435\u0440 \u043F\u043E\u0440\u0442\u0430", type: "number", inputProps: { min: 1, max: 65535 }, value: editingPortNumber, onChange: (event) => setEditingPortNumber(event.target.value) }), _jsxs(TextField, { select: true, label: "\u041F\u0440\u043E\u0442\u043E\u043A\u043E\u043B", value: editingPortProtocol, onChange: (event) => setEditingPortProtocol(event.target.value), children: [_jsx(MenuItem, { value: "tcp", children: "tcp" }), _jsx(MenuItem, { value: "udp", children: "udp" })] }), _jsxs(TextField, { select: true, label: "\u0421\u043E\u0441\u0442\u043E\u044F\u043D\u0438\u0435", value: editingPortState, onChange: (event) => setEditingPortState(event.target.value), children: [_jsx(MenuItem, { value: "open", children: "open" }), _jsx(MenuItem, { value: "closed", children: "closed" }), _jsx(MenuItem, { value: "filtered", children: "filtered" })] })] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setEditPortOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", onClick: () => void savePortEdit(), children: "\u0421\u043E\u0445\u0440\u0430\u043D\u0438\u0442\u044C" })] })] }), _jsxs(Dialog, { open: isCreatePortOpen, onClose: () => setCreatePortOpen(false), fullWidth: true, children: [_jsx(DialogTitle, { children: "\u0414\u043E\u0431\u0430\u0432\u0438\u0442\u044C \u043F\u043E\u0440\u0442" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [_jsx(TextField, { label: "\u041D\u043E\u043C\u0435\u0440 \u043F\u043E\u0440\u0442\u0430", type: "number", inputProps: { min: 1, max: 65535 }, value: creatingPortNumber, onChange: (event) => setCreatingPortNumber(event.target.value) }), _jsxs(TextField, { select: true, label: "\u041F\u0440\u043E\u0442\u043E\u043A\u043E\u043B", value: creatingPortProtocol, onChange: (event) => setCreatingPortProtocol(event.target.value), children: [_jsx(MenuItem, { value: "tcp", children: "tcp" }), _jsx(MenuItem, { value: "udp", children: "udp" })] }), _jsxs(TextField, { select: true, label: "\u0421\u043E\u0441\u0442\u043E\u044F\u043D\u0438\u0435", value: creatingPortState, onChange: (event) => setCreatingPortState(event.target.value), children: [_jsx(MenuItem, { value: "open", children: "open" }), _jsx(MenuItem, { value: "closed", children: "closed" }), _jsx(MenuItem, { value: "filtered", children: "filtered" })] })] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setCreatePortOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", onClick: () => void createHostPort(), children: "\u0421\u043E\u0437\u0434\u0430\u0442\u044C" })] })] }), _jsxs(Dialog, { open: isCreateServiceOpen, onClose: () => setCreateServiceOpen(false), fullWidth: true, children: [_jsx(DialogTitle, { children: "\u0414\u043E\u0431\u0430\u0432\u0438\u0442\u044C \u0441\u0435\u0440\u0432\u0438\u0441" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [_jsx(TextField, { label: "\u041D\u0430\u0437\u0432\u0430\u043D\u0438\u0435 \u0441\u0435\u0440\u0432\u0438\u0441\u0430", value: creatingServiceName, onChange: (event) => setCreatingServiceName(event.target.value) }), _jsx(TextField, { label: "\u0412\u0435\u0440\u0441\u0438\u044F", value: creatingServiceVersion, onChange: (event) => setCreatingServiceVersion(event.target.value) }), _jsx(TextField, { multiline: true, minRows: 3, label: "Banner", value: creatingServiceBanner, onChange: (event) => setCreatingServiceBanner(event.target.value) })] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setCreateServiceOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", onClick: () => void createPortService(), disabled: !creatingServiceName.trim(), children: "\u0421\u043E\u0437\u0434\u0430\u0442\u044C" })] })] }), _jsxs(Dialog, { open: isEditServiceOpen, onClose: () => setEditServiceOpen(false), fullWidth: true, children: [_jsx(DialogTitle, { children: "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u0441\u0435\u0440\u0432\u0438\u0441" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [_jsx(TextField, { label: "\u041D\u0430\u0437\u0432\u0430\u043D\u0438\u0435 \u0441\u0435\u0440\u0432\u0438\u0441\u0430", value: editingServiceName, onChange: (event) => setEditingServiceName(event.target.value) }), _jsx(TextField, { label: "\u0412\u0435\u0440\u0441\u0438\u044F", value: editingServiceVersion, onChange: (event) => setEditingServiceVersion(event.target.value) }), _jsx(TextField, { multiline: true, minRows: 3, label: "Banner", value: editingServiceBanner, onChange: (event) => setEditingServiceBanner(event.target.value) })] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setEditServiceOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", onClick: () => void saveServiceEdit(), disabled: !editingServiceName.trim(), children: "\u0421\u043E\u0445\u0440\u0430\u043D\u0438\u0442\u044C" })] })] }), _jsxs(Dialog, { open: isEditEndpointOpen, onClose: () => setEditEndpointOpen(false), fullWidth: true, children: [_jsx(DialogTitle, { children: "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u044D\u043D\u0434\u043F\u043E\u0438\u043D\u0442" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [_jsx(TextField, { multiline: true, minRows: 6, label: "Raw HTTP request (\u043E\u043F\u0446\u0438\u043E\u043D\u0430\u043B\u044C\u043D\u043E)", placeholder: "POST /api/login HTTP/1.1\nHost: target.local\nContent-Type: application/json\n\n{\"user\":\"admin\"}", value: editingEndpointRequestRaw, onChange: (event) => applyParsedRequestToEditEndpoint(event.target.value) }), _jsx(TextField, { label: "\u041F\u0443\u0442\u044C", value: editingEndpointPath, onChange: (event) => setEditingEndpointPath(event.target.value) }), _jsx(TextField, { select: true, label: "HTTP-\u043C\u0435\u0442\u043E\u0434", value: editingEndpointMethod, onChange: (event) => setEditingEndpointMethod(event.target.value), children: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map((method) => (_jsx(MenuItem, { value: method, children: method }, method))) }), _jsx(TextField, { multiline: true, minRows: 3, label: "\u041E\u043F\u0438\u0441\u0430\u043D\u0438\u0435", value: editingEndpointDescription, onChange: (event) => setEditingEndpointDescription(event.target.value) })] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setEditEndpointOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", onClick: () => void saveEndpointEdit(), disabled: !editingEndpointPath.trim(), children: "\u0421\u043E\u0445\u0440\u0430\u043D\u0438\u0442\u044C" })] })] }), _jsxs(Dialog, { open: isCreateEndpointOpen, onClose: () => setCreateEndpointOpen(false), fullWidth: true, children: [_jsx(DialogTitle, { children: "\u0414\u043E\u0431\u0430\u0432\u0438\u0442\u044C \u044D\u043D\u0434\u043F\u043E\u0438\u043D\u0442" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [_jsx(TextField, { multiline: true, minRows: 6, label: "Raw HTTP request (\u043E\u043F\u0446\u0438\u043E\u043D\u0430\u043B\u044C\u043D\u043E)", placeholder: "POST /api/login HTTP/1.1\nHost: target.local\nContent-Type: application/json\n\n{\"user\":\"admin\"}", value: creatingEndpointRequestRaw, onChange: (event) => applyParsedRequestToCreateEndpoint(event.target.value) }), _jsx(TextField, { label: "\u041F\u0443\u0442\u044C", value: creatingEndpointPath, onChange: (event) => setCreatingEndpointPath(event.target.value) }), _jsx(TextField, { select: true, label: "HTTP-\u043C\u0435\u0442\u043E\u0434", value: creatingEndpointMethod, onChange: (event) => setCreatingEndpointMethod(event.target.value), children: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map((method) => (_jsx(MenuItem, { value: method, children: method }, method))) }), _jsx(TextField, { multiline: true, minRows: 3, label: "\u041E\u043F\u0438\u0441\u0430\u043D\u0438\u0435", value: creatingEndpointDescription, onChange: (event) => setCreatingEndpointDescription(event.target.value) })] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setCreateEndpointOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", onClick: () => void createHostEndpoint(), disabled: !creatingEndpointPath.trim() && !creatingEndpointRequestRaw.trim(), children: "\u0421\u043E\u0437\u0434\u0430\u0442\u044C" })] })] }), _jsxs(Dialog, { open: isEditVulnerabilityOpen, onClose: () => setEditVulnerabilityOpen(false), fullWidth: true, children: [_jsx(DialogTitle, { children: "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u0443\u044F\u0437\u0432\u0438\u043C\u043E\u0441\u0442\u044C" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [_jsx(TextField, { label: "\u041D\u0430\u0437\u0432\u0430\u043D\u0438\u0435", value: editingVulnerabilityTitle, onChange: (event) => setEditingVulnerabilityTitle(event.target.value) }), _jsx(TextField, { multiline: true, minRows: 3, label: "\u041E\u043F\u0438\u0441\u0430\u043D\u0438\u0435", value: editingVulnerabilityDescription, onChange: (event) => setEditingVulnerabilityDescription(event.target.value) }), _jsxs(TextField, { select: true, label: "\u041A\u0440\u0438\u0442\u0438\u0447\u043D\u043E\u0441\u0442\u044C", value: editingVulnerabilitySeverity, onChange: (event) => setEditingVulnerabilitySeverity(event.target.value), children: [_jsx(MenuItem, { value: "critical", children: "critical" }), _jsx(MenuItem, { value: "high", children: "high" }), _jsx(MenuItem, { value: "medium", children: "medium" }), _jsx(MenuItem, { value: "low", children: "low" }), _jsx(MenuItem, { value: "info", children: "info" })] }), _jsxs(TextField, { select: true, label: "\u0421\u0442\u0430\u0442\u0443\u0441", value: editingVulnerabilityStatus, onChange: (event) => setEditingVulnerabilityStatus(event.target.value), children: [_jsx(MenuItem, { value: "open", children: "open" }), _jsx(MenuItem, { value: "in_progress", children: "in_progress" }), _jsx(MenuItem, { value: "fixed", children: "fixed" }), _jsx(MenuItem, { value: "wont_fix", children: "wont_fix" }), _jsx(MenuItem, { value: "accepted_risk", children: "accepted_risk" })] })] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setEditVulnerabilityOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", onClick: () => void saveVulnerabilityEdit(), disabled: !editingVulnerabilityTitle.trim(), children: "\u0421\u043E\u0445\u0440\u0430\u043D\u0438\u0442\u044C" })] })] }), _jsxs(Dialog, { open: isCreateVulnerabilityOpen, onClose: () => setCreateVulnerabilityOpen(false), fullWidth: true, children: [_jsx(DialogTitle, { children: "\u0414\u043E\u0431\u0430\u0432\u0438\u0442\u044C \u0443\u044F\u0437\u0432\u0438\u043C\u043E\u0441\u0442\u044C \u043A \u0445\u043E\u0441\u0442\u0443" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [_jsx(TextField, { label: "\u041D\u0430\u0437\u0432\u0430\u043D\u0438\u0435", value: creatingVulnerabilityTitle, onChange: (event) => setCreatingVulnerabilityTitle(event.target.value) }), _jsx(TextField, { multiline: true, minRows: 3, label: "\u041E\u043F\u0438\u0441\u0430\u043D\u0438\u0435", value: creatingVulnerabilityDescription, onChange: (event) => setCreatingVulnerabilityDescription(event.target.value) }), _jsxs(TextField, { select: true, label: "\u041A\u0440\u0438\u0442\u0438\u0447\u043D\u043E\u0441\u0442\u044C", value: creatingVulnerabilitySeverity, onChange: (event) => setCreatingVulnerabilitySeverity(event.target.value), children: [_jsx(MenuItem, { value: "critical", children: "critical" }), _jsx(MenuItem, { value: "high", children: "high" }), _jsx(MenuItem, { value: "medium", children: "medium" }), _jsx(MenuItem, { value: "low", children: "low" }), _jsx(MenuItem, { value: "info", children: "info" })] }), _jsxs(TextField, { select: true, label: "\u0421\u0442\u0430\u0442\u0443\u0441", value: creatingVulnerabilityStatus, onChange: (event) => setCreatingVulnerabilityStatus(event.target.value), children: [_jsx(MenuItem, { value: "open", children: "open" }), _jsx(MenuItem, { value: "in_progress", children: "in_progress" }), _jsx(MenuItem, { value: "fixed", children: "fixed" }), _jsx(MenuItem, { value: "wont_fix", children: "wont_fix" }), _jsx(MenuItem, { value: "accepted_risk", children: "accepted_risk" })] })] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setCreateVulnerabilityOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", onClick: () => void createHostVulnerability(), disabled: !creatingVulnerabilityTitle.trim(), children: "\u0421\u043E\u0437\u0434\u0430\u0442\u044C" })] })] })] }));
}
