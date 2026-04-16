import DeleteIcon from "@mui/icons-material/Delete";
import EditIcon from "@mui/icons-material/Edit";
import AddIcon from "@mui/icons-material/Add";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import MoreVertIcon from "@mui/icons-material/MoreVert";
import UploadFileIcon from "@mui/icons-material/UploadFile";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Collapse,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Grid2 as Grid,
  IconButton,
  Menu,
  MenuItem,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import { useCallback, useEffect, useState } from "react";
import { load as parseYaml } from "js-yaml";
import ReactMarkdown from "react-markdown";
import { useNavigate, useParams } from "react-router-dom";
import {
  addVulnerabilityAsset,
  createEndpoint,
  createPort,
  createService,
  createVulnerability,
  deleteEndpoint,
  deleteHost,
  deletePort,
  deleteService,
  deleteVulnerability,
  getServices,
  getHost,
  getHosts,
  getHostVulnerabilities,
  updateEndpoint,
  updateHost,
  updatePort,
  updateService,
  updateVulnerability,
} from "../api";
import { ProjectTreeNav, type DetailSection } from "../components/ProjectTreeNav";
import type { Endpoint, Host, HostDetails, HostTreeStats, Port, Service, Vulnerability } from "../types";

export function HostDetailPage() {
  const { projectId, hostId } = useParams<{ projectId: string; hostId: string }>();
  const navigate = useNavigate();

  const [host, setHost] = useState<HostDetails | null>(null);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [infoMessage, setInfoMessage] = useState<string | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [selectedSection, setSelectedSection] = useState<DetailSection>("overview");
  const [isSidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [hostStatsById, setHostStatsById] = useState<Record<string, HostTreeStats>>({});
  const [isEditPortOpen, setEditPortOpen] = useState(false);
  const [editingPortId, setEditingPortId] = useState<string | null>(null);
  const [editingPortNumber, setEditingPortNumber] = useState("1");
  const [editingPortProtocol, setEditingPortProtocol] = useState<Port["protocol"]>("tcp");
  const [editingPortState, setEditingPortState] = useState<Port["state"]>("open");
  const [servicesByPortId, setServicesByPortId] = useState<Record<string, Service[]>>({});
  const [isCreateServiceOpen, setCreateServiceOpen] = useState(false);
  const [createServicePortId, setCreateServicePortId] = useState<string | null>(null);
  const [creatingServiceName, setCreatingServiceName] = useState("");
  const [creatingServiceVersion, setCreatingServiceVersion] = useState("");
  const [creatingServiceBanner, setCreatingServiceBanner] = useState("");
  const [isEditServiceOpen, setEditServiceOpen] = useState(false);
  const [editServicePortId, setEditServicePortId] = useState<string | null>(null);
  const [editingServiceId, setEditingServiceId] = useState<string | null>(null);
  const [editingServiceName, setEditingServiceName] = useState("");
  const [editingServiceVersion, setEditingServiceVersion] = useState("");
  const [editingServiceBanner, setEditingServiceBanner] = useState("");
  const [isEditEndpointOpen, setEditEndpointOpen] = useState(false);
  const [editingEndpointId, setEditingEndpointId] = useState<string | null>(null);
  const [editingEndpointPath, setEditingEndpointPath] = useState("");
  const [editingEndpointMethod, setEditingEndpointMethod] = useState<Exclude<Endpoint["method"], null>>("GET");
  const [editingEndpointDescription, setEditingEndpointDescription] = useState("");
  const [editingEndpointRequestRaw, setEditingEndpointRequestRaw] = useState("");
  const [isEditVulnerabilityOpen, setEditVulnerabilityOpen] = useState(false);
  const [editingVulnerabilityId, setEditingVulnerabilityId] = useState<string | null>(null);
  const [editingVulnerabilityTitle, setEditingVulnerabilityTitle] = useState("");
  const [editingVulnerabilityDescription, setEditingVulnerabilityDescription] = useState("");
  const [editingVulnerabilitySeverity, setEditingVulnerabilitySeverity] = useState<Vulnerability["severity"]>("medium");
  const [editingVulnerabilityStatus, setEditingVulnerabilityStatus] = useState<Vulnerability["status"]>("open");
  const [isCreatePortOpen, setCreatePortOpen] = useState(false);
  const [creatingPortNumber, setCreatingPortNumber] = useState("443");
  const [creatingPortProtocol, setCreatingPortProtocol] = useState<Port["protocol"]>("tcp");
  const [creatingPortState, setCreatingPortState] = useState<Port["state"]>("open");
  const [isCreateEndpointOpen, setCreateEndpointOpen] = useState(false);
  const [creatingEndpointPath, setCreatingEndpointPath] = useState("");
  const [creatingEndpointMethod, setCreatingEndpointMethod] = useState<Exclude<Endpoint["method"], null>>("GET");
  const [creatingEndpointDescription, setCreatingEndpointDescription] = useState("");
  const [creatingEndpointRequestRaw, setCreatingEndpointRequestRaw] = useState("");
  const [swaggerImporting, setSwaggerImporting] = useState(false);
  const [isCreateVulnerabilityOpen, setCreateVulnerabilityOpen] = useState(false);
  const [creatingVulnerabilityTitle, setCreatingVulnerabilityTitle] = useState("");
  const [creatingVulnerabilityDescription, setCreatingVulnerabilityDescription] = useState("");
  const [creatingVulnerabilitySeverity, setCreatingVulnerabilitySeverity] = useState<Vulnerability["severity"]>("medium");
  const [creatingVulnerabilityStatus, setCreatingVulnerabilityStatus] = useState<Vulnerability["status"]>("open");
  const [hostActionsAnchorEl, setHostActionsAnchorEl] = useState<HTMLElement | null>(null);
  const [isEditHostOpen, setEditHostOpen] = useState(false);
  const [editingHostIp, setEditingHostIp] = useState("");
  const [editingHostName, setEditingHostName] = useState("");
  const [editingHostStatus, setEditingHostStatus] = useState<Host["status"]>("unknown");
  const [editingHostNotes, setEditingHostNotes] = useState("");
  const [portActionsAnchorEl, setPortActionsAnchorEl] = useState<HTMLElement | null>(null);
  const [activePort, setActivePort] = useState<Port | null>(null);
  const [endpointActionsAnchorEl, setEndpointActionsAnchorEl] = useState<HTMLElement | null>(null);
  const [activeEndpoint, setActiveEndpoint] = useState<Endpoint | null>(null);
  const [vulnerabilityActionsAnchorEl, setVulnerabilityActionsAnchorEl] = useState<HTMLElement | null>(null);
  const [activeVulnerability, setActiveVulnerability] = useState<Vulnerability | null>(null);
  const [expandedPortIds, setExpandedPortIds] = useState<string[]>([]);
  const [expandedEndpointIds, setExpandedEndpointIds] = useState<string[]>([]);
  const [expandedVulnerabilityIds, setExpandedVulnerabilityIds] = useState<string[]>([]);

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
      const statsEntries = await Promise.allSettled(
        hostsResponse.items.map(async (listedHost) => {
          if (listedHost.id === hostId) {
            return [
              listedHost.id,
              {
                portsCount: hostResponse.ports.length,
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
              portsCount: hostDetails.ports.length,
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
    } catch {
      setError("Не удалось загрузить страницу хоста.");
    } finally {
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
      const entries = await Promise.allSettled(
        host.ports.map(async (port) => {
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
  }, [host?.ports, hostId, projectId]);

  const hostActionsOpen = Boolean(hostActionsAnchorEl);
  const portActionsOpen = Boolean(portActionsAnchorEl);
  const endpointActionsOpen = Boolean(endpointActionsAnchorEl);
  const vulnerabilityActionsOpen = Boolean(vulnerabilityActionsAnchorEl);

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
      setHost((prev) =>
        prev
          ? {
              ...prev,
              ip_address: updatedHost.ip_address,
              hostname: updatedHost.hostname,
              status: updatedHost.status,
              notes: updatedHost.notes,
            }
          : prev
      );
      setEditHostOpen(false);
    } catch {
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

  const openEndpointActions = (event: React.MouseEvent<HTMLElement>, endpoint: Endpoint) => {
    event.stopPropagation();
    setEndpointActionsAnchorEl(event.currentTarget);
    setActiveEndpoint(endpoint);
  };

  const closeEndpointActions = () => {
    setEndpointActionsAnchorEl(null);
    setActiveEndpoint(null);
  };

  const openVulnerabilityActions = (event: React.MouseEvent<HTMLElement>, vulnerability: Vulnerability) => {
    event.stopPropagation();
    setVulnerabilityActionsAnchorEl(event.currentTarget);
    setActiveVulnerability(vulnerability);
  };

  const closeVulnerabilityActions = () => {
    setVulnerabilityActionsAnchorEl(null);
    setActiveVulnerability(null);
  };

  const toggleExpandedId = (id: string, setExpanded: React.Dispatch<React.SetStateAction<string[]>>) => {
    setExpanded((current) => (current.includes(id) ? current.filter((itemId) => itemId !== id) : [...current, id]));
  };

  const buildEndpointRawRequest = (endpoint: Endpoint) => {
    const method = endpoint.method ?? "GET";
    const hostHeader = host?.hostname || host?.ip_address || "example.local";
    return `${method} ${endpoint.path} HTTP/1.1\nHost: ${hostHeader}\n\n`;
  };

  const buildEndpointCurl = (endpoint: Endpoint) => {
    const method = endpoint.method ?? "GET";
    const hostTarget = host?.hostname || host?.ip_address || "example.local";
    return `curl -X ${method} "http://${hostTarget}${endpoint.path}"`;
  };

  const copyEndpointRequest = async (format: "curl" | "raw") => {
    if (!activeEndpoint) {
      return;
    }
    const text = format === "curl" ? buildEndpointCurl(activeEndpoint) : buildEndpointRawRequest(activeEndpoint);
    await navigator.clipboard.writeText(text);
    closeEndpointActions();
  };

  const openPortEdit = (port: Port) => {
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

  const removePort = async (portId: string) => {
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

  const openCreateServiceDialog = (portId: string) => {
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

  const openEditServiceDialog = (portId: string, service: Service) => {
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

  const removeService = async (portId: string, serviceId: string) => {
    if (!projectId || !hostId) {
      return;
    }
    if (!window.confirm("Удалить сервис?")) {
      return;
    }
    await deleteService(projectId, hostId, portId, serviceId);
    await loadHost();
  };

  const parseRawHttpRequest = (rawRequest: string): { method: Exclude<Endpoint["method"], null>; path: string } | null => {
    const firstLine = rawRequest.replace("\r", "").split("\n").map((line) => line.trim()).find(Boolean);
    if (!firstLine) {
      return null;
    }
    const requestLineMatch = firstLine.match(/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP\/\d(?:\.\d)?$/i);
    if (!requestLineMatch) {
      return null;
    }
    return {
      method: requestLineMatch[1].toUpperCase() as Exclude<Endpoint["method"], null>,
      path: requestLineMatch[2],
    };
  };

  const applyParsedRequestToCreateEndpoint = (rawRequest: string) => {
    setCreatingEndpointRequestRaw(rawRequest);
    const parsed = parseRawHttpRequest(rawRequest);
    if (!parsed) {
      return;
    }
    setCreatingEndpointMethod(parsed.method);
    setCreatingEndpointPath(parsed.path);
  };

  const applyParsedRequestToEditEndpoint = (rawRequest: string) => {
    setEditingEndpointRequestRaw(rawRequest);
    const parsed = parseRawHttpRequest(rawRequest);
    if (!parsed) {
      return;
    }
    setEditingEndpointMethod(parsed.method);
    setEditingEndpointPath(parsed.path);
  };

  const openEndpointEdit = (endpoint: Endpoint) => {
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

  const removeEndpoint = async (endpointId: string) => {
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

  const importEndpointsFromSwaggerFile = async (file: File | null) => {
    if (!file || !projectId || !hostId) {
      return;
    }
    setSwaggerImporting(true);
    setError(null);
    setInfoMessage(null);
    try {
      const rawText = await file.text();
      let parsedSpec: unknown;
      const lowerCaseName = file.name.toLowerCase();
      const looksLikeYaml = lowerCaseName.endsWith(".yaml") || lowerCaseName.endsWith(".yml");
      try {
        parsedSpec = looksLikeYaml ? parseYaml(rawText) : JSON.parse(rawText);
      } catch {
        if (!looksLikeYaml) {
          try {
            parsedSpec = parseYaml(rawText);
          } catch {
            throw new Error("Swagger/OpenAPI файл должен быть валидным JSON или YAML.");
          }
        } else {
          throw new Error("Swagger/OpenAPI YAML файл невалиден.");
        }
      }
      if (!parsedSpec || typeof parsedSpec !== "object") {
        throw new Error("Некорректный Swagger/OpenAPI документ.");
      }
      const paths = (parsedSpec as { paths?: Record<string, Record<string, Record<string, unknown>>> }).paths;
      if (!paths || typeof paths !== "object") {
        throw new Error("В Swagger/OpenAPI документе отсутствует объект paths.");
      }
      const methodOrder = ["get", "post", "put", "patch", "delete", "head", "options"] as const;
      const operations: Array<{ method: Exclude<Endpoint["method"], null>; path: string; description?: string }> = [];
      Object.entries(paths).forEach(([pathValue, pathItem]) => {
        if (!pathItem || typeof pathItem !== "object") {
          return;
        }
        methodOrder.forEach((methodName) => {
          const operation = pathItem[methodName];
          if (!operation || typeof operation !== "object") {
            return;
          }
          const opInfo = operation as { summary?: string; description?: string };
          const combinedDescription = [opInfo.summary, opInfo.description].filter(Boolean).join("\n\n");
          operations.push({
            method: methodName.toUpperCase() as Exclude<Endpoint["method"], null>,
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
        } catch {
          failed += 1;
        }
      }
      await loadHost();
      setInfoMessage(`Swagger импорт завершен: добавлено ${created}, пропущено ${skipped}, ошибок ${failed}.`);
    } catch (importError) {
      setError(importError instanceof Error ? importError.message : "Не удалось импортировать Swagger/OpenAPI.");
    } finally {
      setSwaggerImporting(false);
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

  const removeVulnerability = async (vulnerabilityId: string) => {
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

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" py={6}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Stack spacing={2.5}>
      {error && <Alert severity="error">{error}</Alert>}
      {infoMessage && <Alert severity="success">{infoMessage}</Alert>}

      <Stack direction="row" justifyContent="space-between" alignItems="center" flexWrap="wrap" gap={1}>
        <Stack spacing={0.2}>
          <Typography variant="h4" fontWeight={700}>
            Хост: {hostTitle}
          </Typography>
        </Stack>
        <IconButton onClick={openHostActionsMenu} sx={{ border: "1px solid rgba(126,224,255,0.2)", borderRadius: 2 }}>
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

      <Stack direction={{ xs: "column", md: "row" }} spacing={2}>
        <ProjectTreeNav
          hosts={hosts}
          selectedHostId={hostId ?? null}
          selectedSection={selectedSection}
          isCollapsed={isSidebarCollapsed}
          portsCount={portsCount}
          endpointsCount={endpointsCount}
          vulnerabilitiesCount={vulnerabilitiesCount}
          hostStatsById={hostStatsById}
          onToggleCollapsed={() => setSidebarCollapsed((v) => !v)}
          onSelectSection={setSelectedSection}
          onSelectProjectOverview={() => navigate(`/projects/${projectId}`)}
          onSelectHost={(nextHostId) => navigate(`/projects/${projectId}/hosts/${nextHostId}`)}
          onOpenHost={(nextHostId) => navigate(`/projects/${projectId}/hosts/${nextHostId}`)}
        />

        <Stack flex={1} spacing={2}>
          <Grid container spacing={2}>
            <Grid size={{ xs: 12, md: 4 }}>
              <Card
                onClick={() => setSelectedSection("ports")}
                sx={{
                  cursor: "pointer",
                  border: selectedSection === "ports" ? "1px solid rgba(126,224,255,0.45)" : "1px solid rgba(126,224,255,0.16)",
                  borderRadius: 0,
                }}
              >
                <CardContent>
                  <Typography color="text.secondary">Портов хоста</Typography>
                  <Typography variant="h4" fontWeight={700}>
                    {portsCount}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <Card
                onClick={() => setSelectedSection("endpoints")}
                sx={{
                  cursor: "pointer",
                  border: selectedSection === "endpoints" ? "1px solid rgba(126,224,255,0.45)" : "1px solid rgba(126,224,255,0.16)",
                  borderRadius: 0,
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
                onClick={() => setSelectedSection("vulns")}
                sx={{
                  cursor: "pointer",
                  border: selectedSection === "vulns" ? "1px solid rgba(126,224,255,0.45)" : "1px solid rgba(126,224,255,0.16)",
                  borderRadius: 0,
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
              <Card sx={{ border: "1px solid rgba(126,224,255,0.16)", borderRadius: 0 }}>
                <CardContent>
                  <Typography variant="h6" fontWeight={700} mb={1}>
                    Описание хоста
                  </Typography>
                  <Box sx={{ border: "1px solid rgba(126,224,255,0.12)", p: 1.5, borderRadius: 0 }}>
                    <ReactMarkdown>{host?.notes || "_Описание хоста не заполнено_"}</ReactMarkdown>
                  </Box>
                </CardContent>
              </Card>
            </Stack>
          )}

          {selectedSection === "ports" && (
            <Card sx={{ border: "1px solid rgba(126,224,255,0.16)", borderRadius: 0 }}>
              <CardContent>
                <Stack direction="row" alignItems="center" justifyContent="space-between" mb={1}>
                  <Typography variant="h6" fontWeight={700}>
                    Порты
                  </Typography>
                  <Tooltip title="Добавить порт">
                    <IconButton size="small" onClick={() => setCreatePortOpen(true)}>
                      <AddIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                </Stack>
                <Stack spacing={1}>
                  {host?.ports.map((port) => (
                    <Stack
                      key={port.id}
                      onClick={() => toggleExpandedId(port.id, setExpandedPortIds)}
                      sx={{
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
                      }}
                    >
                      <Stack direction="row" justifyContent="space-between" alignItems="center">
                        <Stack direction="row" spacing={1} alignItems="center">
                          <Typography fontWeight={600}>
                            {port.port_number}/{port.protocol}
                          </Typography>
                          <Chip label={port.state} size="small" />
                        </Stack>
                        <Stack direction="row" spacing={0.4} className="port-actions">
                          <Tooltip title="Действия">
                            <IconButton size="small" onClick={(event) => openPortActions(event, port)}>
                              <MoreVertIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        </Stack>
                      </Stack>
                      <Collapse in={expandedPortIds.includes(port.id)} timeout="auto" unmountOnExit>
                        <Stack mt={1} spacing={1}>
                          <Typography color="text.secondary" variant="body2">
                            Порт {port.port_number}/{port.protocol} сейчас в состоянии {port.state}.
                          </Typography>
                          <Stack direction="row" justifyContent="space-between" alignItems="center">
                            <Typography variant="body2" fontWeight={600}>
                              Сервисы
                            </Typography>
                            <Tooltip title="Добавить сервис">
                              <IconButton
                                size="small"
                                onClick={(event) => {
                                  event.stopPropagation();
                                  openCreateServiceDialog(port.id);
                                }}
                              >
                                <AddIcon fontSize="small" />
                              </IconButton>
                            </Tooltip>
                          </Stack>
                          <Stack spacing={0.8}>
                            {(servicesByPortId[port.id] ?? []).map((service) => (
                              <Stack
                                key={service.id}
                                direction="row"
                                justifyContent="space-between"
                                alignItems="center"
                                sx={{ border: "1px solid rgba(126,224,255,0.12)", p: 0.8, borderRadius: 0 }}
                              >
                                <Stack spacing={0.2}>
                                  <Typography variant="body2" fontWeight={600}>
                                    {service.name}
                                  </Typography>
                                  <Typography variant="caption" color="text.secondary">
                                    {service.version || "version n/a"}
                                  </Typography>
                                </Stack>
                                <Stack direction="row" spacing={0.4}>
                                  <Tooltip title="Редактировать сервис">
                                    <IconButton
                                      size="small"
                                      onClick={(event) => {
                                        event.stopPropagation();
                                        openEditServiceDialog(port.id, service);
                                      }}
                                    >
                                      <EditIcon fontSize="small" />
                                    </IconButton>
                                  </Tooltip>
                                  <Tooltip title="Удалить сервис">
                                    <IconButton
                                      size="small"
                                      color="error"
                                      onClick={(event) => {
                                        event.stopPropagation();
                                        void removeService(port.id, service.id);
                                      }}
                                    >
                                      <DeleteIcon fontSize="small" />
                                    </IconButton>
                                  </Tooltip>
                                </Stack>
                              </Stack>
                            ))}
                            {(servicesByPortId[port.id] ?? []).length === 0 && (
                              <Typography variant="caption" color="text.secondary">
                                Сервисы на порту пока не добавлены.
                              </Typography>
                            )}
                          </Stack>
                        </Stack>
                      </Collapse>
                    </Stack>
                  ))}
                  {!host?.ports.length && <Typography color="text.secondary">Порты для этого хоста пока не добавлены.</Typography>}
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
                    Редактировать
                  </MenuItem>
                  <MenuItem
                    onClick={() => {
                      if (activePort) {
                        void removePort(activePort.id);
                      }
                      closePortActions();
                    }}
                  >
                    <DeleteIcon fontSize="small" sx={{ mr: 1 }} />
                    Удалить
                  </MenuItem>
                </Menu>
              </CardContent>
            </Card>
          )}

          {selectedSection === "endpoints" && (
            <Card sx={{ border: "1px solid rgba(126,224,255,0.16)", borderRadius: 0 }}>
              <CardContent>
                <Stack direction="row" alignItems="center" justifyContent="space-between" mb={1}>
                  <Typography variant="h6" fontWeight={700}>
                    Эндпоинты
                  </Typography>
                  <Stack direction="row" spacing={0.5}>
                    <Tooltip title="Импортировать из Swagger/OpenAPI (JSON/YAML)">
                      <IconButton size="small" component="label" disabled={swaggerImporting}>
                        <UploadFileIcon fontSize="small" />
                        <input
                          hidden
                          type="file"
                          accept="application/json,.json,.yaml,.yml,text/yaml,application/yaml"
                          onChange={(event) => {
                            const selectedFile = event.target.files?.[0] ?? null;
                            void importEndpointsFromSwaggerFile(selectedFile);
                            event.target.value = "";
                          }}
                        />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Добавить эндпоинт">
                      <IconButton size="small" onClick={() => setCreateEndpointOpen(true)}>
                        <AddIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  </Stack>
                </Stack>
                <Stack spacing={1}>
                  {host?.endpoints.map((endpoint) => (
                    <Box
                      key={endpoint.id}
                      onClick={() => toggleExpandedId(endpoint.id, setExpandedEndpointIds)}
                      sx={{
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
                      }}
                    >
                      <Stack direction="row" spacing={1} alignItems="center" justifyContent="space-between">
                        <Stack direction="row" spacing={1} alignItems="center">
                          <Chip size="small" label={endpoint.method || "ANY"} />
                          <Typography fontWeight={600}>{endpoint.path}</Typography>
                        </Stack>
                        <Stack direction="row" spacing={0.4} className="endpoint-actions">
                          <Tooltip title="Действия">
                            <IconButton size="small" onClick={(event) => openEndpointActions(event, endpoint)}>
                              <MoreVertIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        </Stack>
                      </Stack>
                      <Collapse in={expandedEndpointIds.includes(endpoint.id)} timeout="auto" unmountOnExit>
                        <Typography mt={0.8} color="text.secondary" variant="body2">
                          {endpoint.description || "Описание не указано"}
                        </Typography>
                      </Collapse>
                    </Box>
                  ))}
                  {!host?.endpoints.length && <Typography color="text.secondary">Эндпоинты для этого хоста пока не добавлены.</Typography>}
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

          {selectedSection === "vulns" && (
            <Card sx={{ border: "1px solid rgba(126,224,255,0.16)", borderRadius: 0 }}>
              <CardContent>
                <Stack direction="row" alignItems="center" justifyContent="space-between" mb={1}>
                  <Typography variant="h6" fontWeight={700}>
                    Уязвимости хоста
                  </Typography>
                  <Tooltip title="Добавить уязвимость">
                    <IconButton size="small" onClick={() => setCreateVulnerabilityOpen(true)}>
                      <AddIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                </Stack>
                <Stack spacing={1}>
                  {vulnerabilities.map((item) => (
                    <Box
                      key={item.id}
                      onClick={() => toggleExpandedId(item.id, setExpandedVulnerabilityIds)}
                      sx={{
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
                      }}
                    >
                      <Stack direction="row" justifyContent="space-between" alignItems="center">
                        <Stack spacing={0.8}>
                          <Typography fontWeight={600}>{item.title}</Typography>
                          <Stack direction="row" spacing={1}>
                            <Chip size="small" label={item.severity} sx={severityChipSx[item.severity]} />
                            <Chip size="small" label={item.status} sx={vulnerabilityStatusChipSx[item.status]} />
                          </Stack>
                        </Stack>
                        <Stack direction="row" spacing={0.4} alignItems="center" className="vuln-actions">
                          <Tooltip title="Действия">
                            <IconButton size="small" onClick={(event) => openVulnerabilityActions(event, item)}>
                              <MoreVertIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        </Stack>
                      </Stack>
                      <Collapse in={expandedVulnerabilityIds.includes(item.id)} timeout="auto" unmountOnExit>
                        <Typography mt={0.8} color="text.secondary" variant="body2">
                          {item.description || "Описание не указано"}
                        </Typography>
                      </Collapse>
                    </Box>
                  ))}
                  {!vulnerabilities.length && <Typography color="text.secondary">Уязвимости, привязанные к этому хосту, пока не добавлены.</Typography>}
                </Stack>
                <Menu
                  anchorEl={vulnerabilityActionsAnchorEl}
                  open={vulnerabilityActionsOpen}
                  onClose={closeVulnerabilityActions}
                  anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
                  transformOrigin={{ vertical: "top", horizontal: "right" }}
                >
                  <MenuItem
                    onClick={() => {
                      if (activeVulnerability) {
                        openVulnerabilityEdit(activeVulnerability);
                      }
                      closeVulnerabilityActions();
                    }}
                  >
                    <EditIcon fontSize="small" sx={{ mr: 1 }} />
                    Редактировать
                  </MenuItem>
                  <MenuItem
                    onClick={() => {
                      if (activeVulnerability) {
                        void removeVulnerability(activeVulnerability.id);
                      }
                      closeVulnerabilityActions();
                    }}
                  >
                    <DeleteIcon fontSize="small" sx={{ mr: 1 }} />
                    Удалить
                  </MenuItem>
                </Menu>
              </CardContent>
            </Card>
          )}
        </Stack>
      </Stack>

      <Dialog open={isEditHostOpen} onClose={() => setEditHostOpen(false)} fullWidth>
        <DialogTitle>Редактировать хост</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField label="IP-адрес" value={editingHostIp} onChange={(event) => setEditingHostIp(event.target.value)} />
            <TextField label="Hostname" value={editingHostName} onChange={(event) => setEditingHostName(event.target.value)} />
            <TextField select label="Статус" value={editingHostStatus} onChange={(event) => setEditingHostStatus(event.target.value as Host["status"])}>
              <MenuItem value="up">up</MenuItem>
              <MenuItem value="down">down</MenuItem>
              <MenuItem value="unknown">unknown</MenuItem>
            </TextField>
            <TextField
              multiline
              minRows={4}
              label="Описание"
              value={editingHostNotes}
              onChange={(event) => setEditingHostNotes(event.target.value)}
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditHostOpen(false)}>Отмена</Button>
          <Button variant="contained" onClick={() => void saveHostInfo()} disabled={!editingHostIp.trim() && !editingHostName.trim()}>
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
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreatePortOpen(false)}>Отмена</Button>
          <Button variant="contained" onClick={() => void createHostPort()}>
            Создать
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={isCreateServiceOpen} onClose={() => setCreateServiceOpen(false)} fullWidth>
        <DialogTitle>Добавить сервис</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField label="Название сервиса" value={creatingServiceName} onChange={(event) => setCreatingServiceName(event.target.value)} />
            <TextField label="Версия" value={creatingServiceVersion} onChange={(event) => setCreatingServiceVersion(event.target.value)} />
            <TextField multiline minRows={3} label="Banner" value={creatingServiceBanner} onChange={(event) => setCreatingServiceBanner(event.target.value)} />
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
            <TextField multiline minRows={3} label="Banner" value={editingServiceBanner} onChange={(event) => setEditingServiceBanner(event.target.value)} />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditServiceOpen(false)}>Отмена</Button>
          <Button variant="contained" onClick={() => void saveServiceEdit()} disabled={!editingServiceName.trim()}>
            Сохранить
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={isEditEndpointOpen} onClose={() => setEditEndpointOpen(false)} fullWidth>
        <DialogTitle>Редактировать эндпоинт</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField
              multiline
              minRows={6}
              label="Raw HTTP request (опционально)"
              placeholder={"POST /api/login HTTP/1.1\nHost: target.local\nContent-Type: application/json\n\n{\"user\":\"admin\"}"}
              value={editingEndpointRequestRaw}
              onChange={(event) => applyParsedRequestToEditEndpoint(event.target.value)}
            />
            <TextField label="Путь" value={editingEndpointPath} onChange={(event) => setEditingEndpointPath(event.target.value)} />
            <TextField
              select
              label="HTTP-метод"
              value={editingEndpointMethod}
              onChange={(event) => setEditingEndpointMethod(event.target.value as Exclude<Endpoint["method"], null>)}
            >
              {["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map((method) => (
                <MenuItem key={method} value={method}>
                  {method}
                </MenuItem>
              ))}
            </TextField>
            <TextField
              multiline
              minRows={3}
              label="Описание"
              value={editingEndpointDescription}
              onChange={(event) => setEditingEndpointDescription(event.target.value)}
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditEndpointOpen(false)}>Отмена</Button>
          <Button variant="contained" onClick={() => void saveEndpointEdit()} disabled={!editingEndpointPath.trim()}>
            Сохранить
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={isCreateEndpointOpen} onClose={() => setCreateEndpointOpen(false)} fullWidth>
        <DialogTitle>Добавить эндпоинт</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField
              multiline
              minRows={6}
              label="Raw HTTP request (опционально)"
              placeholder={"POST /api/login HTTP/1.1\nHost: target.local\nContent-Type: application/json\n\n{\"user\":\"admin\"}"}
              value={creatingEndpointRequestRaw}
              onChange={(event) => applyParsedRequestToCreateEndpoint(event.target.value)}
            />
            <TextField label="Путь" value={creatingEndpointPath} onChange={(event) => setCreatingEndpointPath(event.target.value)} />
            <TextField
              select
              label="HTTP-метод"
              value={creatingEndpointMethod}
              onChange={(event) => setCreatingEndpointMethod(event.target.value as Exclude<Endpoint["method"], null>)}
            >
              {["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map((method) => (
                <MenuItem key={method} value={method}>
                  {method}
                </MenuItem>
              ))}
            </TextField>
            <TextField
              multiline
              minRows={3}
              label="Описание"
              value={creatingEndpointDescription}
              onChange={(event) => setCreatingEndpointDescription(event.target.value)}
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateEndpointOpen(false)}>Отмена</Button>
          <Button
            variant="contained"
            onClick={() => void createHostEndpoint()}
            disabled={!creatingEndpointPath.trim() && !creatingEndpointRequestRaw.trim()}
          >
            Создать
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={isEditVulnerabilityOpen} onClose={() => setEditVulnerabilityOpen(false)} fullWidth>
        <DialogTitle>Редактировать уязвимость</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField label="Название" value={editingVulnerabilityTitle} onChange={(event) => setEditingVulnerabilityTitle(event.target.value)} />
            <TextField
              multiline
              minRows={3}
              label="Описание"
              value={editingVulnerabilityDescription}
              onChange={(event) => setEditingVulnerabilityDescription(event.target.value)}
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

      <Dialog open={isCreateVulnerabilityOpen} onClose={() => setCreateVulnerabilityOpen(false)} fullWidth>
        <DialogTitle>Добавить уязвимость к хосту</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField
              label="Название"
              value={creatingVulnerabilityTitle}
              onChange={(event) => setCreatingVulnerabilityTitle(event.target.value)}
            />
            <TextField
              multiline
              minRows={3}
              label="Описание"
              value={creatingVulnerabilityDescription}
              onChange={(event) => setCreatingVulnerabilityDescription(event.target.value)}
            />
            <TextField
              select
              label="Критичность"
              value={creatingVulnerabilitySeverity}
              onChange={(event) => setCreatingVulnerabilitySeverity(event.target.value as Vulnerability["severity"])}
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
              value={creatingVulnerabilityStatus}
              onChange={(event) => setCreatingVulnerabilityStatus(event.target.value as Vulnerability["status"])}
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
          <Button onClick={() => setCreateVulnerabilityOpen(false)}>Отмена</Button>
          <Button variant="contained" onClick={() => void createHostVulnerability()} disabled={!creatingVulnerabilityTitle.trim()}>
            Создать
          </Button>
        </DialogActions>
      </Dialog>
    </Stack>
  );
}
