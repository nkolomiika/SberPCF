import AddIcon from "@mui/icons-material/Add";
import AccessTimeIcon from "@mui/icons-material/AccessTime";
import CloseIcon from "@mui/icons-material/Close";
import DeleteOutlineIcon from "@mui/icons-material/DeleteOutline";
import DownloadIcon from "@mui/icons-material/Download";
import EditIcon from "@mui/icons-material/Edit";
import FlagIcon from "@mui/icons-material/Flag";
import MoreVertIcon from "@mui/icons-material/MoreVert";
import UploadFileIcon from "@mui/icons-material/UploadFile";
import {
  Avatar,
  Box,
  Button,
  Card,
  CardContent,
  Checkbox,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  Grid2 as Grid,
  IconButton,
  List,
  ListItem,
  ListItemText,
  Menu,
  MenuItem,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { Fragment, useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import ReactMarkdown from "react-markdown";
import { useNavigate, useParams } from "react-router-dom";
import { MarkdownEditor } from "../components/MarkdownEditor";
import { MarkdownImage } from "../components/MarkdownImage";
import { MarkdownOutlinedReadonlyField } from "../components/MarkdownOutlinedReadonlyField";
import { markdownUrlTransform, normalizeMarkdownForRender } from "../markdownUrlTransform";
import {
  createHost,
  createProjectNote,
  createVulnerabilityComment,
  deleteHost,
  deleteProjectNote,
  addProjectMember,
  deleteVulnerabilityComment,
  downloadProjectAcceptanceReport,
  downloadProjectCertificationReport,
  getApiErrorMessage,
  getEndpoints,
  getHostVulnerabilities,
  getHosts,
  getPorts,
  getServices,
  getProjectMembers,
  getUsers,
  getProject,
  getVulnerabilities,
  getVulnerability,
  importProjectData,
  listProjectNotes,
  listVulnerabilityComments,
  moveProjectNote,
  removeProjectMember,
  reorderProjectNotes,
  updateProject,
  updateProjectNote,
  updateVulnerabilityComment,
  updateVulnerability,
  uploadVulnerabilityFile,
} from "../api";
import { calculateCvssScore, severityFromCvssScore } from "../cvss";
import { PROJECT_STATUS_CHIP_SX, PROJECT_STATUS_LABELS, PROJECT_STATUS_ORDER } from "../projectStatus";
import { ProjectNotesSection } from "../components/ProjectNotesSection";
import { ProjectTreeNav, type DetailSection } from "../components/ProjectTreeNav";
import { VulnerabilityStagesEditor } from "../components/VulnerabilityStagesEditor";
import { useAuthStore } from "../store";
import type {
  Endpoint,
  Host,
  HostTreeStats,
  ImportResult,
  Port,
  ProjectMember,
  ProjectNote,
  ProjectStatus,
  User,
  Vulnerability,
  VulnerabilityComment,
  VulnerabilityDetails,
} from "../types";
import { useErrorToast } from "../useErrorToast";

const SEVERITY_LABELS_RU: Record<Vulnerability["severity"], string> = {
  critical: "Критическая",
  high: "Высокая",
  medium: "Средняя",
  low: "Низкая",
  info: "Инфо",
};

const SEVERITY_ORDER: Vulnerability["severity"][] = ["critical", "high", "medium", "low", "info"];

const DAY_IN_MS = 24 * 60 * 60 * 1000;
const CVSS_VERSION = "4.0" as const;
const UUID_PATH_SEGMENT_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const normalizeEndpointDisplayPath = (pathValue: string): string => {
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

const dedupeEndpointsByNormalizedPath = (endpoints: Endpoint[]): Endpoint[] => {
  const deduped = new Map<string, Endpoint>();
  for (const endpoint of endpoints) {
    const normalizedPath = normalizeEndpointDisplayPath(endpoint.path);
    const key = `${(endpoint.method || "GET").toUpperCase()} ${normalizedPath}`;
    const candidate = { ...endpoint, path: normalizedPath };
    const existing = deduped.get(key);
    deduped.set(
      key,
      existing
        ? {
            ...existing,
            description: existing.description || candidate.description,
            query_params: existing.query_params?.length ? existing.query_params : candidate.query_params,
            request_body: existing.request_body || candidate.request_body,
            request_content_type: existing.request_content_type || candidate.request_content_type,
            request_headers: existing.request_headers?.length ? existing.request_headers : candidate.request_headers,
          }
        : candidate
    );
  }
  return Array.from(deduped.values());
};

const toDateInputValue = (date: Date) => {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
};

const parseIsoDateOnly = (value: string | null) => {
  if (!value) {
    return null;
  }
  const parsed = new Date(`${value}T00:00:00`);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
};

const parseIsoDateTimeToDateOnly = (value: string | null) => {
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
  const { projectId } = useParams<{ projectId: string }>();
  const navigate = useNavigate();
  const user = useAuthStore((s) => s.user);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [ports, setPorts] = useState<Port[]>([]);
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const normalizedEndpoints = useMemo(() => dedupeEndpointsByNormalizedPath(endpoints), [endpoints]);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [projectVulnerabilities, setProjectVulnerabilities] = useState<Vulnerability[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [selectedHostId, setSelectedHostId] = useState<string | null>(null);
  const [selectedSection, setSelectedSection] = useState<DetailSection>("overview");
  const [isSidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [projectNotes, setProjectNotes] = useState<ProjectNote[]>([]);
  const [selectedNoteId, setSelectedNoteId] = useState<string | null>(null);
  const [projectName, setProjectName] = useState<string>("");
  const [projectDescription, setProjectDescription] = useState<string>("");
  const [projectStatus, setProjectStatus] = useState<ProjectStatus>("active");
  const [projectStartDate, setProjectStartDate] = useState<string | null>(null);
  const [projectEndDate, setProjectEndDate] = useState<string | null>(null);
  const [projectTimelineFrozenAt, setProjectTimelineFrozenAt] = useState<string | null>(null);
  const [projectMembers, setProjectMembers] = useState<ProjectMember[]>([]);
  const [usersCatalog, setUsersCatalog] = useState<User[]>([]);
  const [membersDialogOpen, setMembersDialogOpen] = useState(false);
  const [removeMembersDialogOpen, setRemoveMembersDialogOpen] = useState(false);
  const [selectedAvailableMemberIds, setSelectedAvailableMemberIds] = useState<string[]>([]);
  const [memberSearchQuery, setMemberSearchQuery] = useState("");
  const [selectedMemberIds, setSelectedMemberIds] = useState<string[]>([]);
  const [membersBusy, setMembersBusy] = useState(false);
  const [hostStatsById, setHostStatsById] = useState<Record<string, HostTreeStats>>({});
  const [importOpen, setImportOpen] = useState(false);
  const [importFile, setImportFile] = useState<File | null>(null);
  const [importing, setImporting] = useState(false);
  const [importSummary, setImportSummary] = useState<ImportResult | null>(null);
  const [reportLoadingKind, setReportLoadingKind] = useState<"szi" | "pp" | null>(null);
  const [actionsAnchorEl, setActionsAnchorEl] = useState<HTMLElement | null>(null);
  const [hostsMenuAnchorEl, setHostsMenuAnchorEl] = useState<HTMLElement | null>(null);
  const [membersMenuAnchorEl, setMembersMenuAnchorEl] = useState<HTMLElement | null>(null);
  const [exportOpen, setExportOpen] = useState(false);
  const [exportReportKind, setExportReportKind] = useState<"szi" | "pp">("szi");
  const [extendDialogOpen, setExtendDialogOpen] = useState(false);
  const [statusDialogOpen, setStatusDialogOpen] = useState(false);
  const [projectEditDialogOpen, setProjectEditDialogOpen] = useState(false);
  const [projectDescriptionEditOpen, setProjectDescriptionEditOpen] = useState(false);
  const [projectDraftName, setProjectDraftName] = useState("");
  const [projectDraftStartDate, setProjectDraftStartDate] = useState("");
  const [projectDraftEndDate, setProjectDraftEndDate] = useState("");
  const [projectDraftDescription, setProjectDraftDescription] = useState("");
  const [projectSaving, setProjectSaving] = useState(false);
  const [pendingProjectStatus, setPendingProjectStatus] = useState<ProjectStatus>("active");
  const [extendEndDate, setExtendEndDate] = useState("");
  const [extendingProject, setExtendingProject] = useState(false);
  const storagePrefix = projectId ? `project-detail:${projectId}` : null;

  const [hostOpen, setHostOpen] = useState(false);
  const [removeHostsDialogOpen, setRemoveHostsDialogOpen] = useState(false);
  const [selectedHostIds, setSelectedHostIds] = useState<string[]>([]);
  const [hostIp, setHostIp] = useState("");
  const [hostName, setHostName] = useState("");
  const [hostNotes, setHostNotes] = useState("");
  const [vulnDetailOpen, setVulnDetailOpen] = useState(false);
  const [activeVuln, setActiveVuln] = useState<VulnerabilityDetails | null>(null);
  const [vulnComments, setVulnComments] = useState<VulnerabilityComment[]>([]);
  const [newComment, setNewComment] = useState("");
  const [vulnBusy, setVulnBusy] = useState(false);
  const [vulnEditMode, setVulnEditMode] = useState(false);
  const [editCommentOpen, setEditCommentOpen] = useState(false);
  const [editingCommentId, setEditingCommentId] = useState<string | null>(null);
  const [editingCommentContent, setEditingCommentContent] = useState("");
  const [commentActionsAnchorEl, setCommentActionsAnchorEl] = useState<HTMLElement | null>(null);
  const [activeComment, setActiveComment] = useState<VulnerabilityComment | null>(null);

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
      .sort(
        (left, right) =>
          Number(right.inProject) - Number(left.inProject) || left.username.localeCompare(right.username, "ru-RU")
      );
  }, [memberSearchQuery, projectMembers, usersCatalog]);

  const loadProjectData = useCallback(async () => {
    if (!projectId) {
      return;
    }
    try {
      const [hostsResp, projectResp, membersResp, vulnsPage] = await Promise.all([
        getHosts(projectId),
        getProject(projectId),
        getProjectMembers(projectId),
        getVulnerabilities(projectId),
      ]);
      setHosts(hostsResp.items);
      setProjectMembers(membersResp);
      setProjectName(projectResp.name ?? projectId);
      setProjectDescription(projectResp.description ?? "");
      setProjectStatus(projectResp.status);
      setProjectStartDate(projectResp.start_date);
      setProjectEndDate(projectResp.end_date);
      setProjectTimelineFrozenAt(projectResp.timeline_frozen_at);
      setProjectVulnerabilities(vulnsPage.items);
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
    } catch (error) {
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
    } catch (error) {
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
      const statsEntries = await Promise.allSettled(
        hosts.map(async (host) => {
          if (host.id === selectedHostId) {
            return [
              host.id,
              {
                portsCount: ports.length,
                endpointsCount: endpoints.length,
                vulnerabilitiesCount: vulnerabilities.length,
              },
            ] as const;
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
    const storedSection = window.localStorage.getItem(`${storagePrefix}:selectedSection`) as DetailSection | null;
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
  const projectSeverityStats = useMemo(() => {
    const stats = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    projectVulnerabilities.forEach((item) => {
      stats[item.severity] += 1;
    });
    return stats;
  }, [projectVulnerabilities]);
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
        daysLeft: null as number | null,
        statusTone: "neutral" as "neutral" | "success" | "warning" | "error",
        statusLabel:
          projectStatus === "active" ? "Стандартный срок: 14 дней" : `Статус: ${PROJECT_STATUS_LABELS[projectStatus]}`,
      };
    }

    if (projectStatus !== "active") {
      return {
        startLabel: start.toLocaleDateString("ru-RU"),
        endLabel: end.toLocaleDateString("ru-RU"),
        daysLeft: null as number | null,
        statusTone: "neutral" as const,
        statusLabel: `Статус: ${PROJECT_STATUS_LABELS[projectStatus]}`,
      };
    }

    const daysLeft = Math.ceil((end.getTime() - today.getTime()) / DAY_IN_MS);
    if (daysLeft < 0) {
      return {
        startLabel: start.toLocaleDateString("ru-RU"),
        endLabel: end.toLocaleDateString("ru-RU"),
        daysLeft,
        statusTone: "error" as const,
        statusLabel: "Просрочен",
      };
    }
    if (daysLeft <= 2) {
      return {
        startLabel: start.toLocaleDateString("ru-RU"),
        endLabel: end.toLocaleDateString("ru-RU"),
        daysLeft,
        statusTone: "warning" as const,
        statusLabel: "Отчёт: последние 2 дня",
      };
    }
    return {
      startLabel: start.toLocaleDateString("ru-RU"),
      endLabel: end.toLocaleDateString("ru-RU"),
      daysLeft,
      statusTone: "success" as const,
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
    const effectiveToday =
      projectStatus === "active" ? today : new Date(Math.min(frozenAt.getTime(), end?.getTime() ?? frozenAt.getTime()));

    if (!start || !end || end.getTime() <= start.getTime()) {
      return {
        ready: false as const,
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
      } else if (isElapsed) {
        bgColor = "rgba(76,175,80,0.5)";
      } else if (isReportWindow) {
        bgColor = "rgba(255,152,0,0.2)";
      }
      return { bgColor, isToday };
    });

    return {
      ready: true as const,
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

  const loadVulnerabilityDetails = async (vulnerabilityId: string) => {
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
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось загрузить карточку уязвимости"));
    } finally {
      setVulnBusy(false);
    }
  };

  const saveActiveVulnerability = async () => {
    if (!projectId || !activeVuln) {
      return;
    }
    const workflowSteps = activeVuln.workflow_steps || [];
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
        workflow_steps: workflowSteps,
        steps_to_reproduce: activeVuln.steps_to_reproduce || null,
        impact: activeVuln.impact || null,
        recommendations: activeVuln.recommendations || null,
      });
      setActiveVuln((prev) => (prev ? { ...prev, ...updated } : prev));
      setVulnEditMode(false);
      await loadHostAssets();
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось сохранить уязвимость"));
    } finally {
      setVulnBusy(false);
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

  const addCommentToActiveVuln = async () => {
    if (!projectId || !activeVuln || !newComment.trim()) {
      return;
    }
    setVulnBusy(true);
    try {
      const created = await createVulnerabilityComment(projectId, activeVuln.id, newComment.trim());
      setVulnComments((prev) => [...prev, created]);
      setNewComment("");
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось добавить комментарий"));
    } finally {
      setVulnBusy(false);
    }
  };

  const removeCommentFromActiveVuln = async (commentId: string) => {
    if (!projectId || !activeVuln) {
      return;
    }
    setVulnBusy(true);
    try {
      await deleteVulnerabilityComment(projectId, activeVuln.id, commentId);
      setVulnComments((prev) => prev.filter((comment) => comment.id !== commentId));
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось удалить комментарий"));
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
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось обновить комментарий"));
    } finally {
      setVulnBusy(false);
    }
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

  const renderCommentsSection = () => (
    <Stack spacing={1.25}>
      <Typography variant="subtitle1" fontWeight={700}>
        Комментарии ({vulnComments.length})
      </Typography>
      <List dense disablePadding>
        {vulnComments.map((comment, commentIndex) => {
          const canManageComment = user?.id === comment.user_id;
          return (
            <Fragment key={comment.id}>
              <ListItem
                alignItems="flex-start"
                sx={{
                  mb: 0,
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
              {commentIndex < vulnComments.length - 1 ? (
                <Divider
                  component="li"
                  sx={{
                    my: 2.25,
                    borderColor: "rgba(126,224,255,0.2)",
                    borderBottomWidth: 2,
                    listStyle: "none",
                  }}
                />
              ) : null}
            </Fragment>
          );
        })}
        {vulnComments.length === 0 && <Typography color="text.secondary">Комментариев пока нет.</Typography>}
      </List>
      <TextField
        label="Комментарий"
        multiline
        minRows={3}
        value={newComment}
        onChange={(e) => setNewComment(e.target.value)}
        sx={{ "& .MuiInputBase-input": { color: "#ffffff" } }}
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

  const renderMarkdownPreview = (value: string | null | undefined, emptyText: string, title?: string) => {
    if (title) {
      const inputId =
        title === "Влияние"
          ? "project-detail-vuln-impact"
          : title === "Рекомендации"
            ? "project-detail-vuln-recommendations"
            : `project-detail-md-${title.replace(/\s+/g, "-").toLowerCase()}`;
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
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось импортировать JSON-данные проекта"));
    } finally {
      setImporting(false);
    }
  };

  const downloadReport = async (kind: "szi" | "pp") => {
    if (!projectId) {
      return;
    }
    setReportLoadingKind(kind);
    setError(null);
    try {
      const blob =
        kind === "szi" ? await downloadProjectCertificationReport(projectId) : await downloadProjectAcceptanceReport(projectId);
      const fileNameBase = (projectName || "project-report").replace(/[^\w.-]+/g, "_");
      const suffix = kind === "szi" ? "szi" : "pp";
      const objectUrl = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = objectUrl;
      anchor.download = `${fileNameBase}_${suffix}.docx`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(objectUrl);
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось сформировать отчёт"));
    } finally {
      setReportLoadingKind(null);
    }
  };
  const actionsMenuOpen = Boolean(actionsAnchorEl);

  const openActionsMenu = (event: React.MouseEvent<HTMLElement>) => {
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

  const MAX_PROJECT_DESC_IMAGE_BYTES = 1_500_000;

  const appendImageToProjectDraft = (file: File | null) => {
    if (!file?.type.startsWith("image/")) {
      return;
    }
    if (file.size > MAX_PROJECT_DESC_IMAGE_BYTES) {
      setError("Изображение слишком большое (макс. ~1.5 МБ).");
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      const dataUrl = typeof reader.result === "string" ? reader.result : "";
      if (!dataUrl) {
        return;
      }
      const name = file.name.replace(/[^\w.-]/g, "_") || "image";
      setProjectDraftDescription((prev) => `${prev.trimEnd()}\n\n![${name}](${dataUrl})\n`);
    };
    reader.readAsDataURL(file);
  };

  const applyQuickExtension = (days: number) => {
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
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось продлить срок проекта"));
    } finally {
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
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось обновить проект"));
    } finally {
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
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось обновить описание проекта"));
    } finally {
      setProjectSaving(false);
    }
  };

  const updateProjectStatus = async (nextStatus: ProjectStatus) => {
    if (!projectId || nextStatus === projectStatus) {
      return;
    }
    setError(null);
    try {
      await updateProject(projectId, { status: nextStatus });
      setProjectStatus(nextStatus);
      await loadProjectData();
    } catch (error) {
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
    } catch (error) {
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
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось добавить пользователей в проект."));
    } finally {
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
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось удалить выбранных участников из проекта."));
    } finally {
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
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось удалить выбранные хосты."));
    }
  };

  return (
    <Stack spacing={2.5}>
      <Stack direction="row" justifyContent="space-between" alignItems="center">
        <Box>
          <Typography variant="h4" fontWeight={700}>
            {projectName ? `Проект: ${projectName}` : "Проект"}
          </Typography>
        </Box>
        {selectedSection === "overview" ? (
          <IconButton onClick={openActionsMenu} sx={{ border: "1px solid rgba(126,224,255,0.2)", width: 42, height: 42, backgroundColor: "rgba(15,27,45,0.72)" }}>
            <MoreVertIcon />
          </IconButton>
        ) : null}
      </Stack>

      <Menu
        anchorEl={actionsAnchorEl}
        open={actionsMenuOpen}
        onClose={closeActionsMenu}
        anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
        transformOrigin={{ vertical: "top", horizontal: "right" }}
      >
        {user?.role === "admin" && (
          <MenuItem
            onClick={() => {
              closeActionsMenu();
              openProjectEditDialog();
            }}
          >
            <EditIcon fontSize="small" sx={{ mr: 1 }} />
            Редактировать проект
          </MenuItem>
        )}
        <MenuItem
          onClick={() => {
            closeActionsMenu();
            setImportOpen(true);
          }}
        >
          <UploadFileIcon fontSize="small" sx={{ mr: 1 }} />
          Импорт JSON
        </MenuItem>
        <MenuItem
          onClick={() => {
            closeActionsMenu();
            setExportOpen(true);
          }}
        >
          <DownloadIcon fontSize="small" sx={{ mr: 1 }} />
          Экспорт
        </MenuItem>
        {user?.role === "admin" && (
          <MenuItem
            onClick={() => {
              closeActionsMenu();
              openStatusDialog();
            }}
          >
            <FlagIcon fontSize="small" sx={{ mr: 1 }} />
            Статус проекта
          </MenuItem>
        )}
        {user?.role === "admin" && (
          <MenuItem
            onClick={() => {
              closeActionsMenu();
              openExtendDialog();
            }}
          >
            <AccessTimeIcon fontSize="small" sx={{ mr: 1 }} />
            Продлить проект
          </MenuItem>
        )}
      </Menu>

      <Stack direction={{ xs: "column", md: "row" }} spacing={2}>
        <ProjectTreeNav
          hosts={hosts}
          selectedHostId={selectedHostId}
          selectedSection={selectedSection}
          isCollapsed={isSidebarCollapsed}
          portsCount={ports.length}
          endpointsCount={normalizedEndpoints.length}
          vulnerabilitiesCount={vulnerabilities.length}
          hostStatsById={hostStatsById}
          notesCount={projectNotes.length}
          notes={projectNotes}
          selectedNoteId={selectedNoteId}
          onToggleCollapsed={() => setSidebarCollapsed((v) => !v)}
          onSelectSection={setSelectedSection}
          onSelectProjectOverview={() => setSelectedSection("overview")}
          onSelectNote={setSelectedNoteId}
          onCreateNote={async (parentId) => {
            if (!projectId) return;
            const title = window.prompt(parentId ? "Название подстраницы:" : "Название страницы:")?.trim();
            if (!title) return;
            try {
              const created = await createProjectNote(projectId, { title, parent_id: parentId });
              setProjectNotes(await listProjectNotes(projectId));
              setSelectedNoteId(created.id);
              setSelectedSection("notes");
            } catch (err) {
              setError(getApiErrorMessage(err, "Не удалось создать заметку"));
            }
          }}
          onRenameNote={async (noteId) => {
            if (!projectId) return;
            const current = projectNotes.find((n) => n.id === noteId);
            const nextTitle = window.prompt("Новое название:", current?.title ?? "")?.trim();
            if (!nextTitle || nextTitle === current?.title) return;
            try {
              await updateProjectNote(projectId, noteId, { title: nextTitle });
              setProjectNotes(await listProjectNotes(projectId));
            } catch (err) {
              setError(getApiErrorMessage(err, "Не удалось переименовать заметку"));
            }
          }}
          onDeleteNote={async (noteId) => {
            if (!projectId) return;
            const current = projectNotes.find((n) => n.id === noteId);
            if (!window.confirm(`Удалить заметку "${current?.title ?? ""}" со всеми подстраницами?`)) return;
            try {
              await deleteProjectNote(projectId, noteId);
              setProjectNotes(await listProjectNotes(projectId));
              if (selectedNoteId === noteId) setSelectedNoteId(null);
            } catch (err) {
              setError(getApiErrorMessage(err, "Не удалось удалить заметку"));
            }
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
          onSelectHost={setSelectedHostId}
          onOpenHost={(hostId, section) => navigate(`/projects/${projectId}/hosts/${hostId}`, { state: { section } })}
        />
        <Stack flex={1} spacing={2}>
          {selectedSection !== "overview" && (
            <Card sx={{ border: "1px solid rgba(126,224,255,0.14)" }}>
              <CardContent>
                <Typography variant="h6" fontWeight={700}>
                  {selectedSection === "notes" && "Заметки проекта"}
                  {selectedSection === "hosts" && "Хосты проекта"}
                  {selectedSection === "ports" && `Порты хоста: ${hostLabel}`}
                  {selectedSection === "endpoints" && `Эндпоинты хоста: ${hostLabel}`}
                  {selectedSection === "vulns" && `Уязвимости хоста: ${hostLabel}`}
                </Typography>
              </CardContent>
            </Card>
          )}

          {selectedSection === "overview" && (
            <Stack spacing={2}>
              <Card sx={{ border: "1px solid rgba(126,224,255,0.14)" }}>
                <CardContent>
                  <Stack direction={{ xs: "column", md: "row" }} justifyContent="space-between" spacing={1} alignItems={{ md: "center" }}>
                    <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap">
                      <Typography variant="h6" fontWeight={700}>
                        Таймлайн проекта
                      </Typography>
                      <Chip
                        size="small"
                        color={projectTimeMetrics.statusTone === "neutral" ? "default" : projectTimeMetrics.statusTone}
                        label={projectTimeMetrics.statusLabel}
                      />
                      {projectTimeMetrics.daysLeft !== null && (
                        <Chip
                          size="small"
                          variant="outlined"
                          label={
                            projectTimeMetrics.daysLeft >= 0
                              ? `${projectTimeMetrics.daysLeft} дн. осталось`
                              : `${Math.abs(projectTimeMetrics.daysLeft)} дн. просрочки`
                          }
                        />
                      )}
                    </Stack>
        </Stack>
                  <Box sx={{ mt: 1.5 }}>
                    {timelineBar.ready ? (
                      <>
                        <Box
                          sx={{
                            display: "grid",
                            gridTemplateColumns: `repeat(${timelineBar.totalDays}, minmax(12px, 1fr))`,
                            gap: 0.5,
                            p: 1,
                            border: "1px solid rgba(126,224,255,0.12)",
                            borderRadius: 0,
                            backgroundColor: "rgba(8,17,31,0.34)",
                          }}
                        >
                          {timelineBar.cells.map((cell, index) => (
                            <Box
                              key={`timeline-day-${index}`}
                              sx={{
                                height: 16,
                                border: cell.isToday ? "1px solid rgba(76,175,80,0.95)" : "1px solid rgba(126,224,255,0.16)",
                                backgroundColor: cell.bgColor,
                                boxShadow: cell.isToday ? "0 0 0 1px rgba(76,175,80,0.35)" : "none",
                              }}
                            />
                          ))}
                        </Box>
                        <Stack direction="row" justifyContent="space-between" mt={1}>
                          <Typography variant="caption" color="text.secondary">
                            Start: {timelineBar.startLabel}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            End: {timelineBar.endLabel}
                          </Typography>
      </Stack>
                      </>
                    ) : (
                      <Typography variant="body2" color="text.secondary">
                        Стандартный срок проекта: 14 дней. Укажите дату начала и окончания, чтобы отобразить шкалу по дням.
                      </Typography>
                    )}
                  </Box>
                </CardContent>
              </Card>
      <Grid container spacing={2}>
        <Grid size={{ xs: 12, md: 6 }}>
                  <Card
                    sx={{
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
                    }}
                  >
                    <IconButton
                      size="small"
                      className="overview-card-action"
                      onClick={(event) => setHostsMenuAnchorEl(event.currentTarget)}
                      sx={{
                        position: "absolute",
                        top: 10,
                        right: 10,
                        color: "text.secondary",
                        backgroundColor: "transparent",
                        "&:hover": {
                          backgroundColor: "rgba(126,224,255,0.08)",
                          color: "text.primary",
                        },
                      }}
                    >
                      <MoreVertIcon fontSize="small" />
                    </IconButton>
            <CardContent>
                      <Typography color="text.secondary" mb={1}>
                        Хосты проекта
                      </Typography>
                      <Typography variant="h4" fontWeight={700}>
                        {hosts.length}
                      </Typography>
                      <Stack spacing={0.8} mt={1} sx={{ maxHeight: 160, overflowY: "auto" }}>
                        {hosts.length > 0 ? (
                          hosts.map((host) => (
                            <Box key={host.id} sx={{ px: 1.2, py: 0.9, border: "1px solid rgba(126,224,255,0.10)", borderRadius: 0, backgroundColor: "rgba(8,17,31,0.28)" }}>
                              <Typography variant="body2" color="text.primary">
                                {host.hostname || host.ip_address || "unknown-host"}
                              </Typography>
                            </Box>
                          ))
                        ) : (
                          <Typography color="text.secondary">Хосты не добавлены</Typography>
                        )}
              </Stack>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <Card
                    sx={{
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
                    }}
                  >
                    {user?.role === "admin" && (
                      <IconButton
                        size="small"
                        className="overview-card-action"
                        onClick={(event) => setMembersMenuAnchorEl(event.currentTarget)}
                        sx={{
                          position: "absolute",
                          top: 10,
                          right: 10,
                          color: "text.secondary",
                          backgroundColor: "transparent",
                          "&:hover": {
                            backgroundColor: "rgba(126,224,255,0.08)",
                            color: "text.primary",
                          },
                        }}
                      >
                        <MoreVertIcon fontSize="small" />
                      </IconButton>
                    )}
                    <CardContent sx={{ height: "100%" }}>
                      <Typography color="text.secondary" mb={1}>
                        Участники проекта
                      </Typography>
                      <Typography variant="h4" fontWeight={700} mb={1}>
                        {projectMembers.length}
                      </Typography>
                      <Stack spacing={0.8} sx={{ maxHeight: 160, overflowY: "auto" }}>
                        {projectMembers.length > 0 ? (
                          projectMembers.map((member) => (
                            <Box key={member.user_id} sx={{ px: 1.2, py: 0.9, border: "1px solid rgba(126,224,255,0.10)", borderRadius: 0, backgroundColor: "rgba(8,17,31,0.28)" }}>
                              <Typography variant="body2" color="text.primary">
                                {member.username} ({member.role})
                              </Typography>
                            </Box>
                          ))
                        ) : (
                          <Typography color="text.secondary">Участники не добавлены</Typography>
                        )}
                      </Stack>
                    </CardContent>
                  </Card>
                </Grid>
              </Grid>
              <Menu
                anchorEl={hostsMenuAnchorEl}
                open={Boolean(hostsMenuAnchorEl)}
                onClose={closeHostsMenu}
                anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
                transformOrigin={{ vertical: "top", horizontal: "right" }}
              >
                <MenuItem
                  onClick={() => {
                    closeHostsMenu();
                    setHostOpen(true);
                  }}
                >
                  Добавить хост
                </MenuItem>
                <MenuItem
                  onClick={() => {
                    closeHostsMenu();
                    openRemoveHostsDialog();
                  }}
                  disabled={hosts.length === 0}
                >
                  Удалить хосты
                </MenuItem>
              </Menu>
              <Menu
                anchorEl={membersMenuAnchorEl}
                open={Boolean(membersMenuAnchorEl)}
                onClose={closeMembersMenu}
                anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
                transformOrigin={{ vertical: "top", horizontal: "right" }}
              >
                <MenuItem
                  onClick={() => {
                    closeMembersMenu();
                    void openMembersDialog();
                  }}
                >
                  Добавить пользователей
                </MenuItem>
                <MenuItem
                  onClick={() => {
                    closeMembersMenu();
                    openRemoveMembersDialog();
                  }}
                  disabled={projectMembers.length === 0}
                >
                  Удалить пользователей
                </MenuItem>
              </Menu>
              <Card
                sx={{
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
                }}
              >
                <CardContent>
                  <Stack direction="row" justifyContent="space-between" alignItems="flex-start" spacing={1} mb={1}>
                    <Typography variant="h6" fontWeight={700}>
                      Описание проекта
                    </Typography>
                    {user?.role === "admin" && !projectDescriptionEditOpen && (
                      <IconButton size="small" className="project-description-edit-action" onClick={startProjectDescriptionEdit}>
                        <EditIcon fontSize="small" />
                      </IconButton>
                    )}
                  </Stack>
                  {projectDescriptionEditOpen ? (
                    <Stack spacing={1.5}>
                      <MarkdownEditor
                        label="Описание проекта"
                        showLabel={false}
                        minRows={4}
                        value={projectDraftDescription}
                        onChange={(next) => setProjectDraftDescription(next || "")}
                        onImageTooLarge={() => setError("Изображение слишком большое (макс. ~1.5 МБ).")}
                      />
                      <Stack direction="row" spacing={1} justifyContent="flex-end">
                        <Button onClick={cancelProjectDescriptionEdit} disabled={projectSaving}>
                          Отмена
                        </Button>
                        <Button variant="contained" onClick={() => void submitProjectDescription()} disabled={projectSaving}>
                          Сохранить
                        </Button>
                      </Stack>
                    </Stack>
                  ) : (
                    <Box
                      sx={{
                        "& p": { m: 0, color: "#ffffff" },
                        "& p + p": { mt: 1 },
                        "& img": { maxWidth: "100%", height: "auto" },
                        "& ul, & ol": { m: 0, pl: 2.5, color: "#ffffff" },
                        "& li": { color: "#ffffff" },
                        "& a": { color: "rgba(255,255,255,0.92)" },
                        "& code": { color: "#ffffff", backgroundColor: "rgba(0,0,0,0.2)" },
                        "& strong, & em": { color: "#ffffff" },
                      }}
                    >
                      {projectDescription?.trim() ? (
                        <ReactMarkdown urlTransform={markdownUrlTransform} components={{ img: MarkdownImage }}>
                          {normalizeMarkdownForRender(projectDescription)}
                        </ReactMarkdown>
                      ) : (
                        <Typography color="text.secondary">Описание проекта не заполнено</Typography>
                      )}
                    </Box>
                  )}
                </CardContent>
              </Card>
            </Stack>
          )}

          {selectedSection === "notes" && projectId && (
            <ProjectNotesSection
              projectId={projectId}
              selectedNoteId={selectedNoteId}
              onSelectNote={setSelectedNoteId}
              onNotesChange={setProjectNotes}
            />
          )}

          {selectedSection === "hosts" && (
            <Stack spacing={2}>
              <Card sx={{ border: "1px solid rgba(126,224,255,0.14)" }}>
                <CardContent>
                  <Typography variant="h6" fontWeight={700} mb={2}>
                    Уязвимости по критичности (проект)
                  </Typography>
                  <Stack spacing={1.25}>
                    {SEVERITY_ORDER.map((sev) => {
                      const count = projectSeverityStats[sev];
                      const total = SEVERITY_ORDER.reduce((sum, key) => sum + projectSeverityStats[key], 0);
                      const pct = total > 0 ? Math.round((count / total) * 100) : 0;
                      const tone = severityChipSx[sev] as { bgcolor?: string };
                      return (
                        <Stack key={sev} spacing={0.5}>
                          <Stack direction="row" justifyContent="space-between" alignItems="center">
                            <Typography variant="body2" sx={{ color: "#ffffff" }}>
                              {SEVERITY_LABELS_RU[sev]}
                            </Typography>
                            <Typography variant="body2" fontWeight={700} sx={{ color: "#ffffff" }}>
                              {count}
                            </Typography>
                          </Stack>
                          <Box sx={{ height: 10, backgroundColor: "rgba(126,224,255,0.08)", borderRadius: 0, overflow: "hidden" }}>
                            <Box sx={{ height: "100%", width: `${pct}%`, backgroundColor: tone.bgcolor ?? "rgba(126,224,255,0.3)" }} />
                          </Box>
                        </Stack>
                      );
                    })}
                  </Stack>
                  {SEVERITY_ORDER.every((sev) => projectSeverityStats[sev] === 0) ? (
                    <Typography color="text.secondary" variant="body2" sx={{ mt: 2 }}>
                      Уязвимостей по проекту не найдено.
                    </Typography>
                  ) : null}
                </CardContent>
              </Card>
              <Card sx={{ border: "1px solid rgba(126,224,255,0.14)" }}>
                <CardContent>
                  <Typography variant="subtitle1" fontWeight={700} mb={1}>
                    Хосты
                  </Typography>
                  <Stack spacing={1.2}>
                    {hosts.map((host) => (
                      <Box
                        key={host.id}
                        sx={{
                          border: "1px solid rgba(126,224,255,0.12)",
                          p: 1.6,
                          borderRadius: 0,
                          cursor: "pointer",
                          backgroundColor: "rgba(8,17,31,0.24)",
                        }}
                        onClick={() => navigate(`/projects/${projectId}/hosts/${host.id}`)}
                      >
                        <Typography sx={{ color: "#ffffff" }}>{host.hostname || host.ip_address || "unknown-host"}</Typography>
                      </Box>
                    ))}
                    {hosts.length === 0 ? <Typography color="text.secondary">Хосты не добавлены.</Typography> : null}
                  </Stack>
                </CardContent>
              </Card>
            </Stack>
          )}

          {selectedSection === "ports" && (
            <Card sx={{ border: "1px solid rgba(126,224,255,0.14)" }}>
            <CardContent>
                <Stack spacing={1.2}>
                  {ports.map((port) => (
                    <Box key={port.id} sx={{ border: "1px solid rgba(126,224,255,0.12)", p: 1.5, borderRadius: 0, backgroundColor: "rgba(8,17,31,0.24)" }}>
                      <Stack direction="row" spacing={1} alignItems="center">
                        <Typography fontWeight={600}>
                          {port.port_number}/{port.protocol}
                        </Typography>
                        <Chip size="small" label={port.state} />
              </Stack>
                    </Box>
                  ))}
                  {ports.length === 0 && (
                    <Typography color="text.secondary">Порты не добавлены. Выберите хост и добавьте первый порт.</Typography>
                  )}
                </Stack>
              </CardContent>
            </Card>
          )}

          {selectedSection === "endpoints" && (
            <Card sx={{ border: "1px solid rgba(126,224,255,0.14)" }}>
              <CardContent>
                <Stack spacing={1.2}>
                  {normalizedEndpoints.map((endpoint) => (
                    <Box key={endpoint.id} sx={{ border: "1px solid rgba(126,224,255,0.12)", p: 1.5, borderRadius: 0, backgroundColor: "rgba(8,17,31,0.24)" }}>
                      <Stack direction="row" spacing={1} alignItems="center">
                        <Chip size="small" label={endpoint.method || "ANY"} />
                        <Typography fontWeight={600}>{endpoint.path}</Typography>
                      </Stack>
                      <Typography variant="body2" sx={{ mt: 0.8, color: endpoint.description?.trim() ? "#ffffff" : "rgba(148,163,184,0.85)" }}>
                        {endpoint.description || "Описание не указано"}
                      </Typography>
                    </Box>
                  ))}
                  {normalizedEndpoints.length === 0 && (
                    <Typography color="text.secondary">Эндпоинты не добавлены. Выберите хост и добавьте первый эндпоинт.</Typography>
                  )}
                </Stack>
              </CardContent>
            </Card>
          )}

          {selectedSection === "vulns" && (
            <Card sx={{ border: "1px solid rgba(126,224,255,0.14)" }}>
              <CardContent>
              <Stack direction="row" spacing={1} mb={2} flexWrap="wrap">
                  {Object.entries(vulnerabilities.reduce(
                    (acc, item) => {
                      acc[item.severity] += 1;
                      return acc;
                    },
                    { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Vulnerability["severity"], number>
                  )).map(([severity, value]) => (
                  <Chip key={severity} label={`${severity}: ${value}`} />
                ))}
              </Stack>
              <Stack spacing={1.2}>
                {vulnerabilities.map((item) => (
                  <Box key={item.id} sx={{ border: "1px solid rgba(126,224,255,0.12)", p: 1.5, borderRadius: 0, backgroundColor: "rgba(8,17,31,0.24)" }}>
                    <Stack spacing={1}>
                      <Typography>{item.title}</Typography>
                      <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                        {item.cwe_id && <Chip label={item.cwe_id} size="small" variant="outlined" />}
                        {item.cvss_version && <Chip label={`CVSS ${item.cvss_version} ${item.cvss_score ?? "-"}`} size="small" variant="outlined" />}
                        <Chip label={item.severity} size="small" sx={severityChipSx[item.severity]} />
                        <Chip label={item.status} size="small" sx={vulnerabilityStatusChipSx[item.status]} />
                      </Stack>
                      <Typography variant="body2" sx={{ color: item.impact?.trim() ? "#ffffff" : "rgba(148,163,184,0.85)" }}>
                        {item.impact || "Влияние не указано"}
                      </Typography>
                      <Box>
                        <Button
                          size="small"
                          variant="outlined"
                          onClick={() => {
                            if (projectId && selectedHostId) {
                              navigate(`/projects/${projectId}/hosts/${selectedHostId}/vulnerabilities/${item.id}`, {
                                state: { section: "vulns" },
                              });
                            }
                          }}
                          disabled={vulnBusy || !projectId || !selectedHostId}
                        >
                          Открыть
                        </Button>
                      </Box>
                    </Stack>
                  </Box>
                ))}
                  {vulnerabilities.length === 0 && <Typography color="text.secondary">Для выбранного хоста уязвимости не привязаны.</Typography>}
              </Stack>
            </CardContent>
          </Card>
          )}
        </Stack>
      </Stack>

      <Dialog open={hostOpen} onClose={() => setHostOpen(false)} fullWidth>
        <DialogTitle>Добавить хост</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField label="IP-адрес" value={hostIp} onChange={(e) => setHostIp(e.target.value)} />
            <TextField label="Hostname" value={hostName} onChange={(e) => setHostName(e.target.value)} />
            <MarkdownEditor
              label="Описание"
              minRows={3}
              value={hostNotes}
              onChange={(next) => setHostNotes(next || "")}
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setHostOpen(false)}>Отмена</Button>
          <Button variant="contained" disabled={!hostIp && !hostName} onClick={() => void submitHost()}>
            Сохранить
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={removeHostsDialogOpen} onClose={() => setRemoveHostsDialogOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>Удалить хосты</DialogTitle>
        <DialogContent>
          <Stack spacing={1} sx={{ mt: 1 }}>
            <List dense disablePadding>
              {hosts.map((host) => {
                const checked = selectedHostIds.includes(host.id);
                return (
                  <ListItem
                    key={host.id}
                    secondaryAction={
                      <Checkbox
                        edge="end"
                        checked={checked}
                        onChange={(event) =>
                          setSelectedHostIds((prev) =>
                            event.target.checked ? [...prev, host.id] : prev.filter((item) => item !== host.id)
                          )
                        }
                      />
                    }
                  >
                    <ListItemText primary={host.hostname || host.ip_address || "unknown-host"} secondary={host.ip_address || host.hostname || ""} />
                  </ListItem>
                );
              })}
              {hosts.length === 0 && <Typography color="text.secondary">Хосты пока не добавлены.</Typography>}
            </List>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRemoveHostsDialogOpen(false)}>Закрыть</Button>
          <Button color="error" variant="contained" startIcon={<DeleteOutlineIcon />} disabled={selectedHostIds.length === 0} onClick={() => void removeSelectedHosts()}>
            Удалить
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={extendDialogOpen} onClose={() => setExtendDialogOpen(false)} fullWidth maxWidth="xs">
        <DialogTitle>Продлить проект</DialogTitle>
        <DialogContent>
          <Stack spacing={1.5} sx={{ mt: 1 }}>
            <Typography variant="body2" color="text.secondary">
              Текущая дата окончания: {projectEndDate || "не задана"}
            </Typography>
            <TextField
              label="Новая дата окончания"
              type="date"
              value={extendEndDate}
              onChange={(event) => setExtendEndDate(event.target.value)}
              InputLabelProps={{ shrink: true }}
            />
            <Stack direction="row" spacing={1}>
              <Button size="small" variant="text" onClick={() => applyQuickExtension(7)}>
                +7 дней
              </Button>
              <Button size="small" variant="text" onClick={() => applyQuickExtension(14)}>
                +14 дней
              </Button>
              <Button size="small" variant="text" onClick={() => applyQuickExtension(30)}>
                +30 дней
              </Button>
            </Stack>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setExtendDialogOpen(false)}>Отмена</Button>
          <Button variant="contained" disabled={!extendEndDate || extendingProject} onClick={() => void submitProjectExtension()}>
            Продлить
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={projectEditDialogOpen} onClose={() => setProjectEditDialogOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>Редактировать проект</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField label="Название" value={projectDraftName} onChange={(event) => setProjectDraftName(event.target.value)} />
            <TextField
              label="Дата начала"
              type="date"
              value={projectDraftStartDate}
              onChange={(event) => setProjectDraftStartDate(event.target.value)}
              InputLabelProps={{ shrink: true }}
            />
            <TextField
              label="Дата окончания"
              type="date"
              value={projectDraftEndDate}
              onChange={(event) => setProjectDraftEndDate(event.target.value)}
              InputLabelProps={{ shrink: true }}
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setProjectEditDialogOpen(false)}>Отмена</Button>
          <Button variant="contained" onClick={() => void submitProjectEdit()} disabled={projectSaving || !projectDraftName.trim()}>
            Сохранить
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={statusDialogOpen} onClose={() => setStatusDialogOpen(false)} fullWidth maxWidth="xs">
        <DialogTitle>Статус проекта</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField
              select
              label="Статус проекта"
              value={pendingProjectStatus}
              onChange={(event) => setPendingProjectStatus(event.target.value as ProjectStatus)}
              fullWidth
            >
              {PROJECT_STATUS_ORDER.map((status) => (
                <MenuItem key={status} value={status}>
                  {PROJECT_STATUS_LABELS[status]}
                </MenuItem>
              ))}
            </TextField>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setStatusDialogOpen(false)}>Отмена</Button>
          <Button variant="contained" onClick={() => void submitProjectStatus()} disabled={pendingProjectStatus === projectStatus}>
            Сохранить
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog
        open={vulnDetailOpen}
        onClose={() => {
          setVulnEditMode(false);
          setVulnDetailOpen(false);
        }}
        fullWidth
        maxWidth="lg"
      >
        <DialogTitle>Карточка уязвимости</DialogTitle>
        <DialogContent>
          {!activeVuln ? (
            <Typography color="text.secondary">Уязвимость не выбрана.</Typography>
          ) : (
            <Stack spacing={2} sx={{ mt: 0.5 }}>
              <Grid container spacing={2}>
                <Grid size={{ xs: 12, md: 7 }}>
                  <TextField
                    label="Название"
                    fullWidth
                    value={activeVuln.title}
                    onChange={(e) => setActiveVuln((prev) => (prev ? { ...prev, title: e.target.value } : prev))}
                    slotProps={{ input: { readOnly: !vulnEditMode } }}
                  />
                </Grid>
                <Grid size={{ xs: 12, md: 3 }}>
                  <TextField
                    label="CWE ID"
                    fullWidth
                    value={activeVuln.cwe_id || ""}
                    onChange={(e) => setActiveVuln((prev) => (prev ? { ...prev, cwe_id: e.target.value || null } : prev))}
                    slotProps={{ input: { readOnly: !vulnEditMode } }}
                  />
                </Grid>
                <Grid size={{ xs: 12, md: 2 }}>
                  {vulnEditMode ? (
                    <TextField
                      select
                      label="Статус"
                      fullWidth
                      value={activeVuln.status}
                      onChange={(e) => setActiveVuln((prev) => (prev ? { ...prev, status: e.target.value as Vulnerability["status"] } : prev))}
                    >
                      <MenuItem value="open">open</MenuItem>
                      <MenuItem value="in_progress">in_progress</MenuItem>
                      <MenuItem value="fixed">fixed</MenuItem>
                      <MenuItem value="wont_fix">wont_fix</MenuItem>
                      <MenuItem value="accepted_risk">accepted_risk</MenuItem>
                    </TextField>
                  ) : (
                    <TextField label="Статус" fullWidth value={activeVuln.status} slotProps={{ input: { readOnly: true } }} />
                  )}
                </Grid>
                <Grid size={{ xs: 12, md: 2 }}>
                  <TextField label="CVSS score" type="number" fullWidth value={activeVuln.cvss_score ?? ""} slotProps={{ input: { readOnly: true } }} />
                </Grid>
                <Grid size={{ xs: 12, md: 2 }}>
                  <TextField label="Критичность" fullWidth value={activeVuln.severity} slotProps={{ input: { readOnly: true } }} />
                </Grid>
                <Grid size={{ xs: 12, md: 8 }}>
                  <TextField
                    label="CVSS vector"
                    fullWidth
                    value={activeVuln.cvss_vector || ""}
                    onChange={(e) => setActiveVuln((prev) => (prev ? { ...prev, ...buildAutoCvssFields(e.target.value || null) } : prev))}
                    slotProps={{ input: { readOnly: !vulnEditMode } }}
                  />
                </Grid>
                <Grid size={{ xs: 12 }}>
                  <VulnerabilityStagesEditor
                    stages={activeVuln.workflow_steps || []}
                    endpoints={normalizedEndpoints}
                    hostLabel={selectedHost?.hostname || selectedHost?.ip_address || undefined}
                    busy={vulnBusy}
                    editable={vulnEditMode}
                    onChange={(nextStages) =>
                      setActiveVuln((prev) =>
                        prev
                          ? {
                              ...prev,
                              workflow_steps: nextStages,
                            }
                          : prev
                      )
                    }
                    onUploadImage={async (_stageId, file) => {
                      if (!projectId || !activeVuln) {
                        return null;
                      }
                      try {
                        const uploadedFile = await uploadVulnerabilityFile(projectId, activeVuln.id, file);
                        setActiveVuln((prev) =>
                          prev
                            ? {
                                ...prev,
                                files: [uploadedFile, ...prev.files.filter((fileMeta) => fileMeta.id !== uploadedFile.id)],
                              }
                            : prev
                        );
                        return `![${uploadedFile.original_name}](/api/v1/files/${uploadedFile.id}/download)`;
                      } catch {
                        setError("Не удалось загрузить картинку этапа");
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
                      value={activeVuln.impact}
                      onChange={(next) => setActiveVuln((prev) => (prev ? { ...prev, impact: next } : prev))}
                    />
                  ) : (
                    renderMarkdownPreview(activeVuln.impact, "Влияние не указано.", "Влияние")
                  )}
                </Grid>
                <Grid size={{ xs: 12 }}>
                  {vulnEditMode ? (
                    <MarkdownEditor
                      label="Рекомендации"
                      minRows={2}
                      value={activeVuln.recommendations}
                      onChange={(next) => setActiveVuln((prev) => (prev ? { ...prev, recommendations: next } : prev))}
                    />
                  ) : (
                    renderMarkdownPreview(activeVuln.recommendations, "Рекомендации не указаны.", "Рекомендации")
                  )}
                </Grid>
                {vulnEditMode && (
                  <Grid size={{ xs: 12 }}>
                    <Stack direction={{ xs: "column", sm: "row" }} justifyContent="flex-end" spacing={1.5}>
                      <Button variant="outlined" onClick={() => activeVuln && void loadVulnerabilityDetails(activeVuln.id)}>
                        Отменить
                      </Button>
                      <Button variant="contained" size="large" sx={{ minWidth: 180 }} onClick={() => void saveActiveVulnerability()} disabled={!activeVuln || vulnBusy}>
                        Сохранить
                      </Button>
                    </Stack>
                  </Grid>
                )}
              </Grid>
              <Divider />
              {renderCommentsSection()}
            </Stack>
          )}
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 3, pt: 1.5 }}>
          <Button
            onClick={() => {
              setVulnEditMode(false);
              setVulnDetailOpen(false);
            }}
          >
            Закрыть
          </Button>
          {!vulnEditMode && (
            <span>
              <IconButton
                aria-label="Редактировать"
                onClick={() => setVulnEditMode(true)}
                disabled={!activeVuln}
                sx={{ color: "text.secondary", "&:hover": { backgroundColor: "rgba(126,224,255,0.08)", color: "text.primary" } }}
              >
                <EditIcon fontSize="small" />
              </IconButton>
            </span>
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
            sx={{ mt: 1, "& .MuiInputBase-input": { color: "#ffffff" } }}
            label="Комментарий"
            value={editingCommentContent}
            onChange={(event) => setEditingCommentContent(event.target.value)}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditCommentOpen(false)}>Отмена</Button>
          <Button variant="contained" disabled={!editingCommentContent.trim() || vulnBusy} onClick={() => void saveCommentEdit()}>
            Сохранить
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={exportOpen} onClose={() => setExportOpen(false)} fullWidth maxWidth="xs">
        <DialogTitle>Экспорт отчёта</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField
              select
              label="Тип отчёта"
              value={exportReportKind}
              onChange={(e) => setExportReportKind(e.target.value as "szi" | "pp")}
            >
              <MenuItem value="szi">СЗИ — сертификация (Word)</MenuItem>
              <MenuItem value="pp">ПП — внутренняя приёмка (Word)</MenuItem>
            </TextField>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setExportOpen(false)}>Отмена</Button>
          <Button
            variant="contained"
            startIcon={<DownloadIcon />}
            disabled={reportLoadingKind !== null}
            onClick={() => void downloadReport(exportReportKind)}
          >
            Скачать
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={importOpen} onClose={() => setImportOpen(false)} fullWidth>
        <DialogTitle>Импорт структуры проекта (JSON)</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <Button component="label" variant="outlined" startIcon={<UploadFileIcon />}>
              {importFile ? `Файл: ${importFile.name}` : "Выбрать JSON-файл"}
              <input
                hidden
                type="file"
                accept="application/json,.json"
                onChange={(event) => {
                  const selected = event.target.files?.[0] ?? null;
                  setImportFile(selected);
                }}
              />
            </Button>
            {importSummary && (
              <Box sx={{ border: "1px solid rgba(126,224,255,0.16)", p: 1.5 }}>
                <Typography variant="subtitle2" fontWeight={700} mb={0.5}>
                  Результат последнего импорта
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  hosts: {importSummary.hosts_created}, ports: {importSummary.ports_created}, services: {importSummary.services_created},
                  endpoints: {importSummary.endpoints_created}
                </Typography>
                {importSummary.errors.length > 0 && (
                  <Typography variant="body2" color="warning.main" mt={0.5}>
                    Ошибки: {importSummary.errors.join("; ")}
                  </Typography>
                )}
              </Box>
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setImportOpen(false)}>Закрыть</Button>
          <Button variant="contained" disabled={!importFile || importing} onClick={() => void submitImport()}>
            Импортировать
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={membersDialogOpen} onClose={() => setMembersDialogOpen(false)} fullWidth maxWidth="md">
        <DialogTitle sx={{ pr: 6 }}>
          Добавить пользователей в проект
          <IconButton
            aria-label="Закрыть"
            onClick={() => setMembersDialogOpen(false)}
            sx={{ position: "absolute", right: 8, top: 8 }}
          >
            <CloseIcon />
          </IconButton>
        </DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            {user?.role === "admin" && (
              <>
                <TextField
                  label="Поиск по username"
                  value={memberSearchQuery}
                  onChange={(event) => setMemberSearchQuery(event.target.value)}
                  fullWidth
                />
                <List
                  dense
                  disablePadding
                  sx={{
                    maxHeight: 360,
                    overflowY: "auto",
                    border: "1px solid rgba(126,224,255,0.12)",
                    backgroundColor: "rgba(8,17,31,0.2)",
                    px: 1,
                  }}
                >
                  {membersDialogUsers.map((candidate) => {
                    const checked = candidate.inProject || selectedAvailableMemberIds.includes(candidate.id);
                    return (
                      <ListItem
                        key={candidate.id}
                        secondaryAction={
                          <Checkbox
                            edge="end"
                            checked={checked}
                            disabled={candidate.inProject}
                            sx={
                              candidate.inProject
                                ? {
                                    color: "primary.main",
                                    "&.Mui-checked": {
                                      color: "primary.main",
                                    },
                                  }
                                : undefined
                            }
                            onChange={(event) =>
                              setSelectedAvailableMemberIds((prev) =>
                                event.target.checked ? [...prev, candidate.id] : prev.filter((item) => item !== candidate.id)
                              )
                            }
                          />
                        }
                      >
                        <ListItemText
                          primary={`${candidate.username} (${candidate.role})`}
                          secondary={candidate.inProject ? `${candidate.email} • уже в проекте` : candidate.email}
                        />
                      </ListItem>
                    );
                  })}
                  {membersDialogUsers.length === 0 && (
                    <Typography color="text.secondary" sx={{ px: 1, py: 1.5 }}>
                      Пользователи по этому запросу не найдены.
                    </Typography>
                  )}
                </List>
                <Stack direction="row" justifyContent="flex-end">
                  <Button variant="contained" disabled={selectedAvailableMemberIds.length === 0 || membersBusy} onClick={() => void addMembersToProject()}>
                    Добавить выбранных
                  </Button>
                </Stack>
              </>
            )}
          </Stack>
        </DialogContent>
      </Dialog>

      <Dialog open={removeMembersDialogOpen} onClose={() => setRemoveMembersDialogOpen(false)} fullWidth maxWidth="md">
        <DialogTitle>Удалить пользователей из проекта</DialogTitle>
        <DialogContent>
          <Stack spacing={1.5} sx={{ mt: 1 }}>
            <List dense disablePadding>
              {projectMembers.map((member) => {
                const checked = selectedMemberIds.includes(member.user_id);
                return (
                  <ListItem
                    key={member.user_id}
                    secondaryAction={
                      <Checkbox
                        edge="end"
                        checked={checked}
                        onChange={(event) =>
                          setSelectedMemberIds((prev) =>
                            event.target.checked ? [...prev, member.user_id] : prev.filter((item) => item !== member.user_id)
                          )
                        }
                      />
                    }
                  >
                    <ListItemText primary={`${member.username} (${member.role})`} secondary={member.email} />
                  </ListItem>
                );
              })}
              {projectMembers.length === 0 && <Typography color="text.secondary">Участники пока не добавлены.</Typography>}
            </List>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRemoveMembersDialogOpen(false)}>Закрыть</Button>
          <Button
            color="error"
            variant="contained"
            startIcon={<DeleteOutlineIcon />}
            disabled={selectedMemberIds.length === 0 || membersBusy}
            onClick={() => void removeSelectedMembersFromProject()}
          >
            Удалить
          </Button>
        </DialogActions>
      </Dialog>
    </Stack>
  );
}
