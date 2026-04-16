import AddIcon from "@mui/icons-material/Add";
import AttachFileIcon from "@mui/icons-material/AttachFile";
import DeleteOutlineIcon from "@mui/icons-material/DeleteOutline";
import DownloadIcon from "@mui/icons-material/Download";
import EditIcon from "@mui/icons-material/Edit";
import MoreVertIcon from "@mui/icons-material/MoreVert";
import OpenInNewIcon from "@mui/icons-material/OpenInNew";
import GroupIcon from "@mui/icons-material/Group";
import PersonAddAlt1Icon from "@mui/icons-material/PersonAddAlt1";
import UploadFileIcon from "@mui/icons-material/UploadFile";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
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
import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  createHost,
  createVulnerabilityComment,
  addProjectMember,
  deleteVulnerability,
  deleteVulnerabilityComment,
  deleteVulnerabilityFile,
  generateProjectReport,
  getEndpoints,
  getHostVulnerabilities,
  getHosts,
  getPorts,
  getProjectMembers,
  getUsers,
  getProjects,
  getVulnerability,
  importProjectData,
  listVulnerabilityComments,
  listVulnerabilityFiles,
  removeProjectMember,
  updateHost,
  updateVulnerability,
  uploadVulnerabilityFile,
} from "../api";
import { ProjectTreeNav, type DetailSection } from "../components/ProjectTreeNav";
import { useAuthStore } from "../store";
import type { Endpoint, Host, HostTreeStats, ImportResult, Port, ProjectMember, User, Vulnerability, VulnerabilityComment, VulnerabilityDetails, VulnerabilityFile } from "../types";

export function ProjectDetailPage() {
  const { projectId } = useParams<{ projectId: string }>();
  const navigate = useNavigate();
  const user = useAuthStore((s) => s.user);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [ports, setPorts] = useState<Port[]>([]);
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [selectedHostId, setSelectedHostId] = useState<string | null>(null);
  const [selectedSection, setSelectedSection] = useState<DetailSection>("overview");
  const [isSidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [projectName, setProjectName] = useState<string>("");
  const [projectDescription, setProjectDescription] = useState<string>("");
  const [projectMembers, setProjectMembers] = useState<ProjectMember[]>([]);
  const [usersCatalog, setUsersCatalog] = useState<User[]>([]);
  const [membersDialogOpen, setMembersDialogOpen] = useState(false);
  const [selectedMemberUserId, setSelectedMemberUserId] = useState("");
  const [membersBusy, setMembersBusy] = useState(false);
  const [hostStatsById, setHostStatsById] = useState<Record<string, HostTreeStats>>({});
  const [importOpen, setImportOpen] = useState(false);
  const [importFile, setImportFile] = useState<File | null>(null);
  const [importing, setImporting] = useState(false);
  const [importSummary, setImportSummary] = useState<ImportResult | null>(null);
  const [reportLoadingFormat, setReportLoadingFormat] = useState<"md" | "pdf" | "docx" | null>(null);
  const [actionsAnchorEl, setActionsAnchorEl] = useState<HTMLElement | null>(null);
  const [exportOpen, setExportOpen] = useState(false);
  const [exportFormat, setExportFormat] = useState<"md" | "pdf" | "docx">("pdf");

  const [hostOpen, setHostOpen] = useState(false);
  const [hostIp, setHostIp] = useState("");
  const [hostName, setHostName] = useState("");
  const [hostStatus, setHostStatus] = useState<Host["status"]>("unknown");
  const [hostNotes, setHostNotes] = useState("");
  const [editHostOpen, setEditHostOpen] = useState(false);
  const [vulnDetailOpen, setVulnDetailOpen] = useState(false);
  const [activeVuln, setActiveVuln] = useState<VulnerabilityDetails | null>(null);
  const [vulnFiles, setVulnFiles] = useState<VulnerabilityFile[]>([]);
  const [vulnComments, setVulnComments] = useState<VulnerabilityComment[]>([]);
  const [newComment, setNewComment] = useState("");
  const [vulnBusy, setVulnBusy] = useState(false);

  const availableUsers = useMemo(
    () => usersCatalog.filter((candidate) => !projectMembers.some((member) => member.user_id === candidate.id)),
    [projectMembers, usersCatalog]
  );

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
    } catch {
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
    } catch {
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

  const severityStats = useMemo(() => {
    const stats = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    vulnerabilities.forEach((item) => {
      stats[item.severity] += 1;
    });
    return stats;
  }, [vulnerabilities]);
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

  const loadVulnerabilityDetails = async (vulnerabilityId: string) => {
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
    } catch {
      setError("Не удалось загрузить карточку уязвимости");
    } finally {
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
    } catch {
      setError("Не удалось сохранить уязвимость");
    } finally {
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
    } catch {
      setError("Не удалось удалить уязвимость");
    } finally {
      setVulnBusy(false);
    }
  };

  const uploadFileToActiveVuln = async (file: File | null) => {
    if (!projectId || !activeVuln || !file) {
      return;
    }
    setVulnBusy(true);
    try {
      await uploadVulnerabilityFile(projectId, activeVuln.id, file);
      const files = await listVulnerabilityFiles(projectId, activeVuln.id);
      setVulnFiles(files);
    } catch {
      setError("Не удалось загрузить файл");
    } finally {
      setVulnBusy(false);
    }
  };

  const removeVulnerabilityFile = async (fileId: string) => {
    if (!projectId || !activeVuln) {
      return;
    }
    setVulnBusy(true);
    try {
      await deleteVulnerabilityFile(projectId, activeVuln.id, fileId);
      const files = await listVulnerabilityFiles(projectId, activeVuln.id);
      setVulnFiles(files);
    } catch {
      setError("Не удалось удалить файл");
    } finally {
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
    } catch {
      setError("Не удалось добавить комментарий");
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
      const commentsPage = await listVulnerabilityComments(projectId, activeVuln.id);
      setVulnComments(commentsPage.items);
    } catch {
      setError("Не удалось удалить комментарий");
    } finally {
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
    } catch {
      setError("Не удалось импортировать JSON-данные проекта");
    } finally {
      setImporting(false);
    }
  };

  const downloadReport = async (format: "md" | "pdf" | "docx") => {
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
    } catch {
      setError("Не удалось сформировать отчёт");
    } finally {
      setReportLoadingFormat(null);
    }
  };
  const actionsMenuOpen = Boolean(actionsAnchorEl);

  const openActionsMenu = (event: React.MouseEvent<HTMLElement>) => {
    setActionsAnchorEl(event.currentTarget);
  };

  const closeActionsMenu = () => {
    setActionsAnchorEl(null);
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
      const usersResponse = await getUsers(1, 300);
      setUsersCatalog(usersResponse.items);
    } catch {
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
    } catch {
      setError("Не удалось добавить участника в проект.");
    } finally {
      setMembersBusy(false);
    }
  };

  const removeMemberFromProject = async (memberUserId: string) => {
    if (!projectId) {
      return;
    }
    setMembersBusy(true);
    setError(null);
    try {
      await removeProjectMember(projectId, memberUserId);
      await loadProjectData();
    } catch {
      setError("Не удалось удалить участника из проекта.");
    } finally {
      setMembersBusy(false);
    }
  };

  return (
    <Stack spacing={2.5}>
      {error && <Alert severity="error">{error}</Alert>}
      <Stack direction="row" justifyContent="space-between" alignItems="center">
        <Box>
          <Typography variant="h4" fontWeight={700}>
            {projectName ? `Проект: ${projectName}` : "Проект"}
          </Typography>
        </Box>
        <IconButton onClick={openActionsMenu} sx={{ border: "1px solid rgba(126,224,255,0.2)", borderRadius: 2 }}>
          <MoreVertIcon />
        </IconButton>
      </Stack>

      <Menu
        anchorEl={actionsAnchorEl}
        open={actionsMenuOpen}
        onClose={closeActionsMenu}
        anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
        transformOrigin={{ vertical: "top", horizontal: "right" }}
      >
        <MenuItem
          onClick={() => {
            closeActionsMenu();
            setHostOpen(true);
          }}
        >
          <AddIcon fontSize="small" sx={{ mr: 1 }} />
          Добавить хост
        </MenuItem>
        <MenuItem
          disabled={!selectedHost}
          onClick={() => {
            closeActionsMenu();
            openEditHost();
          }}
        >
          <EditIcon fontSize="small" sx={{ mr: 1 }} />
          Редактировать хост
        </MenuItem>
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
        <MenuItem
          onClick={() => {
            closeActionsMenu();
            void openMembersDialog();
          }}
        >
          <GroupIcon fontSize="small" sx={{ mr: 1 }} />
          Участники проекта
        </MenuItem>
      </Menu>

      <Stack direction={{ xs: "column", md: "row" }} spacing={2}>
        <ProjectTreeNav
          hosts={hosts}
          selectedHostId={selectedHostId}
          selectedSection={selectedSection}
          isCollapsed={isSidebarCollapsed}
          portsCount={ports.length}
          endpointsCount={endpoints.length}
          vulnerabilitiesCount={vulnerabilities.length}
          hostStatsById={hostStatsById}
          autoExpandSelectedHost={false}
          onToggleCollapsed={() => setSidebarCollapsed((v) => !v)}
          onSelectSection={setSelectedSection}
          onSelectProjectOverview={() => setSelectedSection("overview")}
          onSelectHost={setSelectedHostId}
          onOpenHost={(hostId) => navigate(`/projects/${projectId}/hosts/${hostId}`)}
        />

        <Stack flex={1} spacing={2}>
          {selectedSection !== "overview" && (
            <Card sx={{ border: "1px solid rgba(126,224,255,0.18)", borderRadius: 0 }}>
              <CardContent>
                <Typography variant="h6" fontWeight={700}>
                  {selectedSection === "hosts" && `Хост: ${hostLabel}`}
                  {selectedSection === "ports" && `Порты хоста: ${hostLabel}`}
                  {selectedSection === "endpoints" && `Эндпоинты хоста: ${hostLabel}`}
                  {selectedSection === "vulns" && `Уязвимости хоста: ${hostLabel}`}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Слева — древовидная навигация по проекту, как в wiki-страницах.
                </Typography>
              </CardContent>
            </Card>
          )}

          {selectedSection === "overview" && (
            <Stack spacing={2}>
              <Card sx={{ border: "1px solid rgba(126,224,255,0.16)", borderRadius: 0 }}>
                <CardContent>
                  <Typography variant="h6" fontWeight={700} mb={1}>
                    Описание проекта
                  </Typography>
                  <Typography color="text.secondary">{projectDescription || "Описание проекта не заполнено"}</Typography>
                </CardContent>
              </Card>
              <Grid container spacing={2}>
                <Grid size={{ xs: 12, md: 6 }}>
                  <Card sx={{ border: "1px solid rgba(126,224,255,0.16)", borderRadius: 0, height: "100%" }}>
                    <CardContent>
                      <Typography color="text.secondary">Хостов</Typography>
                      <Typography variant="h4" fontWeight={700}>
                        {hosts.length}
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <Card sx={{ border: "1px solid rgba(126,224,255,0.16)", borderRadius: 0, height: "100%" }}>
                    <CardContent sx={{ height: "100%" }}>
                      <Typography color="text.secondary" mb={1}>
                        Участники проекта
                      </Typography>
                      <Stack spacing={0.5}>
                        {projectMembers.length > 0 ? (
                          projectMembers.map((member) => (
                            <Typography key={member.user_id} variant="body2">
                              {member.username} ({member.role})
                            </Typography>
                          ))
                        ) : (
                          <Typography color="text.secondary">Участники не добавлены</Typography>
                        )}
                      </Stack>
                    </CardContent>
                  </Card>
                </Grid>
              </Grid>
            </Stack>
          )}

          {selectedSection === "hosts" && (
            <Card sx={{ border: "1px solid rgba(126,224,255,0.16)", borderRadius: 0 }}>
              <CardContent>
                <Stack spacing={1.2}>
                  {hosts.map((host) => (
                    <Box
                      key={host.id}
                      sx={{ border: "1px solid rgba(126,224,255,0.16)", p: 1.5, borderRadius: 0, cursor: "pointer" }}
                      onClick={() => navigate(`/projects/${projectId}/hosts/${host.id}`)}
                    >
                      <Typography>{host.hostname || host.ip_address || "unknown-host"}</Typography>
                      <Typography variant="body2" color="text.secondary">
                        Статус: {host.status}
                      </Typography>
                    </Box>
                  ))}
                </Stack>
              </CardContent>
            </Card>
          )}

          {selectedSection === "ports" && (
            <Card sx={{ border: "1px solid rgba(126,224,255,0.16)", borderRadius: 0 }}>
              <CardContent>
                <Stack spacing={1.2}>
                  {ports.map((port) => (
                    <Box key={port.id} sx={{ border: "1px solid rgba(126,224,255,0.16)", p: 1.5, borderRadius: 0 }}>
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
            <Card sx={{ border: "1px solid rgba(126,224,255,0.16)", borderRadius: 0 }}>
              <CardContent>
                <Stack spacing={1.2}>
                  {endpoints.map((endpoint) => (
                    <Box key={endpoint.id} sx={{ border: "1px solid rgba(126,224,255,0.16)", p: 1.5, borderRadius: 0 }}>
                      <Stack direction="row" spacing={1} alignItems="center">
                        <Chip size="small" label={endpoint.method || "ANY"} />
                        <Typography fontWeight={600}>{endpoint.path}</Typography>
                      </Stack>
                      <Typography variant="body2" color="text.secondary" mt={0.8}>
                        {endpoint.description || "Описание не указано"}
                      </Typography>
                    </Box>
                  ))}
                  {endpoints.length === 0 && (
                    <Typography color="text.secondary">Эндпоинты не добавлены. Выберите хост и добавьте первый эндпоинт.</Typography>
                  )}
                </Stack>
              </CardContent>
            </Card>
          )}

          {selectedSection === "vulns" && (
            <Card sx={{ border: "1px solid rgba(126,224,255,0.16)", borderRadius: 0 }}>
              <CardContent>
                <Stack direction="row" spacing={1} mb={2} flexWrap="wrap">
                  {Object.entries(severityStats).map(([severity, value]) => (
                    <Chip key={severity} label={`${severity}: ${value}`} />
                  ))}
                </Stack>
                <Stack spacing={1.2}>
                  {vulnerabilities.map((item) => (
                    <Box key={item.id} sx={{ border: "1px solid rgba(126,224,255,0.16)", p: 1.5, borderRadius: 0 }}>
                      <Stack direction="row" justifyContent="space-between" alignItems="center">
                        <Typography>{item.title}</Typography>
                        <Button size="small" variant="outlined" onClick={() => void loadVulnerabilityDetails(item.id)} disabled={vulnBusy}>
                          Открыть
                        </Button>
                      </Stack>
                      <Stack direction="row" spacing={1} mt={1} flexWrap="wrap">
                        <Chip label={item.severity} size="small" sx={severityChipSx[item.severity]} />
                        <Chip label={item.status} size="small" sx={vulnerabilityStatusChipSx[item.status]} />
                      </Stack>
                    </Box>
                  ))}
                  {vulnerabilities.length === 0 && (
                    <Typography color="text.secondary">Для выбранного хоста уязвимости не привязаны.</Typography>
                  )}
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
            <TextField select label="Статус" value={hostStatus} onChange={(e) => setHostStatus(e.target.value as Host["status"])}>
              <MenuItem value="up">up</MenuItem>
              <MenuItem value="down">down</MenuItem>
              <MenuItem value="unknown">unknown</MenuItem>
            </TextField>
            <TextField label="Описание" multiline minRows={3} value={hostNotes} onChange={(e) => setHostNotes(e.target.value)} />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setHostOpen(false)}>Отмена</Button>
          <Button variant="contained" disabled={!hostIp && !hostName} onClick={() => void submitHost()}>
            Сохранить
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={editHostOpen} onClose={() => setEditHostOpen(false)} fullWidth>
        <DialogTitle>Редактировать хост</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField label="IP-адрес" value={hostIp} onChange={(e) => setHostIp(e.target.value)} />
            <TextField label="Hostname" value={hostName} onChange={(e) => setHostName(e.target.value)} />
            <TextField select label="Статус" value={hostStatus} onChange={(e) => setHostStatus(e.target.value as Host["status"])}>
              <MenuItem value="up">up</MenuItem>
              <MenuItem value="down">down</MenuItem>
              <MenuItem value="unknown">unknown</MenuItem>
            </TextField>
            <TextField label="Описание" multiline minRows={3} value={hostNotes} onChange={(e) => setHostNotes(e.target.value)} />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditHostOpen(false)}>Отмена</Button>
          <Button variant="contained" disabled={!hostIp && !hostName} onClick={() => void submitHostEdit()}>
            Сохранить
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={vulnDetailOpen} onClose={() => setVulnDetailOpen(false)} fullWidth maxWidth="lg">
        <DialogTitle>Карточка уязвимости</DialogTitle>
        <DialogContent>
          {!activeVuln ? (
            <Typography color="text.secondary">Уязвимость не выбрана.</Typography>
          ) : (
            <Stack spacing={2} sx={{ mt: 0.5 }}>
              <Grid container spacing={2}>
                <Grid size={{ xs: 12, md: 8 }}>
                  <TextField
                    label="Название"
                    fullWidth
                    value={activeVuln.title}
                    onChange={(e) => setActiveVuln((prev) => (prev ? { ...prev, title: e.target.value } : prev))}
                  />
                </Grid>
                <Grid size={{ xs: 12, md: 2 }}>
                  <TextField
                    select
                    label="Критичность"
                    fullWidth
                    value={activeVuln.severity}
                    onChange={(e) => setActiveVuln((prev) => (prev ? { ...prev, severity: e.target.value as Vulnerability["severity"] } : prev))}
                  >
                    <MenuItem value="critical">critical</MenuItem>
                    <MenuItem value="high">high</MenuItem>
                    <MenuItem value="medium">medium</MenuItem>
                    <MenuItem value="low">low</MenuItem>
                    <MenuItem value="info">info</MenuItem>
                  </TextField>
                </Grid>
                <Grid size={{ xs: 12, md: 2 }}>
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
                </Grid>
                <Grid size={{ xs: 12 }}>
                  <TextField
                    label="Описание"
                    fullWidth
                    multiline
                    minRows={3}
                    value={activeVuln.description || ""}
                    onChange={(e) => setActiveVuln((prev) => (prev ? { ...prev, description: e.target.value || null } : prev))}
                  />
                </Grid>
                <Grid size={{ xs: 12, md: 3 }}>
                  <TextField
                    select
                    label="CVSS версия"
                    fullWidth
                    value={activeVuln.cvss_version || ""}
                    onChange={(e) => setActiveVuln((prev) => (prev ? { ...prev, cvss_version: (e.target.value as "3.1" | "4.0" | "") || null } : prev))}
                  >
                    <MenuItem value="">-</MenuItem>
                    <MenuItem value="3.1">3.1</MenuItem>
                    <MenuItem value="4.0">4.0</MenuItem>
                  </TextField>
                </Grid>
                <Grid size={{ xs: 12, md: 3 }}>
                  <TextField
                    label="CVSS score"
                    type="number"
                    fullWidth
                    value={activeVuln.cvss_score ?? ""}
                    onChange={(e) => {
                      const value = e.target.value;
                      setActiveVuln((prev) => (prev ? { ...prev, cvss_score: value === "" ? null : Number(value) } : prev));
                    }}
                  />
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField
                    label="CVSS vector"
                    fullWidth
                    value={activeVuln.cvss_vector || ""}
                    onChange={(e) => setActiveVuln((prev) => (prev ? { ...prev, cvss_vector: e.target.value || null } : prev))}
                  />
                </Grid>
                <Grid size={{ xs: 12 }}>
                  <TextField
                    label="CWE ID"
                    fullWidth
                    value={activeVuln.cwe_id || ""}
                    onChange={(e) => setActiveVuln((prev) => (prev ? { ...prev, cwe_id: e.target.value || null } : prev))}
                  />
                </Grid>
                <Grid size={{ xs: 12 }}>
                  <TextField
                    label="Шаги воспроизведения"
                    fullWidth
                    multiline
                    minRows={2}
                    value={activeVuln.steps_to_reproduce || ""}
                    onChange={(e) => setActiveVuln((prev) => (prev ? { ...prev, steps_to_reproduce: e.target.value || null } : prev))}
                  />
                </Grid>
                <Grid size={{ xs: 12 }}>
                  <TextField
                    label="Влияние"
                    fullWidth
                    multiline
                    minRows={2}
                    value={activeVuln.impact || ""}
                    onChange={(e) => setActiveVuln((prev) => (prev ? { ...prev, impact: e.target.value || null } : prev))}
                  />
                </Grid>
                <Grid size={{ xs: 12 }}>
                  <TextField
                    label="Рекомендации"
                    fullWidth
                    multiline
                    minRows={2}
                    value={activeVuln.recommendations || ""}
                    onChange={(e) => setActiveVuln((prev) => (prev ? { ...prev, recommendations: e.target.value || null } : prev))}
                  />
                </Grid>
              </Grid>

              <Divider />
              <Stack spacing={1}>
                <Typography variant="subtitle1" fontWeight={700}>
                  Файлы ({vulnFiles.length})
                </Typography>
                <Button component="label" variant="outlined" startIcon={<AttachFileIcon />}>
                  Загрузить файл
                  <input hidden type="file" onChange={(e) => void uploadFileToActiveVuln(e.target.files?.[0] ?? null)} />
                </Button>
                <List dense disablePadding>
                  {vulnFiles.map((file) => (
                    <ListItem
                      key={file.id}
                      secondaryAction={
                        <Stack direction="row" spacing={0.5}>
                          <IconButton size="small" component="a" href={`/api/v1/files/${file.id}/download`} target="_blank" rel="noreferrer">
                            <OpenInNewIcon fontSize="small" />
                          </IconButton>
                          <IconButton size="small" onClick={() => void removeVulnerabilityFile(file.id)}>
                            <DeleteOutlineIcon fontSize="small" />
                          </IconButton>
                        </Stack>
                      }
                    >
                      <ListItemText primary={file.original_name} secondary={`${file.content_type} • ${Math.round(file.size_bytes / 1024)} KB`} />
                    </ListItem>
                  ))}
                  {vulnFiles.length === 0 && <Typography color="text.secondary">Файлы не загружены.</Typography>}
                </List>
              </Stack>

              <Divider />
              <Stack spacing={1}>
                <Typography variant="subtitle1" fontWeight={700}>
                  Комментарии ({vulnComments.length})
                </Typography>
                <TextField
                  label="Новый комментарий (поддержка @username)"
                  multiline
                  minRows={2}
                  value={newComment}
                  onChange={(e) => setNewComment(e.target.value)}
                />
                <Button variant="contained" disabled={!newComment.trim()} onClick={() => void addCommentToActiveVuln()}>
                  Добавить комментарий
                </Button>
                <List dense disablePadding>
                  {vulnComments.map((comment) => (
                    <ListItem
                      key={comment.id}
                      alignItems="flex-start"
                      secondaryAction={
                        (user?.role === "admin" || user?.id === comment.user_id) && (
                          <IconButton size="small" onClick={() => void removeCommentFromActiveVuln(comment.id)}>
                            <DeleteOutlineIcon fontSize="small" />
                          </IconButton>
                        )
                      }
                    >
                      <ListItemText
                        primary={`${comment.username} • ${new Date(comment.created_at).toLocaleString()}`}
                        secondary={comment.content}
                      />
                    </ListItem>
                  ))}
                  {vulnComments.length === 0 && <Typography color="text.secondary">Комментариев пока нет.</Typography>}
                </List>
              </Stack>
            </Stack>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setVulnDetailOpen(false)}>Закрыть</Button>
          <Button color="error" variant="outlined" onClick={() => void removeActiveVulnerability()} disabled={!activeVuln || vulnBusy}>
            Удалить
          </Button>
          <Button variant="contained" onClick={() => void saveActiveVulnerability()} disabled={!activeVuln || vulnBusy}>
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
              label="Формат"
              value={exportFormat}
              onChange={(e) => setExportFormat(e.target.value as "md" | "pdf" | "docx")}
            >
              <MenuItem value="md">Markdown (.md)</MenuItem>
              <MenuItem value="pdf">PDF (.pdf)</MenuItem>
              <MenuItem value="docx">DOCX (.docx)</MenuItem>
            </TextField>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setExportOpen(false)}>Отмена</Button>
          <Button
            variant="contained"
            startIcon={<DownloadIcon />}
            disabled={reportLoadingFormat !== null}
            onClick={() => void downloadReport(exportFormat)}
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
        <DialogTitle>Участники проекта</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            {user?.role === "admin" && (
              <Stack direction={{ xs: "column", md: "row" }} spacing={1}>
                <TextField
                  select
                  fullWidth
                  label="Добавить пользователя"
                  value={selectedMemberUserId}
                  onChange={(event) => setSelectedMemberUserId(event.target.value)}
                >
                  {availableUsers.map((candidate) => (
                    <MenuItem key={candidate.id} value={candidate.id}>
                      {candidate.username} ({candidate.role})
                    </MenuItem>
                  ))}
                </TextField>
                <Button
                  variant="contained"
                  startIcon={<PersonAddAlt1Icon />}
                  disabled={!selectedMemberUserId || membersBusy}
                  onClick={() => void addMemberToProject()}
                >
                  Добавить
                </Button>
              </Stack>
            )}

            <List dense disablePadding>
              {projectMembers.map((member) => (
                <ListItem
                  key={member.user_id}
                  secondaryAction={
                    user?.role === "admin" ? (
                      <IconButton size="small" onClick={() => void removeMemberFromProject(member.user_id)} disabled={membersBusy}>
                        <DeleteOutlineIcon fontSize="small" />
                      </IconButton>
                    ) : null
                  }
                >
                  <ListItemText primary={`${member.username} (${member.role})`} secondary={member.email} />
                </ListItem>
              ))}
              {projectMembers.length === 0 && <Typography color="text.secondary">Участники пока не добавлены.</Typography>}
            </List>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setMembersDialogOpen(false)}>Закрыть</Button>
        </DialogActions>
      </Dialog>
    </Stack>
  );
}
