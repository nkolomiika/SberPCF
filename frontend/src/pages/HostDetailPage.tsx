import DeleteIcon from "@mui/icons-material/Delete";
import EditIcon from "@mui/icons-material/Edit";
import AddIcon from "@mui/icons-material/Add";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Grid2 as Grid,
  IconButton,
  MenuItem,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import { useCallback, useEffect, useState } from "react";
import ReactMarkdown from "react-markdown";
import { useNavigate, useParams } from "react-router-dom";
import {
  addVulnerabilityAsset,
  createEndpoint,
  createPort,
  createVulnerability,
  deleteEndpoint,
  deleteHost,
  deletePort,
  deleteVulnerability,
  getHost,
  getHosts,
  getHostVulnerabilities,
  updateEndpoint,
  updateHost,
  updatePort,
  updateVulnerability,
} from "../api";
import { ProjectTreeNav, type DetailSection } from "../components/ProjectTreeNav";
import type { Endpoint, Host, HostDetails, HostTreeStats, Port, Vulnerability } from "../types";

export function HostDetailPage() {
  const { projectId, hostId } = useParams<{ projectId: string; hostId: string }>();
  const navigate = useNavigate();

  const [host, setHost] = useState<HostDetails | null>(null);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [selectedSection, setSelectedSection] = useState<DetailSection>("overview");
  const [isSidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [isEditDescriptionOpen, setEditDescriptionOpen] = useState(false);
  const [editedDescription, setEditedDescription] = useState("");
  const [isSavingDescription, setSavingDescription] = useState(false);
  const [hostStatsById, setHostStatsById] = useState<Record<string, HostTreeStats>>({});
  const [isEditPortOpen, setEditPortOpen] = useState(false);
  const [editingPortId, setEditingPortId] = useState<string | null>(null);
  const [editingPortNumber, setEditingPortNumber] = useState("1");
  const [editingPortProtocol, setEditingPortProtocol] = useState<Port["protocol"]>("tcp");
  const [editingPortState, setEditingPortState] = useState<Port["state"]>("open");
  const [isEditEndpointOpen, setEditEndpointOpen] = useState(false);
  const [editingEndpointId, setEditingEndpointId] = useState<string | null>(null);
  const [editingEndpointPath, setEditingEndpointPath] = useState("");
  const [editingEndpointMethod, setEditingEndpointMethod] = useState<Exclude<Endpoint["method"], null>>("GET");
  const [editingEndpointDescription, setEditingEndpointDescription] = useState("");
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
  const [isCreateVulnerabilityOpen, setCreateVulnerabilityOpen] = useState(false);
  const [creatingVulnerabilityTitle, setCreatingVulnerabilityTitle] = useState("");
  const [creatingVulnerabilityDescription, setCreatingVulnerabilityDescription] = useState("");
  const [creatingVulnerabilitySeverity, setCreatingVulnerabilitySeverity] = useState<Vulnerability["severity"]>("medium");
  const [creatingVulnerabilityStatus, setCreatingVulnerabilityStatus] = useState<Vulnerability["status"]>("open");

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
      setEditedDescription(hostResponse.notes ?? "");
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

  const saveHostDescription = async () => {
    if (!projectId || !hostId) {
      return;
    }
    setSavingDescription(true);
    setError(null);
    try {
      const updatedHost = await updateHost(projectId, hostId, { notes: editedDescription.trim() || undefined });
      setHost((previous) => (previous ? { ...previous, notes: updatedHost.notes } : previous));
      setEditDescriptionOpen(false);
    } catch {
      setError("Не удалось обновить описание хоста.");
    } finally {
      setSavingDescription(false);
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

  const openEndpointEdit = (endpoint: Endpoint) => {
    setEditingEndpointId(endpoint.id);
    setEditingEndpointPath(endpoint.path);
    setEditingEndpointMethod(endpoint.method || "GET");
    setEditingEndpointDescription(endpoint.description || "");
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
    });
    setEditEndpointOpen(false);
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
      path: creatingEndpointPath.trim(),
      method: creatingEndpointMethod,
      description: creatingEndpointDescription.trim() || undefined,
    });
    setCreateEndpointOpen(false);
    setCreatingEndpointPath("");
    setCreatingEndpointMethod("GET");
    setCreatingEndpointDescription("");
    await loadHost();
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

      <Stack direction="row" justifyContent="space-between" alignItems="center" flexWrap="wrap" gap={1}>
        <Stack spacing={0.4}>
          <Typography variant="h4" fontWeight={700}>
            Хост: {hostTitle}
          </Typography>
          <Typography color="text.secondary">Навигация по разделам хоста через интерактивные карточки.</Typography>
        </Stack>
        <Button color="error" variant="outlined" startIcon={<DeleteIcon />} onClick={() => void removeHost()}>
          Удалить хост
        </Button>
      </Stack>

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
                  <Stack direction="row" justifyContent="space-between" alignItems="center" mb={1}>
                    <Typography variant="h6" fontWeight={700}>
                      Описание хоста
                    </Typography>
                    <Button
                      variant="outlined"
                      size="small"
                      startIcon={<EditIcon fontSize="small" />}
                      onClick={() => {
                        setEditedDescription(host?.notes ?? "");
                        setEditDescriptionOpen(true);
                      }}
                    >
                      Редактировать описание
                    </Button>
                  </Stack>
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
                      direction="row"
                      justifyContent="space-between"
                      alignItems="center"
                      sx={{ border: "1px solid rgba(126,224,255,0.12)", p: 1.2, borderRadius: 0 }}
                    >
                      <Stack direction="row" spacing={1} alignItems="center">
                        <Typography fontWeight={600}>
                          {port.port_number}/{port.protocol}
                        </Typography>
                        <Chip label={port.state} size="small" />
                      </Stack>
                      <Stack direction="row" spacing={0.4}>
                        <Tooltip title="Редактировать">
                          <IconButton size="small" onClick={() => openPortEdit(port)}>
                            <EditIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Удалить">
                          <IconButton size="small" color="error" onClick={() => void removePort(port.id)}>
                            <DeleteIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </Stack>
                    </Stack>
                  ))}
                  {!host?.ports.length && <Typography color="text.secondary">Порты для этого хоста пока не добавлены.</Typography>}
                </Stack>
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
                  <Tooltip title="Добавить эндпоинт">
                    <IconButton size="small" onClick={() => setCreateEndpointOpen(true)}>
                      <AddIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                </Stack>
                <Stack spacing={1}>
                  {host?.endpoints.map((endpoint) => (
                    <Box key={endpoint.id} sx={{ border: "1px solid rgba(126,224,255,0.12)", p: 1.2, borderRadius: 0 }}>
                      <Stack direction="row" spacing={1} alignItems="center" justifyContent="space-between">
                        <Stack direction="row" spacing={1} alignItems="center">
                          <Chip size="small" label={endpoint.method || "ANY"} />
                          <Typography fontWeight={600}>{endpoint.path}</Typography>
                        </Stack>
                        <Stack direction="row" spacing={0.4}>
                          <Tooltip title="Редактировать">
                            <IconButton size="small" onClick={() => openEndpointEdit(endpoint)}>
                              <EditIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Удалить">
                            <IconButton size="small" color="error" onClick={() => void removeEndpoint(endpoint.id)}>
                              <DeleteIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        </Stack>
                      </Stack>
                      <Typography mt={0.8} color="text.secondary" variant="body2">
                        {endpoint.description || "Описание не указано"}
                      </Typography>
                    </Box>
                  ))}
                  {!host?.endpoints.length && <Typography color="text.secondary">Эндпоинты для этого хоста пока не добавлены.</Typography>}
                </Stack>
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
                    <Box key={item.id} sx={{ border: "1px solid rgba(126,224,255,0.12)", p: 1.2, borderRadius: 0 }}>
                      <Stack direction="row" justifyContent="space-between" alignItems="center">
                        <Stack spacing={0.8}>
                          <Typography fontWeight={600}>{item.title}</Typography>
                          <Stack direction="row" spacing={1}>
                            <Chip size="small" label={item.severity} sx={severityChipSx[item.severity]} />
                            <Chip size="small" label={item.status} sx={vulnerabilityStatusChipSx[item.status]} />
                          </Stack>
                        </Stack>
                        <Stack direction="row" spacing={0.4} alignItems="center">
                          <Tooltip title="Редактировать">
                            <IconButton size="small" onClick={() => openVulnerabilityEdit(item)}>
                              <EditIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Удалить">
                            <IconButton size="small" color="error" onClick={() => void removeVulnerability(item.id)}>
                              <DeleteIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        </Stack>
                      </Stack>
                    </Box>
                  ))}
                  {!vulnerabilities.length && <Typography color="text.secondary">Уязвимости, привязанные к этому хосту, пока не добавлены.</Typography>}
                </Stack>
              </CardContent>
            </Card>
          )}
        </Stack>
      </Stack>

      <Dialog open={isEditDescriptionOpen} onClose={() => setEditDescriptionOpen(false)} fullWidth maxWidth="md">
        <DialogTitle>Редактирование описания хоста</DialogTitle>
        <DialogContent>
          <TextField
            multiline
            minRows={6}
            fullWidth
            label="Описание"
            value={editedDescription}
            onChange={(event) => setEditedDescription(event.target.value)}
            sx={{ mt: 1 }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditDescriptionOpen(false)} disabled={isSavingDescription}>
            Отмена
          </Button>
          <Button variant="contained" onClick={() => void saveHostDescription()} disabled={isSavingDescription}>
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

      <Dialog open={isEditEndpointOpen} onClose={() => setEditEndpointOpen(false)} fullWidth>
        <DialogTitle>Редактировать эндпоинт</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
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
          <Button variant="contained" onClick={() => void createHostEndpoint()} disabled={!creatingEndpointPath.trim()}>
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
