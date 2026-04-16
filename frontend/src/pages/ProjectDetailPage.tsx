import AddIcon from "@mui/icons-material/Add";
import EditIcon from "@mui/icons-material/Edit";
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
  Grid2 as Grid,
  MenuItem,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { createHost, getEndpoints, getHostVulnerabilities, getHosts, getPorts, getProjectMembers, getProjects, updateHost } from "../api";
import { ProjectTreeNav, type DetailSection } from "../components/ProjectTreeNav";
import type { Endpoint, Host, HostTreeStats, Port, ProjectMember, Vulnerability } from "../types";

export function ProjectDetailPage() {
  const { projectId } = useParams<{ projectId: string }>();
  const navigate = useNavigate();
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
  const [hostStatsById, setHostStatsById] = useState<Record<string, HostTreeStats>>({});

  const [hostOpen, setHostOpen] = useState(false);
  const [hostIp, setHostIp] = useState("");
  const [hostName, setHostName] = useState("");
  const [hostStatus, setHostStatus] = useState<Host["status"]>("unknown");
  const [hostNotes, setHostNotes] = useState("");
  const [editHostOpen, setEditHostOpen] = useState(false);

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

  return (
    <Stack spacing={2.5}>
      {error && <Alert severity="error">{error}</Alert>}
      <Stack direction="row" justifyContent="space-between" alignItems="center">
        <Box>
          <Typography variant="h4" fontWeight={700}>
            {projectName ? `Проект: ${projectName}` : "Проект"}
          </Typography>
          <Typography color="text.secondary">
            Матрешка навигации: проекты, хосты, порты, эндпоинты и уязвимости хоста
          </Typography>
        </Box>
        <Stack direction="row" spacing={1}>
          <Button variant="outlined" startIcon={<AddIcon />} onClick={() => setHostOpen(true)}>
            Добавить хост
          </Button>
          <Button variant="contained" startIcon={<EditIcon />} onClick={openEditHost} disabled={!selectedHost}>
            Редактировать
          </Button>
        </Stack>
      </Stack>

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
                      <Typography>{item.title}</Typography>
                      <Stack direction="row" spacing={1} mt={1}>
                        <Chip label={item.severity} size="small" />
                        <Chip label={item.status} size="small" color="warning" />
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
    </Stack>
  );
}
