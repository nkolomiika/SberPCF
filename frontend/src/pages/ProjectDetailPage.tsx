import AddIcon from "@mui/icons-material/Add";
import ChevronLeftIcon from "@mui/icons-material/ChevronLeft";
import ChevronRightIcon from "@mui/icons-material/ChevronRight";
import DnsIcon from "@mui/icons-material/Dns";
import HubIcon from "@mui/icons-material/Hub";
import LanIcon from "@mui/icons-material/Lan";
import ReportProblemIcon from "@mui/icons-material/ReportProblem";
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
  ListItemButton,
  ListItemText,
  MenuItem,
  Paper,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { createEndpoint, createHost, createPort, createVulnerability, getEndpoints, getHosts, getPorts, getVulnerabilities } from "../api";
import type { Endpoint, Host, Port, Vulnerability } from "../types";

type DetailSection = "overview" | "hosts" | "ports" | "endpoints" | "vulns";

export function ProjectDetailPage() {
  const { projectId } = useParams<{ projectId: string }>();
  const [hosts, setHosts] = useState<Host[]>([]);
  const [ports, setPorts] = useState<Port[]>([]);
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [selectedHostId, setSelectedHostId] = useState<string | null>(null);
  const [selectedSection, setSelectedSection] = useState<DetailSection>("overview");
  const [isSidebarCollapsed, setSidebarCollapsed] = useState(false);

  const [hostOpen, setHostOpen] = useState(false);
  const [hostIp, setHostIp] = useState("");
  const [hostName, setHostName] = useState("");
  const [hostOs, setHostOs] = useState("");

  const [portOpen, setPortOpen] = useState(false);
  const [portNumber, setPortNumber] = useState("443");
  const [portProtocol, setPortProtocol] = useState<"tcp" | "udp">("tcp");

  const [endpointOpen, setEndpointOpen] = useState(false);
  const [endpointPath, setEndpointPath] = useState("");
  const [endpointMethod, setEndpointMethod] = useState<"GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS">("GET");
  const [endpointDescription, setEndpointDescription] = useState("");

  const [vulnOpen, setVulnOpen] = useState(false);
  const [vulnTitle, setVulnTitle] = useState("");
  const [vulnDescription, setVulnDescription] = useState("");
  const [vulnSeverity, setVulnSeverity] = useState<Vulnerability["severity"]>("medium");

  const loadProjectData = useCallback(async () => {
    if (!projectId) {
      return;
    }
    try {
      const [hostsResp, vulnsResp] = await Promise.all([getHosts(projectId), getVulnerabilities(projectId)]);
      setHosts(hostsResp.items);
      setVulnerabilities(vulnsResp.items);
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
      return;
    }
    try {
      const [portsResp, endpointsResp] = await Promise.all([getPorts(projectId, selectedHostId), getEndpoints(projectId, selectedHostId)]);
      setPorts(portsResp);
      setEndpoints(endpointsResp);
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
    await createHost(projectId, { ip_address: hostIp || undefined, hostname: hostName || undefined, os: hostOs || undefined });
    setHostOpen(false);
    setHostIp("");
    setHostName("");
    setHostOs("");
    await loadProjectData();
  };

  const submitPort = async () => {
    if (!projectId) {
      return;
    }
    if (!selectedHostId) {
      setError("Сначала выберите хост в левом меню");
      return;
    }
    await createPort(projectId, selectedHostId, { port_number: Number(portNumber), protocol: portProtocol });
    setPortOpen(false);
    setPortNumber("443");
    setPortProtocol("tcp");
    await loadHostAssets();
  };

  const submitEndpoint = async () => {
    if (!projectId) {
      return;
    }
    if (!selectedHostId) {
      setError("Сначала выберите хост в левом меню");
      return;
    }
    await createEndpoint(projectId, selectedHostId, {
      path: endpointPath,
      method: endpointMethod,
      description: endpointDescription || undefined,
    });
    setEndpointOpen(false);
    setEndpointPath("");
    setEndpointMethod("GET");
    setEndpointDescription("");
    await loadHostAssets();
  };

  const submitVulnerability = async () => {
    if (!projectId) {
      return;
    }
    await createVulnerability(projectId, { title: vulnTitle, description: vulnDescription || undefined, severity: vulnSeverity });
    setVulnOpen(false);
    setVulnTitle("");
    setVulnDescription("");
    setVulnSeverity("medium");
    await loadProjectData();
  };

  const selectedHost = hosts.find((host) => host.id === selectedHostId) ?? null;
  const hostLabel = selectedHost ? selectedHost.hostname || selectedHost.ip_address || "unknown-host" : "Хост не выбран";

  return (
    <Stack spacing={2.5}>
      {error && <Alert severity="error">{error}</Alert>}
      <Stack direction="row" justifyContent="space-between" alignItems="center">
        <Box>
          <Typography variant="h4" fontWeight={700}>
            Проект {projectId}
          </Typography>
          <Typography color="text.secondary">
            Матрешка навигации: проекты, хосты, порты и эндпоинты, плюс уязвимости проекта
          </Typography>
        </Box>
        <Stack direction="row" spacing={1}>
          <Button variant="outlined" startIcon={<AddIcon />} onClick={() => setHostOpen(true)}>
            Добавить хост
          </Button>
          {selectedSection === "ports" && (
            <Button variant="outlined" startIcon={<AddIcon />} onClick={() => setPortOpen(true)}>
              Добавить порт
            </Button>
          )}
          {selectedSection === "endpoints" && (
            <Button variant="outlined" startIcon={<AddIcon />} onClick={() => setEndpointOpen(true)}>
              Добавить эндпоинт
            </Button>
          )}
          <Button variant="contained" startIcon={<AddIcon />} onClick={() => setVulnOpen(true)}>
            Добавить уязвимость
          </Button>
        </Stack>
      </Stack>

      <Stack direction={{ xs: "column", md: "row" }} spacing={2}>
        <Paper
          sx={{
            width: { xs: "100%", md: isSidebarCollapsed ? 88 : 320 },
            transition: "width .2s ease",
            borderRadius: 3,
            border: "1px solid rgba(126,224,255,0.18)",
            overflow: "hidden",
            flexShrink: 0,
          }}
        >
          <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ px: 1.5, py: 1 }}>
            {!isSidebarCollapsed && (
              <Typography variant="subtitle2" fontWeight={700}>
                Структура проекта
              </Typography>
            )}
            <IconButton size="small" onClick={() => setSidebarCollapsed((v) => !v)}>
              {isSidebarCollapsed ? <ChevronRightIcon /> : <ChevronLeftIcon />}
            </IconButton>
          </Stack>
          <Divider />
          <List dense disablePadding>
            <ListItemButton selected={selectedSection === "overview"} onClick={() => setSelectedSection("overview")}>
              <HubIcon fontSize="small" />
              {!isSidebarCollapsed && <ListItemText sx={{ ml: 1 }} primary="Обзор проекта" />}
            </ListItemButton>

            <Divider sx={{ my: 0.5 }} />
            {!isSidebarCollapsed && (
              <Typography sx={{ px: 2, pt: 1, pb: 0.5 }} variant="caption" color="text.secondary">
                Хосты
              </Typography>
            )}
            {hosts.map((host) => {
              const label = host.hostname || host.ip_address || "unknown-host";
              const isActiveHost = selectedHostId === host.id;
              return (
                <Box key={host.id}>
                  <ListItemButton
                    selected={isActiveHost && selectedSection === "hosts"}
                    onClick={() => {
                      setSelectedHostId(host.id);
                      setSelectedSection("hosts");
                    }}
                  >
                    <DnsIcon fontSize="small" />
                    {!isSidebarCollapsed && <ListItemText sx={{ ml: 1 }} primary={label} secondary={host.os || "OS не указана"} />}
                  </ListItemButton>
                  {isActiveHost && !isSidebarCollapsed && (
                    <Stack sx={{ pl: 5, pr: 1, pb: 1 }} spacing={0.5}>
                      <ListItemButton
                        sx={{ borderRadius: 1 }}
                        selected={selectedSection === "ports"}
                        onClick={() => setSelectedSection("ports")}
                      >
                        <LanIcon fontSize="small" />
                        <ListItemText sx={{ ml: 1 }} primary={`Порты (${ports.length})`} />
                      </ListItemButton>
                      <ListItemButton
                        sx={{ borderRadius: 1 }}
                        selected={selectedSection === "endpoints"}
                        onClick={() => setSelectedSection("endpoints")}
                      >
                        <HubIcon fontSize="small" />
                        <ListItemText sx={{ ml: 1 }} primary={`Эндпоинты (${endpoints.length})`} />
                      </ListItemButton>
                    </Stack>
                  )}
                </Box>
              );
            })}
            <Divider sx={{ my: 0.5 }} />
            <ListItemButton selected={selectedSection === "vulns"} onClick={() => setSelectedSection("vulns")}>
              <ReportProblemIcon fontSize="small" />
              {!isSidebarCollapsed && <ListItemText sx={{ ml: 1 }} primary={`Уязвимости проекта (${vulnerabilities.length})`} />}
            </ListItemButton>
          </List>
        </Paper>

        <Stack flex={1} spacing={2}>
          <Card sx={{ border: "1px solid rgba(126,224,255,0.18)" }}>
            <CardContent>
              <Typography variant="h6" fontWeight={700}>
                {selectedSection === "overview" && "Обзор проекта"}
                {selectedSection === "hosts" && `Хост: ${hostLabel}`}
                {selectedSection === "ports" && `Порты хоста: ${hostLabel}`}
                {selectedSection === "endpoints" && `Эндпоинты хоста: ${hostLabel}`}
                {selectedSection === "vulns" && "Уязвимости проекта"}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Слева — древовидная навигация по проекту, как в wiki-страницах.
              </Typography>
            </CardContent>
          </Card>

          {selectedSection === "overview" && (
            <Grid container spacing={2}>
              <Grid size={{ xs: 12, md: 4 }}>
                <Card sx={{ border: "1px solid rgba(126,224,255,0.16)" }}>
                  <CardContent>
                    <Typography color="text.secondary">Хостов</Typography>
                    <Typography variant="h4" fontWeight={700}>
                      {hosts.length}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid size={{ xs: 12, md: 4 }}>
                <Card sx={{ border: "1px solid rgba(126,224,255,0.16)" }}>
                  <CardContent>
                    <Typography color="text.secondary">Портов (выбранный хост)</Typography>
                    <Typography variant="h4" fontWeight={700}>
                      {ports.length}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid size={{ xs: 12, md: 4 }}>
                <Card sx={{ border: "1px solid rgba(126,224,255,0.16)" }}>
                  <CardContent>
                    <Typography color="text.secondary">Уязвимостей</Typography>
                    <Typography variant="h4" fontWeight={700}>
                      {vulnerabilities.length}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          )}

          {selectedSection === "hosts" && (
            <Card sx={{ border: "1px solid rgba(126,224,255,0.16)" }}>
              <CardContent>
                <Stack spacing={1.2}>
                  {hosts.map((host) => (
                    <Box key={host.id} sx={{ border: "1px solid rgba(126,224,255,0.16)", p: 1.5, borderRadius: 2 }}>
                      <Typography>{host.hostname || host.ip_address || "unknown-host"}</Typography>
                      <Typography variant="body2" color="text.secondary">
                        {host.os || "OS не указана"}
                      </Typography>
                    </Box>
                  ))}
                </Stack>
              </CardContent>
            </Card>
          )}

          {selectedSection === "ports" && (
            <Card sx={{ border: "1px solid rgba(126,224,255,0.16)" }}>
              <CardContent>
                <Stack spacing={1.2}>
                  {ports.map((port) => (
                    <Box key={port.id} sx={{ border: "1px solid rgba(126,224,255,0.16)", p: 1.5, borderRadius: 2 }}>
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
            <Card sx={{ border: "1px solid rgba(126,224,255,0.16)" }}>
              <CardContent>
                <Stack spacing={1.2}>
                  {endpoints.map((endpoint) => (
                    <Box key={endpoint.id} sx={{ border: "1px solid rgba(126,224,255,0.16)", p: 1.5, borderRadius: 2 }}>
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
            <Card sx={{ border: "1px solid rgba(126,224,255,0.16)" }}>
              <CardContent>
                <Stack direction="row" spacing={1} mb={2} flexWrap="wrap">
                  {Object.entries(severityStats).map(([severity, value]) => (
                    <Chip key={severity} label={`${severity}: ${value}`} />
                  ))}
                </Stack>
                <Stack spacing={1.2}>
                  {vulnerabilities.map((item) => (
                    <Box key={item.id} sx={{ border: "1px solid rgba(126,224,255,0.16)", p: 1.5, borderRadius: 2 }}>
                      <Typography>{item.title}</Typography>
                      <Stack direction="row" spacing={1} mt={1}>
                        <Chip label={item.severity} size="small" />
                        <Chip label={item.status} size="small" color="warning" />
                      </Stack>
                    </Box>
                  ))}
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
            <TextField label="ОС" value={hostOs} onChange={(e) => setHostOs(e.target.value)} />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setHostOpen(false)}>Отмена</Button>
          <Button variant="contained" disabled={!hostIp && !hostName} onClick={() => void submitHost()}>
            Сохранить
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={portOpen} onClose={() => setPortOpen(false)} fullWidth>
        <DialogTitle>Добавить порт</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField
              label="Номер порта"
              value={portNumber}
              type="number"
              inputProps={{ min: 1, max: 65535 }}
              onChange={(e) => setPortNumber(e.target.value)}
            />
            <TextField select label="Протокол" value={portProtocol} onChange={(e) => setPortProtocol(e.target.value as "tcp" | "udp")}>
              <MenuItem value="tcp">TCP</MenuItem>
              <MenuItem value="udp">UDP</MenuItem>
            </TextField>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setPortOpen(false)}>Отмена</Button>
          <Button variant="contained" onClick={() => void submitPort()}>
            Сохранить
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={endpointOpen} onClose={() => setEndpointOpen(false)} fullWidth>
        <DialogTitle>Добавить эндпоинт</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField label="Путь" value={endpointPath} onChange={(e) => setEndpointPath(e.target.value)} />
            <TextField
              select
              label="HTTP-метод"
              value={endpointMethod}
              onChange={(e) =>
                setEndpointMethod(e.target.value as "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS")
              }
            >
              {["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map((method) => (
                <MenuItem key={method} value={method}>
                  {method}
                </MenuItem>
              ))}
            </TextField>
            <TextField
              label="Описание"
              multiline
              minRows={2}
              value={endpointDescription}
              onChange={(e) => setEndpointDescription(e.target.value)}
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEndpointOpen(false)}>Отмена</Button>
          <Button variant="contained" disabled={!endpointPath.trim()} onClick={() => void submitEndpoint()}>
            Сохранить
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={vulnOpen} onClose={() => setVulnOpen(false)} fullWidth>
        <DialogTitle>Добавить уязвимость</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField label="Название" value={vulnTitle} onChange={(e) => setVulnTitle(e.target.value)} />
            <TextField
              label="Описание"
              multiline
              minRows={3}
              value={vulnDescription}
              onChange={(e) => setVulnDescription(e.target.value)}
            />
            <TextField
              select
              label="Критичность"
              value={vulnSeverity}
              onChange={(e) => setVulnSeverity(e.target.value as Vulnerability["severity"])}
            >
              <MenuItem value="critical">critical</MenuItem>
              <MenuItem value="high">high</MenuItem>
              <MenuItem value="medium">medium</MenuItem>
              <MenuItem value="low">low</MenuItem>
              <MenuItem value="info">info</MenuItem>
            </TextField>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setVulnOpen(false)}>Отмена</Button>
          <Button variant="contained" disabled={!vulnTitle.trim()} onClick={() => void submitVulnerability()}>
            Сохранить
          </Button>
        </DialogActions>
      </Dialog>
    </Stack>
  );
}
