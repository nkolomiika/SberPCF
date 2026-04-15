import AddIcon from "@mui/icons-material/Add";
import SecurityIcon from "@mui/icons-material/Security";
import StorageIcon from "@mui/icons-material/Storage";
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
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { useEffect, useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { createHost, createVulnerability, getHosts, getVulnerabilities } from "../api";
import type { Host, Vulnerability } from "../types";

export function ProjectDetailPage() {
  const { projectId } = useParams<{ projectId: string }>();
  const [hosts, setHosts] = useState<Host[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [error, setError] = useState<string | null>(null);

  const [hostOpen, setHostOpen] = useState(false);
  const [hostIp, setHostIp] = useState("");
  const [hostName, setHostName] = useState("");
  const [hostOs, setHostOs] = useState("");

  const [vulnOpen, setVulnOpen] = useState(false);
  const [vulnTitle, setVulnTitle] = useState("");
  const [vulnSeverity, setVulnSeverity] = useState<Vulnerability["severity"]>("medium");

  const loadData = async () => {
    if (!projectId) {
      return;
    }
    try {
      const [hostsResp, vulnsResp] = await Promise.all([getHosts(projectId), getVulnerabilities(projectId)]);
      setHosts(hostsResp.items);
      setVulnerabilities(vulnsResp.items);
    } catch {
      setError("Не удалось загрузить данные проекта");
    }
  };

  useEffect(() => {
    void loadData();
  }, [projectId]);

  useEffect(() => {
    if (!projectId) {
      return;
    }
    const wsProtocol = window.location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${wsProtocol}://${window.location.host}/ws/projects/${projectId}`);
    ws.onmessage = () => {
      void loadData();
    };
    return () => ws.close();
  }, [projectId]);

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
    await loadData();
  };

  const submitVulnerability = async () => {
    if (!projectId) {
      return;
    }
    await createVulnerability(projectId, { title: vulnTitle, severity: vulnSeverity });
    setVulnOpen(false);
    setVulnTitle("");
    setVulnSeverity("medium");
    await loadData();
  };

  return (
    <Stack spacing={3}>
      {error && <Alert severity="error">{error}</Alert>}
      <Stack direction="row" justifyContent="space-between" alignItems="center">
        <Box>
          <Typography variant="h4" fontWeight={700}>
            Проект {projectId}
          </Typography>
          <Typography color="text.secondary">Активы, уязвимости и синхронизация в реальном времени</Typography>
        </Box>
        <Stack direction="row" spacing={1}>
          <Button variant="outlined" startIcon={<AddIcon />} onClick={() => setHostOpen(true)}>
            Добавить хост
          </Button>
          <Button variant="contained" startIcon={<AddIcon />} onClick={() => setVulnOpen(true)}>
            Добавить уязвимость
          </Button>
        </Stack>
      </Stack>

      <Grid container spacing={2}>
        <Grid size={{ xs: 12, md: 6 }}>
          <Card sx={{ border: "1px solid #2a3c5f" }}>
            <CardContent>
              <Stack direction="row" alignItems="center" spacing={1} mb={2}>
                <StorageIcon color="primary" />
                <Typography variant="h6">Хосты ({hosts.length})</Typography>
              </Stack>
              <Stack spacing={1.2}>
                {hosts.map((host) => (
                  <Box key={host.id} sx={{ border: "1px solid #2a3c5f", p: 1.5, borderRadius: 2 }}>
                    <Typography>{host.ip_address || host.hostname || "unknown"}</Typography>
                    <Typography variant="body2" color="text.secondary">
                      {host.os || "OS не указана"}
                    </Typography>
                  </Box>
                ))}
              </Stack>
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 12, md: 6 }}>
          <Card sx={{ border: "1px solid #2a3c5f" }}>
            <CardContent>
              <Stack direction="row" alignItems="center" spacing={1} mb={2}>
                <SecurityIcon color="error" />
                <Typography variant="h6">Уязвимости ({vulnerabilities.length})</Typography>
              </Stack>
              <Stack direction="row" spacing={1} mb={2} flexWrap="wrap">
                {Object.entries(severityStats).map(([severity, value]) => (
                  <Chip key={severity} label={`${severity}: ${value}`} />
                ))}
              </Stack>
              <Stack spacing={1.2}>
                {vulnerabilities.map((item) => (
                  <Box key={item.id} sx={{ border: "1px solid #2a3c5f", p: 1.5, borderRadius: 2 }}>
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
        </Grid>
      </Grid>

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

      <Dialog open={vulnOpen} onClose={() => setVulnOpen(false)} fullWidth>
        <DialogTitle>Добавить уязвимость</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField label="Название" value={vulnTitle} onChange={(e) => setVulnTitle(e.target.value)} />
            <TextField
              label="Критичность (critical/high/medium/low/info)"
              value={vulnSeverity}
              onChange={(e) => setVulnSeverity(e.target.value as Vulnerability["severity"])}
            />
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
