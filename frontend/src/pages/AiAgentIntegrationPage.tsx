import DeleteOutlineIcon from "@mui/icons-material/DeleteOutline";
import SmartToyOutlinedIcon from "@mui/icons-material/SmartToyOutlined";
import {
  Box,
  Button,
  Card,
  CardContent,
  Checkbox,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  FormGroup,
  IconButton,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import { useCallback, useEffect, useState } from "react";
import { Navigate } from "react-router-dom";
import {
  createAgentToken,
  getApiErrorMessage,
  getProjects,
  listAgentTokens,
  revokeAgentToken,
} from "../api";
import { useAuthStore, useToastStore } from "../store";
import type { AgentApiToken, Project } from "../types";

const SCOPE_OPTIONS = [
  { id: "projects:read", label: "projects:read — список проектов" },
  { id: "assets:read", label: "assets:read — хосты и активы" },
  { id: "notes:read", label: "notes:read — чтение заметок" },
  { id: "notes:write", label: "notes:write — изменение заметок" },
  { id: "vulns:read", label: "vulns:read — чтение уязвимостей" },
  { id: "vulns:write", label: "vulns:write — изменение уязвимостей" },
] as const;

export function AiAgentIntegrationPage() {
  const user = useAuthStore((s) => s.user);
  const pushToast = useToastStore((s) => s.pushToast);
  const [tokens, setTokens] = useState<AgentApiToken[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [newName, setNewName] = useState("");
  const [allProjects, setAllProjects] = useState(true);
  const [selectedProjectIds, setSelectedProjectIds] = useState<string[]>([]);
  const [scopes, setScopes] = useState<string[]>(() => SCOPE_OPTIONS.map((s) => s.id));
  const [revealedToken, setRevealedToken] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [tok, proj] = await Promise.all([listAgentTokens(), getProjects(1, 500)]);
      setTokens(tok);
      setProjects(proj.items);
    } catch (e) {
      setError(getApiErrorMessage(e, "Не удалось загрузить данные"));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const toggleScope = (id: string) => {
    setScopes((prev) => (prev.includes(id) ? prev.filter((s) => s !== id) : [...prev, id]));
  };

  const toggleProject = (id: string) => {
    setSelectedProjectIds((prev) => (prev.includes(id) ? prev.filter((p) => p !== id) : [...prev, id]));
  };

  const submitCreate = async () => {
    const name = newName.trim();
    if (!name) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const payload = {
        name,
        scopes: scopes.length ? scopes : ["projects:read", "assets:read", "notes:read", "vulns:read"],
        project_ids: allProjects ? [] : selectedProjectIds,
        all_projects: allProjects,
      };
      const created = await createAgentToken(payload);
      setRevealedToken(created.token);
      pushToast("Токен создан. Сохраните значение — оно показывается один раз.", "success");
      setCreateOpen(false);
      setNewName("");
      await load();
    } catch (e) {
      setError(getApiErrorMessage(e, "Не удалось создать токен"));
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (id: string) => {
    if (!window.confirm("Отозвать этот токен? клиенты с ним потеряют доступ.")) {
      return;
    }
    setBusy(true);
    try {
      await revokeAgentToken(id);
      pushToast("Токен отозван", "info");
      await load();
    } catch (e) {
      setError(getApiErrorMessage(e, "Не удалось отозвать токен"));
    } finally {
      setBusy(false);
    }
  };

  const formatTs = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleString("ru-RU") : "—");

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  if (user.role !== "admin") {
    return (
      <Box sx={{ p: 3 }}>
        <Typography variant="h6" fontWeight={700}>
          Интеграция с ИИ
        </Typography>
        <Typography color="text.secondary" sx={{ mt: 1 }}>
          Управление токенами API агента доступно только администраторам.
        </Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ p: { xs: 2, md: 3 }, maxWidth: 1100, mx: "auto" }}>
      <Stack direction="row" spacing={1} alignItems="center" mb={2}>
        <SmartToyOutlinedIcon color="primary" />
        <Typography variant="h5" fontWeight={700}>
          Интеграция с ИИ (API агента)
        </Typography>
      </Stack>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Bearer-токены для доступа к <strong>/api/v2</strong> из внешних ассистентов и скриптов. Храните секрет в надёжном месте.
      </Typography>

      {error && (
        <Typography color="error" variant="body2" sx={{ mb: 2 }}>
          {error}
        </Typography>
      )}

      <Stack direction="row" spacing={1} mb={2}>
        <Button variant="contained" onClick={() => setCreateOpen(true)} disabled={busy}>
          Новый токен
        </Button>
        <Button variant="outlined" onClick={() => void load()} disabled={loading}>
          Обновить список
        </Button>
      </Stack>

      <Card sx={{ border: "1px solid rgba(126,224,255,0.14)" }}>
        <CardContent>
          <Typography variant="subtitle1" fontWeight={700} mb={1}>
            Активные токены
          </Typography>
          {loading ? (
            <Typography color="text.secondary">Загрузка…</Typography>
          ) : tokens.length === 0 ? (
            <Typography color="text.secondary">Токены ещё не созданы.</Typography>
          ) : (
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Имя</TableCell>
                  <TableCell>Префикс</TableCell>
                  <TableCell>Проекты</TableCell>
                  <TableCell>Создан</TableCell>
                  <TableCell align="right" />
                </TableRow>
              </TableHead>
              <TableBody>
                {tokens.map((t) => (
                  <TableRow key={t.id}>
                    <TableCell>{t.name}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace" }}>{t.token_prefix}…</TableCell>
                    <TableCell>{t.all_projects ? "Все" : `${t.project_ids.length} выбран.`}</TableCell>
                    <TableCell>{formatTs(t.created_at)}</TableCell>
                    <TableCell align="right">
                      <IconButton size="small" aria-label="Отозвать токен" disabled={Boolean(t.revoked_at) || busy} onClick={() => void revoke(t.id)}>
                        <DeleteOutlineIcon fontSize="small" />
                      </IconButton>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Dialog open={createOpen} onClose={() => (busy ? undefined : setCreateOpen(false))} fullWidth maxWidth="sm">
        <DialogTitle>Новый токен агента</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField label="Название" value={newName} onChange={(e) => setNewName(e.target.value)} fullWidth required />
            <FormControlLabel control={<Checkbox checked={allProjects} onChange={(e) => setAllProjects(e.target.checked)} />} label="Доступ ко всем проектам" />
            {!allProjects && (
              <Box sx={{ maxHeight: 200, overflowY: "auto", border: "1px solid rgba(126,224,255,0.16)", p: 1 }}>
                <FormGroup>
                  {projects.map((p) => (
                    <FormControlLabel key={p.id} control={<Checkbox checked={selectedProjectIds.includes(p.id)} onChange={() => toggleProject(p.id)} />} label={p.name} />
                  ))}
                </FormGroup>
              </Box>
            )}
            <Typography variant="subtitle2" fontWeight={600}>
              Области (scopes)
            </Typography>
            <FormGroup>
              {SCOPE_OPTIONS.map((opt) => (
                <FormControlLabel key={opt.id} control={<Checkbox checked={scopes.includes(opt.id)} onChange={() => toggleScope(opt.id)} />} label={opt.label} />
              ))}
            </FormGroup>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateOpen(false)} disabled={busy}>
            Отмена
          </Button>
          <Button variant="contained" disabled={busy || !newName.trim()} onClick={() => void submitCreate()}>
            Создать
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={Boolean(revealedToken)} onClose={() => setRevealedToken(null)} fullWidth maxWidth="sm">
        <DialogTitle>Сохраните токен</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
            Значение больше не будет показано.
          </Typography>
          <TextField value={revealedToken ?? ""} fullWidth multiline minRows={3} InputProps={{ readOnly: true, sx: { fontFamily: "monospace", fontSize: "0.85rem" } }} />
        </DialogContent>
        <DialogActions>
          <Button
            onClick={async () => {
              if (revealedToken) {
                await navigator.clipboard.writeText(revealedToken);
                pushToast("Скопировано", "success");
              }
            }}
          >
            Копировать
          </Button>
          <Button variant="contained" onClick={() => setRevealedToken(null)}>
            Закрыть
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
