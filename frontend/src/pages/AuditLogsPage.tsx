import AccessTimeIcon from "@mui/icons-material/AccessTime";
import ExpandLessIcon from "@mui/icons-material/ExpandLess";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import FilterAltOffIcon from "@mui/icons-material/FilterAltOff";
import PersonOutlineIcon from "@mui/icons-material/PersonOutline";
import RefreshIcon from "@mui/icons-material/Refresh";
import SearchIcon from "@mui/icons-material/Search";
import TuneIcon from "@mui/icons-material/Tune";
import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Collapse,
  Divider,
  FormControlLabel,
  IconButton,
  MenuItem,
  Stack,
  Switch,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { getApiErrorMessage, getAuditLogs } from "../api";
import type { AuditLog } from "../types";
import { useErrorToast } from "../useErrorToast";

const formatDateTime = (value: string) =>
  new Date(value).toLocaleString("ru-RU", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

const auditActionOptions = ["LOGIN", "LOGOUT", "CREATE", "UPDATE", "DELETE", "FILE_UPLOAD", "FILE_DELETE"] as const;
const auditEntityTypeOptions = [
  "project",
  "project_member",
  "project_folder",
  "host",
  "port",
  "service",
  "endpoint",
  "vulnerability",
  "vulnerability_asset",
  "file",
  "comment",
  "user",
  "user_profile",
  "user_password",
  "user_password_reset",
] as const;

export function AuditLogsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [items, setItems] = useState<AuditLog[]>([]);
  const [page, setPage] = useState(Math.max(1, Number(searchParams.get("page") || "1") || 1));
  const [pages, setPages] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedDetailsId, setExpandedDetailsId] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(searchParams.get("auto_refresh") !== "0");
  const [filters, setFilters] = useState({
    query: searchParams.get("query") || "",
    username: searchParams.get("username") || "",
    action: searchParams.get("action") || "",
    entity_type: searchParams.get("entity_type") || "",
    ip_address: searchParams.get("ip_address") || "",
    created_from: searchParams.get("created_from") || "",
    created_to: searchParams.get("created_to") || "",
  });
  const [draftFilters, setDraftFilters] = useState(filters);

  useErrorToast(error);

  const loadLogs = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await getAuditLogs(page, 50, {
        query: filters.query.trim() || undefined,
        username: filters.username.trim() || undefined,
        action: filters.action.trim() || undefined,
        entity_type: filters.entity_type.trim() || undefined,
        ip_address: filters.ip_address.trim() || undefined,
        created_from: filters.created_from || undefined,
        created_to: filters.created_to || undefined,
      });
      setItems(response.items);
      setPages(response.pages);
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось загрузить журнал действий."));
    } finally {
      setLoading(false);
    }
  }, [filters, page]);

  useEffect(() => {
    void loadLogs();
  }, [loadLogs]);

  useEffect(() => {
    if (!autoRefresh) {
      return;
    }
    const timer = window.setInterval(() => {
      void loadLogs();
    }, 10000);
    return () => window.clearInterval(timer);
  }, [autoRefresh, loadLogs]);

  useEffect(() => {
    const params = new URLSearchParams();
    params.set("page", String(page));
    if (filters.query.trim()) {
      params.set("query", filters.query.trim());
    }
    if (filters.username.trim()) {
      params.set("username", filters.username.trim());
    }
    if (filters.action.trim()) {
      params.set("action", filters.action.trim());
    }
    if (filters.entity_type.trim()) {
      params.set("entity_type", filters.entity_type.trim());
    }
    if (filters.ip_address.trim()) {
      params.set("ip_address", filters.ip_address.trim());
    }
    if (filters.created_from) {
      params.set("created_from", filters.created_from);
    }
    if (filters.created_to) {
      params.set("created_to", filters.created_to);
    }
    if (!autoRefresh) {
      params.set("auto_refresh", "0");
    }
    setSearchParams(params, { replace: true });
  }, [autoRefresh, filters, page, setSearchParams]);

  const actionsSummary = useMemo(() => {
    const uniqueActions = new Set(items.map((item) => item.action));
    const uniqueEntityTypes = new Set(items.map((item) => item.entity_type).filter(Boolean));
    return {
      total: items.length,
      uniqueActions: uniqueActions.size,
      uniqueEntityTypes: uniqueEntityTypes.size,
    };
  }, [items]);

  const quickActionOptions = useMemo(() => {
    return Array.from(new Set([...auditActionOptions, ...items.map((item) => item.action)])).slice(0, 20);
  }, [items]);

  const quickEntityTypeOptions = useMemo(() => {
    return Array.from(new Set([...auditEntityTypeOptions, ...(items.map((item) => item.entity_type).filter(Boolean) as string[])])).slice(0, 20);
  }, [items]);

  const applyFilters = () => {
    setFilters({
      query: draftFilters.query.trim(),
      username: draftFilters.username.trim(),
      action: draftFilters.action.trim(),
      entity_type: draftFilters.entity_type.trim(),
      ip_address: draftFilters.ip_address.trim(),
      created_from: draftFilters.created_from,
      created_to: draftFilters.created_to,
    });
    setPage(1);
  };

  const resetFilters = () => {
    const emptyFilters = {
      query: "",
      username: "",
      action: "",
      entity_type: "",
      ip_address: "",
      created_from: "",
      created_to: "",
    };
    setDraftFilters(emptyFilters);
    setFilters(emptyFilters);
    setPage(1);
  };

  const setDraftField = (field: keyof typeof draftFilters, value: string) => {
    setDraftFilters((prev) => ({ ...prev, [field]: value }));
  };

  const toggleQuickAction = (action: string) => {
    const nextValue = draftFilters.action === action ? "" : action;
    const nextFilters = { ...draftFilters, action: nextValue };
    setDraftFilters(nextFilters);
    setFilters((prev) => ({ ...prev, action: nextValue }));
    setPage(1);
  };

  const toggleQuickEntityType = (entityType: string) => {
    const nextValue = draftFilters.entity_type === entityType ? "" : entityType;
    const nextFilters = { ...draftFilters, entity_type: nextValue };
    setDraftFilters(nextFilters);
    setFilters((prev) => ({ ...prev, entity_type: nextValue }));
    setPage(1);
  };

  const visibleDetailsCount = useMemo(
    () => items.filter((item) => item.details && Object.keys(item.details).length > 0).length,
    [items]
  );

  const renderDetailsPreview = (details: Record<string, unknown> | null) => {
    if (!details) {
      return null;
    }
    return Object.entries(details)
      .slice(0, 4)
      .map(([key, value]) => (
        <Chip
          key={key}
          size="small"
          variant="outlined"
          label={`${key}: ${typeof value === "object" ? JSON.stringify(value) : String(value)}`}
          sx={{ maxWidth: 260 }}
        />
      ));
  };

  return (
    <Stack spacing={2.5}>
      <Card sx={{ border: "1px solid rgba(126,224,255,0.14)" }}>
        <CardContent sx={{ pb: "16px !important" }}>
          <Stack spacing={2}>
            <Stack direction={{ xs: "column", md: "row" }} justifyContent="space-between" alignItems={{ md: "center" }} gap={1}>
              <Stack spacing={0.3}>
                <Typography variant="h4" fontWeight={700}>
                  Журнал действий
                </Typography>
                <Typography color="text.secondary">Операционный поток событий по системе, пользователям и данным проекта.</Typography>
              </Stack>
              <Stack direction="row" spacing={1} alignItems="center">
                <FormControlLabel
                  control={<Switch checked={autoRefresh} onChange={(event) => setAutoRefresh(event.target.checked)} />}
                  label="Автообновление"
                />
                <Tooltip title="Обновить">
                  <span>
                    <IconButton onClick={() => void loadLogs()} disabled={loading}>
                      <RefreshIcon />
                    </IconButton>
                  </span>
                </Tooltip>
              </Stack>
            </Stack>

            <Stack direction={{ xs: "column", md: "row" }} spacing={1} alignItems={{ md: "center" }} flexWrap="wrap" useFlexGap>
              <Chip label={`Событий на странице: ${actionsSummary.total}`} variant="outlined" />
              <Chip label={`Типов действий: ${actionsSummary.uniqueActions}`} variant="outlined" />
              <Chip label={`Типов сущностей: ${actionsSummary.uniqueEntityTypes}`} variant="outlined" />
              <Chip label={`С деталями: ${visibleDetailsCount}`} variant="outlined" />
            </Stack>

            <Divider />

            <Stack direction={{ xs: "column", md: "row" }} spacing={1.2} alignItems={{ md: "flex-start" }}>
              <Stack flex={1} spacing={1.2}>
                <Stack direction={{ xs: "column", md: "row" }} spacing={1.2}>
                  <TextField
                    label="Поиск по логу"
                    value={draftFilters.query}
                    onChange={(event) => setDraftField("query", event.target.value)}
                    placeholder="action, user, details, ip"
                    fullWidth
                  />
                  <TextField
                    label="Пользователь"
                    value={draftFilters.username}
                    onChange={(event) => setDraftField("username", event.target.value)}
                    fullWidth
                  />
                  <TextField select label="Action" value={draftFilters.action} onChange={(event) => setDraftField("action", event.target.value)} fullWidth>
                    <MenuItem value="">Все действия</MenuItem>
                    {quickActionOptions.map((action) => (
                      <MenuItem key={action} value={action}>
                        {action}
                      </MenuItem>
                    ))}
                  </TextField>
                </Stack>
                <Stack direction={{ xs: "column", md: "row" }} spacing={1.2}>
                  <TextField select label="Сущность" value={draftFilters.entity_type} onChange={(event) => setDraftField("entity_type", event.target.value)} fullWidth>
                    <MenuItem value="">Все сущности</MenuItem>
                    {quickEntityTypeOptions.map((entityType) => (
                      <MenuItem key={entityType} value={entityType}>
                        {entityType}
                      </MenuItem>
                    ))}
                  </TextField>
                  <TextField
                    label="IP"
                    value={draftFilters.ip_address}
                    onChange={(event) => setDraftField("ip_address", event.target.value)}
                    fullWidth
                  />
                  <TextField
                    label="От"
                    type="datetime-local"
                    value={draftFilters.created_from}
                    onChange={(event) => setDraftField("created_from", event.target.value)}
                    InputLabelProps={{ shrink: true }}
                    fullWidth
                  />
                  <TextField
                    label="До"
                    type="datetime-local"
                    value={draftFilters.created_to}
                    onChange={(event) => setDraftField("created_to", event.target.value)}
                    InputLabelProps={{ shrink: true }}
                    fullWidth
                  />
                </Stack>
              </Stack>
              <Stack direction={{ xs: "row", md: "column" }} spacing={1}>
                <Tooltip title="Применить фильтры">
                  <span>
                    <IconButton color="primary" onClick={applyFilters} disabled={loading}>
                      <SearchIcon />
                    </IconButton>
                  </span>
                </Tooltip>
                <Tooltip title="Сбросить фильтры">
                  <span>
                    <IconButton onClick={resetFilters} disabled={loading}>
                      <FilterAltOffIcon />
                    </IconButton>
                  </span>
                </Tooltip>
              </Stack>
            </Stack>

            <Stack spacing={0.8}>
              <Typography variant="body2" color="text.secondary">
                Быстрые действия
              </Typography>
              <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                {quickActionOptions.map((action) => (
                  <Chip
                    key={action}
                    label={action}
                    color={filters.action === action ? "primary" : "default"}
                    variant={filters.action === action ? "filled" : "outlined"}
                    onClick={() => toggleQuickAction(action)}
                  />
                ))}
              </Stack>
            </Stack>

            <Stack spacing={0.8}>
              <Typography variant="body2" color="text.secondary">
                Быстрые сущности
              </Typography>
              <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                {quickEntityTypeOptions.map((entityType) => (
                  <Chip
                    key={entityType}
                    label={entityType}
                    color={filters.entity_type === entityType ? "primary" : "default"}
                    variant={filters.entity_type === entityType ? "filled" : "outlined"}
                    onClick={() => toggleQuickEntityType(entityType)}
                  />
                ))}
              </Stack>
            </Stack>
          </Stack>
        </CardContent>
      </Card>

      <Stack spacing={1}>
        {items.map((item) => (
          <Card
            key={item.id}
            sx={{
              borderRadius: 0,
              border: "1px solid rgba(126,224,255,0.12)",
              borderLeft: "3px solid rgba(126,224,255,0.35)",
              backgroundColor: "rgba(8,17,31,0.28)",
            }}
          >
            <CardContent>
              <Stack spacing={1.2}>
                <Stack direction={{ xs: "column", md: "row" }} justifyContent="space-between" gap={1}>
                  <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap">
                    <Chip size="small" icon={<TuneIcon />} label={item.action} />
                    {item.entity_type && <Chip size="small" variant="outlined" label={item.entity_type} />}
                    {item.entity_id && <Chip size="small" variant="outlined" label={`ID: ${item.entity_id}`} />}
                  </Stack>
                  <Stack direction="row" spacing={0.8} alignItems="center">
                    <AccessTimeIcon fontSize="small" color="disabled" />
                    <Typography variant="body2" color="text.secondary">
                      {formatDateTime(item.created_at)}
                    </Typography>
                  </Stack>
                </Stack>

                <Stack direction={{ xs: "column", md: "row" }} spacing={2} alignItems={{ md: "center" }}>
                  <Stack direction="row" spacing={0.8} alignItems="center">
                    <PersonOutlineIcon fontSize="small" color="disabled" />
                    <Typography variant="body2">{item.username || item.user_id || "system"}</Typography>
                  </Stack>
                  <Chip size="small" variant="outlined" label={`IP: ${item.ip_address || "-"}`} />
                  {item.entity_id && <Chip size="small" variant="outlined" label={`ID: ${item.entity_id}`} />}
                </Stack>

                {item.details && Object.keys(item.details).length > 0 && (
                  <>
                    <Stack direction="row" spacing={0.8} flexWrap="wrap" useFlexGap>
                      {renderDetailsPreview(item.details)}
                    </Stack>
                    <Divider />
                    <Stack spacing={0.8}>
                      <Box display="flex" justifyContent="flex-end">
                        <Tooltip title={expandedDetailsId === item.id ? "Скрыть параметры" : "Показать параметры"}>
                          <IconButton onClick={() => setExpandedDetailsId((prev) => (prev === item.id ? null : item.id))}>
                            {expandedDetailsId === item.id ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                          </IconButton>
                        </Tooltip>
                      </Box>
                      <Collapse in={expandedDetailsId === item.id} timeout="auto" unmountOnExit>
                        <Box
                          sx={{
                            border: "1px solid rgba(126,224,255,0.12)",
                            backgroundColor: "rgba(126,224,255,0.04)",
                            p: 1.2,
                            overflowX: "auto",
                          }}
                        >
                          <Typography
                            component="pre"
                            sx={{
                              m: 0,
                              fontSize: 12,
                              whiteSpace: "pre-wrap",
                              wordBreak: "break-word",
                              fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, Liberation Mono, monospace",
                            }}
                          >
                            {JSON.stringify(item.details, null, 2)}
                          </Typography>
                        </Box>
                      </Collapse>
                    </Stack>
                  </>
                )}
              </Stack>
            </CardContent>
          </Card>
        ))}
        {!items.length && !loading && (
          <Typography color="text.secondary">Записей в журнале не найдено.</Typography>
        )}
      </Stack>

      <Stack direction="row" spacing={1} justifyContent="flex-end">
        <Button variant="outlined" disabled={page <= 1 || loading} onClick={() => setPage((prev) => Math.max(1, prev - 1))}>
          Назад
        </Button>
        <Typography alignSelf="center" color="text.secondary">
          Страница {page} из {pages}
        </Typography>
        <Button variant="outlined" disabled={page >= pages || loading} onClick={() => setPage((prev) => prev + 1)}>
          Вперед
        </Button>
      </Stack>
    </Stack>
  );
}
