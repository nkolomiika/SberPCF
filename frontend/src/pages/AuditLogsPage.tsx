import AccessTimeIcon from "@mui/icons-material/AccessTime";
import FilterAltOffIcon from "@mui/icons-material/FilterAltOff";
import PersonOutlineIcon from "@mui/icons-material/PersonOutline";
import TuneIcon from "@mui/icons-material/Tune";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Alert, Box, Button, Card, CardContent, Chip, Divider, FormControlLabel, Stack, Switch, TextField, Typography } from "@mui/material";
import { useSearchParams } from "react-router-dom";
import { getAuditLogs } from "../api";
import type { AuditLog } from "../types";

const formatDateTime = (value: string) =>
  new Date(value).toLocaleString("ru-RU", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

export function AuditLogsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [items, setItems] = useState<AuditLog[]>([]);
  const [page, setPage] = useState(Math.max(1, Number(searchParams.get("page") || "1") || 1));
  const [pages, setPages] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [usernameFilter, setUsernameFilter] = useState(searchParams.get("username") || "");
  const [actionFilter, setActionFilter] = useState(searchParams.get("action") || "");
  const [entityTypeFilter, setEntityTypeFilter] = useState(searchParams.get("entity_type") || "");
  const [quickAction, setQuickAction] = useState(searchParams.get("quick_action") || "");
  const [quickEntityType, setQuickEntityType] = useState(searchParams.get("quick_entity_type") || "");
  const [expandedDetailsId, setExpandedDetailsId] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(searchParams.get("auto_refresh") !== "0");

  const loadLogs = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await getAuditLogs(page, 50, {
        username: usernameFilter.trim() || undefined,
        action: (quickAction || actionFilter).trim() || undefined,
        entity_type: (quickEntityType || entityTypeFilter).trim() || undefined,
      });
      setItems(response.items);
      setPages(response.pages);
    } catch {
      setError("Не удалось загрузить журнал действий.");
    } finally {
      setLoading(false);
    }
  }, [actionFilter, entityTypeFilter, page, quickAction, quickEntityType, usernameFilter]);

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
    if (usernameFilter.trim()) {
      params.set("username", usernameFilter.trim());
    }
    if (actionFilter.trim()) {
      params.set("action", actionFilter.trim());
    }
    if (entityTypeFilter.trim()) {
      params.set("entity_type", entityTypeFilter.trim());
    }
    if (quickAction.trim()) {
      params.set("quick_action", quickAction.trim());
    }
    if (quickEntityType.trim()) {
      params.set("quick_entity_type", quickEntityType.trim());
    }
    if (!autoRefresh) {
      params.set("auto_refresh", "0");
    }
    setSearchParams(params, { replace: true });
  }, [actionFilter, autoRefresh, entityTypeFilter, page, quickAction, quickEntityType, setSearchParams, usernameFilter]);

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
    return Array.from(new Set(items.map((item) => item.action))).slice(0, 12);
  }, [items]);

  const quickEntityTypeOptions = useMemo(() => {
    return Array.from(new Set(items.map((item) => item.entity_type).filter(Boolean) as string[])).slice(0, 12);
  }, [items]);

  const resetFilters = () => {
    setUsernameFilter("");
    setActionFilter("");
    setEntityTypeFilter("");
    setQuickAction("");
    setQuickEntityType("");
    setPage(1);
  };

  return (
    <Stack spacing={2}>
      {error && <Alert severity="error">{error}</Alert>}
      <Stack direction={{ xs: "column", md: "row" }} spacing={1}>
        <TextField
          label="Пользователь"
          value={usernameFilter}
          onChange={(event) => setUsernameFilter(event.target.value)}
          fullWidth
        />
        <TextField
          label="Фильтр action"
          value={actionFilter}
          onChange={(event) => setActionFilter(event.target.value)}
          fullWidth
        />
        <TextField
          label="Фильтр entity_type"
          value={entityTypeFilter}
          onChange={(event) => setEntityTypeFilter(event.target.value)}
          fullWidth
        />
        <Button variant="contained" disabled={loading} onClick={() => void loadLogs()}>
          Применить
        </Button>
        <Button variant="outlined" startIcon={<FilterAltOffIcon />} disabled={loading} onClick={resetFilters}>
          Сбросить
        </Button>
      </Stack>
      <FormControlLabel
        control={<Switch checked={autoRefresh} onChange={(event) => setAutoRefresh(event.target.checked)} />}
        label="Автообновление (10 сек)"
      />

      <Stack direction={{ xs: "column", md: "row" }} spacing={1} alignItems={{ md: "center" }}>
        <Chip label={`Событий: ${actionsSummary.total}`} variant="outlined" />
        <Chip label={`Типов действий: ${actionsSummary.uniqueActions}`} variant="outlined" />
        <Chip label={`Типов сущностей: ${actionsSummary.uniqueEntityTypes}`} variant="outlined" />
      </Stack>

      <Stack spacing={0.8}>
        <Typography variant="body2" color="text.secondary">
          Быстрый фильтр по action
        </Typography>
        <Stack direction="row" spacing={1} flexWrap="wrap">
          {quickActionOptions.map((action) => (
            <Chip
              key={action}
              label={action}
              color={quickAction === action ? "primary" : "default"}
              variant={quickAction === action ? "filled" : "outlined"}
              onClick={() => {
                setQuickAction((prev) => (prev === action ? "" : action));
                setPage(1);
              }}
            />
          ))}
        </Stack>
      </Stack>

      <Stack spacing={0.8}>
        <Typography variant="body2" color="text.secondary">
          Быстрый фильтр по entity_type
        </Typography>
        <Stack direction="row" spacing={1} flexWrap="wrap">
          {quickEntityTypeOptions.map((entityType) => (
            <Chip
              key={entityType}
              label={entityType}
              color={quickEntityType === entityType ? "primary" : "default"}
              variant={quickEntityType === entityType ? "filled" : "outlined"}
              onClick={() => {
                setQuickEntityType((prev) => (prev === entityType ? "" : entityType));
                setPage(1);
              }}
            />
          ))}
        </Stack>
      </Stack>

      <Stack spacing={1}>
        {items.map((item) => (
          <Card key={item.id} sx={{ borderRadius: 0 }}>
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
                    <Typography variant="body2">
                      <Typography component="span" color="text.secondary">
                        Пользователь:
                      </Typography>{" "}
                      {item.username || item.user_id || "system"}
                    </Typography>
                  </Stack>
                  <Typography variant="body2" color="text.secondary">
                    IP: {item.ip_address || "-"}
                  </Typography>
                </Stack>

                {item.details && (
                  <>
                    <Divider />
                    <Stack spacing={0.8}>
                      <Button
                        variant="text"
                        sx={{ width: "fit-content", px: 0 }}
                        onClick={() => setExpandedDetailsId((prev) => (prev === item.id ? null : item.id))}
                      >
                        {expandedDetailsId === item.id ? "Скрыть параметры" : "Показать параметры"}
                      </Button>
                      {expandedDetailsId === item.id && (
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
                      )}
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
