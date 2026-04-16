import AccessTimeIcon from "@mui/icons-material/AccessTime";
import PersonOutlineIcon from "@mui/icons-material/PersonOutline";
import TuneIcon from "@mui/icons-material/Tune";
import { useEffect, useMemo, useState } from "react";
import { Alert, Box, Button, Card, CardContent, Chip, Divider, Stack, TextField, Typography } from "@mui/material";
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
  const [items, setItems] = useState<AuditLog[]>([]);
  const [page, setPage] = useState(1);
  const [pages, setPages] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [actionFilter, setActionFilter] = useState("");
  const [entityTypeFilter, setEntityTypeFilter] = useState("");
  const [expandedDetailsId, setExpandedDetailsId] = useState<string | null>(null);

  const loadLogs = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await getAuditLogs(page, 50, {
        action: actionFilter.trim() || undefined,
        entity_type: entityTypeFilter.trim() || undefined,
      });
      setItems(response.items);
      setPages(response.pages);
    } catch {
      setError("Не удалось загрузить журнал действий.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadLogs();
  }, [page]); // eslint-disable-line react-hooks/exhaustive-deps

  const actionsSummary = useMemo(() => {
    const uniqueActions = new Set(items.map((item) => item.action));
    return {
      total: items.length,
      uniqueActions: uniqueActions.size,
    };
  }, [items]);

  return (
    <Stack spacing={2}>
      {error && <Alert severity="error">{error}</Alert>}
      <Stack direction={{ xs: "column", md: "row" }} spacing={1}>
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
      </Stack>

      <Stack direction={{ xs: "column", md: "row" }} spacing={1} alignItems={{ md: "center" }}>
        <Chip label={`Событий: ${actionsSummary.total}`} variant="outlined" />
        <Chip label={`Типов действий: ${actionsSummary.uniqueActions}`} variant="outlined" />
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
