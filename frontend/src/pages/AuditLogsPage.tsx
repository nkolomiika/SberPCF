import { useEffect, useState } from "react";
import { Alert, Box, Button, Card, CardContent, Stack, TextField, Typography } from "@mui/material";
import { getAuditLogs } from "../api";
import type { AuditLog } from "../types";

export function AuditLogsPage() {
  const [items, setItems] = useState<AuditLog[]>([]);
  const [page, setPage] = useState(1);
  const [pages, setPages] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [actionFilter, setActionFilter] = useState("");
  const [entityTypeFilter, setEntityTypeFilter] = useState("");

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

      <Stack spacing={1}>
        {items.map((item) => (
          <Card key={item.id} sx={{ borderRadius: 0 }}>
            <CardContent>
              <Stack direction={{ xs: "column", md: "row" }} justifyContent="space-between" gap={1}>
                <Typography fontWeight={700}>
                  {item.action} {item.entity_type ? `• ${item.entity_type}` : ""}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {new Date(item.created_at).toLocaleString()}
                </Typography>
              </Stack>
              <Typography variant="body2" color="text.secondary">
                user_id: {item.user_id || "system"} | entity_id: {item.entity_id || "-"} | ip: {item.ip_address || "-"}
              </Typography>
              {item.details && (
                <Box mt={0.8}>
                  <Typography variant="caption" color="text.secondary">
                    details: {JSON.stringify(item.details)}
                  </Typography>
                </Box>
              )}
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
