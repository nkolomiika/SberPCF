import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useEffect, useState } from "react";
import { Alert, Box, Button, Card, CardContent, Stack, TextField, Typography } from "@mui/material";
import { getAuditLogs } from "../api";
export function AuditLogsPage() {
    const [items, setItems] = useState([]);
    const [page, setPage] = useState(1);
    const [pages, setPages] = useState(1);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
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
        }
        catch {
            setError("Не удалось загрузить журнал действий.");
        }
        finally {
            setLoading(false);
        }
    };
    useEffect(() => {
        void loadLogs();
    }, [page]); // eslint-disable-line react-hooks/exhaustive-deps
    return (_jsxs(Stack, { spacing: 2, children: [error && _jsx(Alert, { severity: "error", children: error }), _jsxs(Stack, { direction: { xs: "column", md: "row" }, spacing: 1, children: [_jsx(TextField, { label: "\u0424\u0438\u043B\u044C\u0442\u0440 action", value: actionFilter, onChange: (event) => setActionFilter(event.target.value), fullWidth: true }), _jsx(TextField, { label: "\u0424\u0438\u043B\u044C\u0442\u0440 entity_type", value: entityTypeFilter, onChange: (event) => setEntityTypeFilter(event.target.value), fullWidth: true }), _jsx(Button, { variant: "contained", disabled: loading, onClick: () => void loadLogs(), children: "\u041F\u0440\u0438\u043C\u0435\u043D\u0438\u0442\u044C" })] }), _jsxs(Stack, { spacing: 1, children: [items.map((item) => (_jsx(Card, { sx: { borderRadius: 0 }, children: _jsxs(CardContent, { children: [_jsxs(Stack, { direction: { xs: "column", md: "row" }, justifyContent: "space-between", gap: 1, children: [_jsxs(Typography, { fontWeight: 700, children: [item.action, " ", item.entity_type ? `• ${item.entity_type}` : ""] }), _jsx(Typography, { variant: "body2", color: "text.secondary", children: new Date(item.created_at).toLocaleString() })] }), _jsxs(Typography, { variant: "body2", color: "text.secondary", children: ["user_id: ", item.user_id || "system", " | entity_id: ", item.entity_id || "-", " | ip: ", item.ip_address || "-"] }), item.details && (_jsx(Box, { mt: 0.8, children: _jsxs(Typography, { variant: "caption", color: "text.secondary", children: ["details: ", JSON.stringify(item.details)] }) }))] }) }, item.id))), !items.length && !loading && (_jsx(Typography, { color: "text.secondary", children: "\u0417\u0430\u043F\u0438\u0441\u0435\u0439 \u0432 \u0436\u0443\u0440\u043D\u0430\u043B\u0435 \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D\u043E." }))] }), _jsxs(Stack, { direction: "row", spacing: 1, justifyContent: "flex-end", children: [_jsx(Button, { variant: "outlined", disabled: page <= 1 || loading, onClick: () => setPage((prev) => Math.max(1, prev - 1)), children: "\u041D\u0430\u0437\u0430\u0434" }), _jsxs(Typography, { alignSelf: "center", color: "text.secondary", children: ["\u0421\u0442\u0440\u0430\u043D\u0438\u0446\u0430 ", page, " \u0438\u0437 ", pages] }), _jsx(Button, { variant: "outlined", disabled: page >= pages || loading, onClick: () => setPage((prev) => prev + 1), children: "\u0412\u043F\u0435\u0440\u0435\u0434" })] })] }));
}
