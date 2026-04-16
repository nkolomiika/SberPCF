import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import AccessTimeIcon from "@mui/icons-material/AccessTime";
import FilterAltOffIcon from "@mui/icons-material/FilterAltOff";
import PersonOutlineIcon from "@mui/icons-material/PersonOutline";
import TuneIcon from "@mui/icons-material/Tune";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Alert, Box, Button, Card, CardContent, Chip, Divider, FormControlLabel, Stack, Switch, TextField, Typography } from "@mui/material";
import { useSearchParams } from "react-router-dom";
import { getAuditLogs } from "../api";
const formatDateTime = (value) => new Date(value).toLocaleString("ru-RU", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
});
export function AuditLogsPage() {
    const [searchParams, setSearchParams] = useSearchParams();
    const [items, setItems] = useState([]);
    const [page, setPage] = useState(Math.max(1, Number(searchParams.get("page") || "1") || 1));
    const [pages, setPages] = useState(1);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    const [usernameFilter, setUsernameFilter] = useState(searchParams.get("username") || "");
    const [actionFilter, setActionFilter] = useState(searchParams.get("action") || "");
    const [entityTypeFilter, setEntityTypeFilter] = useState(searchParams.get("entity_type") || "");
    const [quickAction, setQuickAction] = useState(searchParams.get("quick_action") || "");
    const [quickEntityType, setQuickEntityType] = useState(searchParams.get("quick_entity_type") || "");
    const [expandedDetailsId, setExpandedDetailsId] = useState(null);
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
        }
        catch {
            setError("Не удалось загрузить журнал действий.");
        }
        finally {
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
        return Array.from(new Set(items.map((item) => item.entity_type).filter(Boolean))).slice(0, 12);
    }, [items]);
    const resetFilters = () => {
        setUsernameFilter("");
        setActionFilter("");
        setEntityTypeFilter("");
        setQuickAction("");
        setQuickEntityType("");
        setPage(1);
    };
    return (_jsxs(Stack, { spacing: 2, children: [error && _jsx(Alert, { severity: "error", children: error }), _jsxs(Stack, { direction: { xs: "column", md: "row" }, spacing: 1, children: [_jsx(TextField, { label: "\u041F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u044C", value: usernameFilter, onChange: (event) => setUsernameFilter(event.target.value), fullWidth: true }), _jsx(TextField, { label: "\u0424\u0438\u043B\u044C\u0442\u0440 action", value: actionFilter, onChange: (event) => setActionFilter(event.target.value), fullWidth: true }), _jsx(TextField, { label: "\u0424\u0438\u043B\u044C\u0442\u0440 entity_type", value: entityTypeFilter, onChange: (event) => setEntityTypeFilter(event.target.value), fullWidth: true }), _jsx(Button, { variant: "contained", disabled: loading, onClick: () => void loadLogs(), children: "\u041F\u0440\u0438\u043C\u0435\u043D\u0438\u0442\u044C" }), _jsx(Button, { variant: "outlined", startIcon: _jsx(FilterAltOffIcon, {}), disabled: loading, onClick: resetFilters, children: "\u0421\u0431\u0440\u043E\u0441\u0438\u0442\u044C" })] }), _jsx(FormControlLabel, { control: _jsx(Switch, { checked: autoRefresh, onChange: (event) => setAutoRefresh(event.target.checked) }), label: "\u0410\u0432\u0442\u043E\u043E\u0431\u043D\u043E\u0432\u043B\u0435\u043D\u0438\u0435 (10 \u0441\u0435\u043A)" }), _jsxs(Stack, { direction: { xs: "column", md: "row" }, spacing: 1, alignItems: { md: "center" }, children: [_jsx(Chip, { label: `Событий: ${actionsSummary.total}`, variant: "outlined" }), _jsx(Chip, { label: `Типов действий: ${actionsSummary.uniqueActions}`, variant: "outlined" }), _jsx(Chip, { label: `Типов сущностей: ${actionsSummary.uniqueEntityTypes}`, variant: "outlined" })] }), _jsxs(Stack, { spacing: 0.8, children: [_jsx(Typography, { variant: "body2", color: "text.secondary", children: "\u0411\u044B\u0441\u0442\u0440\u044B\u0439 \u0444\u0438\u043B\u044C\u0442\u0440 \u043F\u043E action" }), _jsx(Stack, { direction: "row", spacing: 1, flexWrap: "wrap", children: quickActionOptions.map((action) => (_jsx(Chip, { label: action, color: quickAction === action ? "primary" : "default", variant: quickAction === action ? "filled" : "outlined", onClick: () => {
                                setQuickAction((prev) => (prev === action ? "" : action));
                                setPage(1);
                            } }, action))) })] }), _jsxs(Stack, { spacing: 0.8, children: [_jsx(Typography, { variant: "body2", color: "text.secondary", children: "\u0411\u044B\u0441\u0442\u0440\u044B\u0439 \u0444\u0438\u043B\u044C\u0442\u0440 \u043F\u043E entity_type" }), _jsx(Stack, { direction: "row", spacing: 1, flexWrap: "wrap", children: quickEntityTypeOptions.map((entityType) => (_jsx(Chip, { label: entityType, color: quickEntityType === entityType ? "primary" : "default", variant: quickEntityType === entityType ? "filled" : "outlined", onClick: () => {
                                setQuickEntityType((prev) => (prev === entityType ? "" : entityType));
                                setPage(1);
                            } }, entityType))) })] }), _jsxs(Stack, { spacing: 1, children: [items.map((item) => (_jsx(Card, { sx: { borderRadius: 0 }, children: _jsx(CardContent, { children: _jsxs(Stack, { spacing: 1.2, children: [_jsxs(Stack, { direction: { xs: "column", md: "row" }, justifyContent: "space-between", gap: 1, children: [_jsxs(Stack, { direction: "row", spacing: 1, alignItems: "center", flexWrap: "wrap", children: [_jsx(Chip, { size: "small", icon: _jsx(TuneIcon, {}), label: item.action }), item.entity_type && _jsx(Chip, { size: "small", variant: "outlined", label: item.entity_type }), item.entity_id && _jsx(Chip, { size: "small", variant: "outlined", label: `ID: ${item.entity_id}` })] }), _jsxs(Stack, { direction: "row", spacing: 0.8, alignItems: "center", children: [_jsx(AccessTimeIcon, { fontSize: "small", color: "disabled" }), _jsx(Typography, { variant: "body2", color: "text.secondary", children: formatDateTime(item.created_at) })] })] }), _jsxs(Stack, { direction: { xs: "column", md: "row" }, spacing: 2, alignItems: { md: "center" }, children: [_jsxs(Stack, { direction: "row", spacing: 0.8, alignItems: "center", children: [_jsx(PersonOutlineIcon, { fontSize: "small", color: "disabled" }), _jsxs(Typography, { variant: "body2", children: [_jsx(Typography, { component: "span", color: "text.secondary", children: "\u041F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u044C:" }), " ", item.username || item.user_id || "system"] })] }), _jsxs(Typography, { variant: "body2", color: "text.secondary", children: ["IP: ", item.ip_address || "-"] })] }), item.details && (_jsxs(_Fragment, { children: [_jsx(Divider, {}), _jsxs(Stack, { spacing: 0.8, children: [_jsx(Button, { variant: "text", sx: { width: "fit-content", px: 0 }, onClick: () => setExpandedDetailsId((prev) => (prev === item.id ? null : item.id)), children: expandedDetailsId === item.id ? "Скрыть параметры" : "Показать параметры" }), expandedDetailsId === item.id && (_jsx(Box, { sx: {
                                                            border: "1px solid rgba(126,224,255,0.12)",
                                                            backgroundColor: "rgba(126,224,255,0.04)",
                                                            p: 1.2,
                                                            overflowX: "auto",
                                                        }, children: _jsx(Typography, { component: "pre", sx: {
                                                                m: 0,
                                                                fontSize: 12,
                                                                whiteSpace: "pre-wrap",
                                                                wordBreak: "break-word",
                                                                fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, Liberation Mono, monospace",
                                                            }, children: JSON.stringify(item.details, null, 2) }) }))] })] }))] }) }) }, item.id))), !items.length && !loading && (_jsx(Typography, { color: "text.secondary", children: "\u0417\u0430\u043F\u0438\u0441\u0435\u0439 \u0432 \u0436\u0443\u0440\u043D\u0430\u043B\u0435 \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D\u043E." }))] }), _jsxs(Stack, { direction: "row", spacing: 1, justifyContent: "flex-end", children: [_jsx(Button, { variant: "outlined", disabled: page <= 1 || loading, onClick: () => setPage((prev) => Math.max(1, prev - 1)), children: "\u041D\u0430\u0437\u0430\u0434" }), _jsxs(Typography, { alignSelf: "center", color: "text.secondary", children: ["\u0421\u0442\u0440\u0430\u043D\u0438\u0446\u0430 ", page, " \u0438\u0437 ", pages] }), _jsx(Button, { variant: "outlined", disabled: page >= pages || loading, onClick: () => setPage((prev) => prev + 1), children: "\u0412\u043F\u0435\u0440\u0435\u0434" })] })] }));
}
