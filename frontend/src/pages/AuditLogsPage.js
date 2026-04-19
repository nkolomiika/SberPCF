import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import AccessTimeIcon from "@mui/icons-material/AccessTime";
import ExpandLessIcon from "@mui/icons-material/ExpandLess";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import FilterAltOffIcon from "@mui/icons-material/FilterAltOff";
import PersonOutlineIcon from "@mui/icons-material/PersonOutline";
import RefreshIcon from "@mui/icons-material/Refresh";
import SearchIcon from "@mui/icons-material/Search";
import TuneIcon from "@mui/icons-material/Tune";
import { Box, Button, Card, CardContent, Chip, Collapse, Divider, FormControlLabel, IconButton, MenuItem, Stack, Switch, TextField, Tooltip, Typography, } from "@mui/material";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { getApiErrorMessage, getAuditLogs } from "../api";
import { useErrorToast } from "../useErrorToast";
const formatDateTime = (value) => new Date(value).toLocaleString("ru-RU", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
});
const auditActionOptions = ["LOGIN", "LOGOUT", "CREATE", "UPDATE", "DELETE", "FILE_UPLOAD", "FILE_DELETE"];
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
];
export function AuditLogsPage() {
    const [searchParams, setSearchParams] = useSearchParams();
    const [items, setItems] = useState([]);
    const [page, setPage] = useState(Math.max(1, Number(searchParams.get("page") || "1") || 1));
    const [pages, setPages] = useState(1);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    const [expandedDetailsId, setExpandedDetailsId] = useState(null);
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
        }
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось загрузить журнал действий."));
        }
        finally {
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
        return Array.from(new Set([...auditEntityTypeOptions, ...items.map((item) => item.entity_type).filter(Boolean)])).slice(0, 20);
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
    const setDraftField = (field, value) => {
        setDraftFilters((prev) => ({ ...prev, [field]: value }));
    };
    const toggleQuickAction = (action) => {
        const nextValue = draftFilters.action === action ? "" : action;
        const nextFilters = { ...draftFilters, action: nextValue };
        setDraftFilters(nextFilters);
        setFilters((prev) => ({ ...prev, action: nextValue }));
        setPage(1);
    };
    const toggleQuickEntityType = (entityType) => {
        const nextValue = draftFilters.entity_type === entityType ? "" : entityType;
        const nextFilters = { ...draftFilters, entity_type: nextValue };
        setDraftFilters(nextFilters);
        setFilters((prev) => ({ ...prev, entity_type: nextValue }));
        setPage(1);
    };
    const visibleDetailsCount = useMemo(() => items.filter((item) => item.details && Object.keys(item.details).length > 0).length, [items]);
    const renderDetailsPreview = (details) => {
        if (!details) {
            return null;
        }
        return Object.entries(details)
            .slice(0, 4)
            .map(([key, value]) => (_jsx(Chip, { size: "small", variant: "outlined", label: `${key}: ${typeof value === "object" ? JSON.stringify(value) : String(value)}`, sx: { maxWidth: 260 } }, key)));
    };
    return (_jsxs(Stack, { spacing: 2.5, children: [_jsx(Card, { sx: { border: "1px solid rgba(126,224,255,0.14)" }, children: _jsx(CardContent, { sx: { pb: "16px !important" }, children: _jsxs(Stack, { spacing: 2, children: [_jsxs(Stack, { direction: { xs: "column", md: "row" }, justifyContent: "space-between", alignItems: { md: "center" }, gap: 1, children: [_jsxs(Stack, { spacing: 0.3, children: [_jsx(Typography, { variant: "h4", fontWeight: 700, children: "\u0416\u0443\u0440\u043D\u0430\u043B \u0434\u0435\u0439\u0441\u0442\u0432\u0438\u0439" }), _jsx(Typography, { color: "text.secondary", children: "\u041E\u043F\u0435\u0440\u0430\u0446\u0438\u043E\u043D\u043D\u044B\u0439 \u043F\u043E\u0442\u043E\u043A \u0441\u043E\u0431\u044B\u0442\u0438\u0439 \u043F\u043E \u0441\u0438\u0441\u0442\u0435\u043C\u0435, \u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u044F\u043C \u0438 \u0434\u0430\u043D\u043D\u044B\u043C \u043F\u0440\u043E\u0435\u043A\u0442\u0430." })] }), _jsxs(Stack, { direction: "row", spacing: 1, alignItems: "center", children: [_jsx(FormControlLabel, { control: _jsx(Switch, { checked: autoRefresh, onChange: (event) => setAutoRefresh(event.target.checked) }), label: "\u0410\u0432\u0442\u043E\u043E\u0431\u043D\u043E\u0432\u043B\u0435\u043D\u0438\u0435" }), _jsx(Tooltip, { title: "\u041E\u0431\u043D\u043E\u0432\u0438\u0442\u044C", children: _jsx("span", { children: _jsx(IconButton, { onClick: () => void loadLogs(), disabled: loading, children: _jsx(RefreshIcon, {}) }) }) })] })] }), _jsxs(Stack, { direction: { xs: "column", md: "row" }, spacing: 1, alignItems: { md: "center" }, flexWrap: "wrap", useFlexGap: true, children: [_jsx(Chip, { label: `Событий на странице: ${actionsSummary.total}`, variant: "outlined" }), _jsx(Chip, { label: `Типов действий: ${actionsSummary.uniqueActions}`, variant: "outlined" }), _jsx(Chip, { label: `Типов сущностей: ${actionsSummary.uniqueEntityTypes}`, variant: "outlined" }), _jsx(Chip, { label: `С деталями: ${visibleDetailsCount}`, variant: "outlined" })] }), _jsx(Divider, {}), _jsxs(Stack, { direction: { xs: "column", md: "row" }, spacing: 1.2, alignItems: { md: "flex-start" }, children: [_jsxs(Stack, { flex: 1, spacing: 1.2, children: [_jsxs(Stack, { direction: { xs: "column", md: "row" }, spacing: 1.2, children: [_jsx(TextField, { label: "\u041F\u043E\u0438\u0441\u043A \u043F\u043E \u043B\u043E\u0433\u0443", value: draftFilters.query, onChange: (event) => setDraftField("query", event.target.value), placeholder: "action, user, details, ip", fullWidth: true }), _jsx(TextField, { label: "\u041F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u044C", value: draftFilters.username, onChange: (event) => setDraftField("username", event.target.value), fullWidth: true }), _jsxs(TextField, { select: true, label: "Action", value: draftFilters.action, onChange: (event) => setDraftField("action", event.target.value), fullWidth: true, children: [_jsx(MenuItem, { value: "", children: "\u0412\u0441\u0435 \u0434\u0435\u0439\u0441\u0442\u0432\u0438\u044F" }), quickActionOptions.map((action) => (_jsx(MenuItem, { value: action, children: action }, action)))] })] }), _jsxs(Stack, { direction: { xs: "column", md: "row" }, spacing: 1.2, children: [_jsxs(TextField, { select: true, label: "\u0421\u0443\u0449\u043D\u043E\u0441\u0442\u044C", value: draftFilters.entity_type, onChange: (event) => setDraftField("entity_type", event.target.value), fullWidth: true, children: [_jsx(MenuItem, { value: "", children: "\u0412\u0441\u0435 \u0441\u0443\u0449\u043D\u043E\u0441\u0442\u0438" }), quickEntityTypeOptions.map((entityType) => (_jsx(MenuItem, { value: entityType, children: entityType }, entityType)))] }), _jsx(TextField, { label: "IP", value: draftFilters.ip_address, onChange: (event) => setDraftField("ip_address", event.target.value), fullWidth: true }), _jsx(TextField, { label: "\u041E\u0442", type: "datetime-local", value: draftFilters.created_from, onChange: (event) => setDraftField("created_from", event.target.value), InputLabelProps: { shrink: true }, fullWidth: true }), _jsx(TextField, { label: "\u0414\u043E", type: "datetime-local", value: draftFilters.created_to, onChange: (event) => setDraftField("created_to", event.target.value), InputLabelProps: { shrink: true }, fullWidth: true })] })] }), _jsxs(Stack, { direction: { xs: "row", md: "column" }, spacing: 1, children: [_jsx(Tooltip, { title: "\u041F\u0440\u0438\u043C\u0435\u043D\u0438\u0442\u044C \u0444\u0438\u043B\u044C\u0442\u0440\u044B", children: _jsx("span", { children: _jsx(IconButton, { color: "primary", onClick: applyFilters, disabled: loading, children: _jsx(SearchIcon, {}) }) }) }), _jsx(Tooltip, { title: "\u0421\u0431\u0440\u043E\u0441\u0438\u0442\u044C \u0444\u0438\u043B\u044C\u0442\u0440\u044B", children: _jsx("span", { children: _jsx(IconButton, { onClick: resetFilters, disabled: loading, children: _jsx(FilterAltOffIcon, {}) }) }) })] })] }), _jsxs(Stack, { spacing: 0.8, children: [_jsx(Typography, { variant: "body2", color: "text.secondary", children: "\u0411\u044B\u0441\u0442\u0440\u044B\u0435 \u0434\u0435\u0439\u0441\u0442\u0432\u0438\u044F" }), _jsx(Stack, { direction: "row", spacing: 1, flexWrap: "wrap", useFlexGap: true, children: quickActionOptions.map((action) => (_jsx(Chip, { label: action, color: filters.action === action ? "primary" : "default", variant: filters.action === action ? "filled" : "outlined", onClick: () => toggleQuickAction(action) }, action))) })] }), _jsxs(Stack, { spacing: 0.8, children: [_jsx(Typography, { variant: "body2", color: "text.secondary", children: "\u0411\u044B\u0441\u0442\u0440\u044B\u0435 \u0441\u0443\u0449\u043D\u043E\u0441\u0442\u0438" }), _jsx(Stack, { direction: "row", spacing: 1, flexWrap: "wrap", useFlexGap: true, children: quickEntityTypeOptions.map((entityType) => (_jsx(Chip, { label: entityType, color: filters.entity_type === entityType ? "primary" : "default", variant: filters.entity_type === entityType ? "filled" : "outlined", onClick: () => toggleQuickEntityType(entityType) }, entityType))) })] })] }) }) }), _jsxs(Stack, { spacing: 1, children: [items.map((item) => (_jsx(Card, { sx: {
                            borderRadius: 0,
                            border: "1px solid rgba(126,224,255,0.12)",
                            borderLeft: "3px solid rgba(126,224,255,0.35)",
                            backgroundColor: "rgba(8,17,31,0.28)",
                        }, children: _jsx(CardContent, { children: _jsxs(Stack, { spacing: 1.2, children: [_jsxs(Stack, { direction: { xs: "column", md: "row" }, justifyContent: "space-between", gap: 1, children: [_jsxs(Stack, { direction: "row", spacing: 1, alignItems: "center", flexWrap: "wrap", children: [_jsx(Chip, { size: "small", icon: _jsx(TuneIcon, {}), label: item.action }), item.entity_type && _jsx(Chip, { size: "small", variant: "outlined", label: item.entity_type }), item.entity_id && _jsx(Chip, { size: "small", variant: "outlined", label: `ID: ${item.entity_id}` })] }), _jsxs(Stack, { direction: "row", spacing: 0.8, alignItems: "center", children: [_jsx(AccessTimeIcon, { fontSize: "small", color: "disabled" }), _jsx(Typography, { variant: "body2", color: "text.secondary", children: formatDateTime(item.created_at) })] })] }), _jsxs(Stack, { direction: { xs: "column", md: "row" }, spacing: 2, alignItems: { md: "center" }, children: [_jsxs(Stack, { direction: "row", spacing: 0.8, alignItems: "center", children: [_jsx(PersonOutlineIcon, { fontSize: "small", color: "disabled" }), _jsx(Typography, { variant: "body2", children: item.username || item.user_id || "system" })] }), _jsx(Chip, { size: "small", variant: "outlined", label: `IP: ${item.ip_address || "-"}` }), item.entity_id && _jsx(Chip, { size: "small", variant: "outlined", label: `ID: ${item.entity_id}` })] }), item.details && Object.keys(item.details).length > 0 && (_jsxs(_Fragment, { children: [_jsx(Stack, { direction: "row", spacing: 0.8, flexWrap: "wrap", useFlexGap: true, children: renderDetailsPreview(item.details) }), _jsx(Divider, {}), _jsxs(Stack, { spacing: 0.8, children: [_jsx(Box, { display: "flex", justifyContent: "flex-end", children: _jsx(Tooltip, { title: expandedDetailsId === item.id ? "Скрыть параметры" : "Показать параметры", children: _jsx(IconButton, { onClick: () => setExpandedDetailsId((prev) => (prev === item.id ? null : item.id)), children: expandedDetailsId === item.id ? _jsx(ExpandLessIcon, {}) : _jsx(ExpandMoreIcon, {}) }) }) }), _jsx(Collapse, { in: expandedDetailsId === item.id, timeout: "auto", unmountOnExit: true, children: _jsx(Box, { sx: {
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
                                                                }, children: JSON.stringify(item.details, null, 2) }) }) })] })] }))] }) }) }, item.id))), !items.length && !loading && (_jsx(Typography, { color: "text.secondary", children: "\u0417\u0430\u043F\u0438\u0441\u0435\u0439 \u0432 \u0436\u0443\u0440\u043D\u0430\u043B\u0435 \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D\u043E." }))] }), _jsxs(Stack, { direction: "row", spacing: 1, justifyContent: "flex-end", children: [_jsx(Button, { variant: "outlined", disabled: page <= 1 || loading, onClick: () => setPage((prev) => Math.max(1, prev - 1)), children: "\u041D\u0430\u0437\u0430\u0434" }), _jsxs(Typography, { alignSelf: "center", color: "text.secondary", children: ["\u0421\u0442\u0440\u0430\u043D\u0438\u0446\u0430 ", page, " \u0438\u0437 ", pages] }), _jsx(Button, { variant: "outlined", disabled: page >= pages || loading, onClick: () => setPage((prev) => prev + 1), children: "\u0412\u043F\u0435\u0440\u0435\u0434" })] })] }));
}
