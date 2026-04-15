import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import AddIcon from "@mui/icons-material/Add";
import SecurityIcon from "@mui/icons-material/Security";
import StorageIcon from "@mui/icons-material/Storage";
import { Alert, Box, Button, Card, CardContent, Chip, Dialog, DialogActions, DialogContent, DialogTitle, Grid2 as Grid, Stack, TextField, Typography, } from "@mui/material";
import { useEffect, useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { createHost, createVulnerability, getHosts, getVulnerabilities } from "../api";
export function ProjectDetailPage() {
    const { projectId } = useParams();
    const [hosts, setHosts] = useState([]);
    const [vulnerabilities, setVulnerabilities] = useState([]);
    const [error, setError] = useState(null);
    const [hostOpen, setHostOpen] = useState(false);
    const [hostIp, setHostIp] = useState("");
    const [hostName, setHostName] = useState("");
    const [hostOs, setHostOs] = useState("");
    const [vulnOpen, setVulnOpen] = useState(false);
    const [vulnTitle, setVulnTitle] = useState("");
    const [vulnSeverity, setVulnSeverity] = useState("medium");
    const loadData = async () => {
        if (!projectId) {
            return;
        }
        try {
            const [hostsResp, vulnsResp] = await Promise.all([getHosts(projectId), getVulnerabilities(projectId)]);
            setHosts(hostsResp.items);
            setVulnerabilities(vulnsResp.items);
        }
        catch {
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
    return (_jsxs(Stack, { spacing: 3, children: [error && _jsx(Alert, { severity: "error", children: error }), _jsxs(Stack, { direction: "row", justifyContent: "space-between", alignItems: "center", children: [_jsxs(Box, { children: [_jsxs(Typography, { variant: "h4", fontWeight: 700, children: ["\u041F\u0440\u043E\u0435\u043A\u0442 ", projectId] }), _jsx(Typography, { color: "text.secondary", children: "\u0410\u043A\u0442\u0438\u0432\u044B, \u0443\u044F\u0437\u0432\u0438\u043C\u043E\u0441\u0442\u0438 \u0438 \u0441\u0438\u043D\u0445\u0440\u043E\u043D\u0438\u0437\u0430\u0446\u0438\u044F \u0432 \u0440\u0435\u0430\u043B\u044C\u043D\u043E\u043C \u0432\u0440\u0435\u043C\u0435\u043D\u0438" })] }), _jsxs(Stack, { direction: "row", spacing: 1, children: [_jsx(Button, { variant: "outlined", startIcon: _jsx(AddIcon, {}), onClick: () => setHostOpen(true), children: "\u0414\u043E\u0431\u0430\u0432\u0438\u0442\u044C \u0445\u043E\u0441\u0442" }), _jsx(Button, { variant: "contained", startIcon: _jsx(AddIcon, {}), onClick: () => setVulnOpen(true), children: "\u0414\u043E\u0431\u0430\u0432\u0438\u0442\u044C \u0443\u044F\u0437\u0432\u0438\u043C\u043E\u0441\u0442\u044C" })] })] }), _jsxs(Grid, { container: true, spacing: 2, children: [_jsx(Grid, { size: { xs: 12, md: 6 }, children: _jsx(Card, { sx: { border: "1px solid #2a3c5f" }, children: _jsxs(CardContent, { children: [_jsxs(Stack, { direction: "row", alignItems: "center", spacing: 1, mb: 2, children: [_jsx(StorageIcon, { color: "primary" }), _jsxs(Typography, { variant: "h6", children: ["\u0425\u043E\u0441\u0442\u044B (", hosts.length, ")"] })] }), _jsx(Stack, { spacing: 1.2, children: hosts.map((host) => (_jsxs(Box, { sx: { border: "1px solid #2a3c5f", p: 1.5, borderRadius: 2 }, children: [_jsx(Typography, { children: host.ip_address || host.hostname || "unknown" }), _jsx(Typography, { variant: "body2", color: "text.secondary", children: host.os || "OS не указана" })] }, host.id))) })] }) }) }), _jsx(Grid, { size: { xs: 12, md: 6 }, children: _jsx(Card, { sx: { border: "1px solid #2a3c5f" }, children: _jsxs(CardContent, { children: [_jsxs(Stack, { direction: "row", alignItems: "center", spacing: 1, mb: 2, children: [_jsx(SecurityIcon, { color: "error" }), _jsxs(Typography, { variant: "h6", children: ["\u0423\u044F\u0437\u0432\u0438\u043C\u043E\u0441\u0442\u0438 (", vulnerabilities.length, ")"] })] }), _jsx(Stack, { direction: "row", spacing: 1, mb: 2, flexWrap: "wrap", children: Object.entries(severityStats).map(([severity, value]) => (_jsx(Chip, { label: `${severity}: ${value}` }, severity))) }), _jsx(Stack, { spacing: 1.2, children: vulnerabilities.map((item) => (_jsxs(Box, { sx: { border: "1px solid #2a3c5f", p: 1.5, borderRadius: 2 }, children: [_jsx(Typography, { children: item.title }), _jsxs(Stack, { direction: "row", spacing: 1, mt: 1, children: [_jsx(Chip, { label: item.severity, size: "small" }), _jsx(Chip, { label: item.status, size: "small", color: "warning" })] })] }, item.id))) })] }) }) })] }), _jsxs(Dialog, { open: hostOpen, onClose: () => setHostOpen(false), fullWidth: true, children: [_jsx(DialogTitle, { children: "\u0414\u043E\u0431\u0430\u0432\u0438\u0442\u044C \u0445\u043E\u0441\u0442" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [_jsx(TextField, { label: "IP-\u0430\u0434\u0440\u0435\u0441", value: hostIp, onChange: (e) => setHostIp(e.target.value) }), _jsx(TextField, { label: "Hostname", value: hostName, onChange: (e) => setHostName(e.target.value) }), _jsx(TextField, { label: "\u041E\u0421", value: hostOs, onChange: (e) => setHostOs(e.target.value) })] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setHostOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", disabled: !hostIp && !hostName, onClick: () => void submitHost(), children: "\u0421\u043E\u0445\u0440\u0430\u043D\u0438\u0442\u044C" })] })] }), _jsxs(Dialog, { open: vulnOpen, onClose: () => setVulnOpen(false), fullWidth: true, children: [_jsx(DialogTitle, { children: "\u0414\u043E\u0431\u0430\u0432\u0438\u0442\u044C \u0443\u044F\u0437\u0432\u0438\u043C\u043E\u0441\u0442\u044C" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [_jsx(TextField, { label: "\u041D\u0430\u0437\u0432\u0430\u043D\u0438\u0435", value: vulnTitle, onChange: (e) => setVulnTitle(e.target.value) }), _jsx(TextField, { label: "\u041A\u0440\u0438\u0442\u0438\u0447\u043D\u043E\u0441\u0442\u044C (critical/high/medium/low/info)", value: vulnSeverity, onChange: (e) => setVulnSeverity(e.target.value) })] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setVulnOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", disabled: !vulnTitle.trim(), onClick: () => void submitVulnerability(), children: "\u0421\u043E\u0445\u0440\u0430\u043D\u0438\u0442\u044C" })] })] })] }));
}
