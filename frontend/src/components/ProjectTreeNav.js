import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import ChevronLeftIcon from "@mui/icons-material/ChevronLeft";
import ChevronRightIcon from "@mui/icons-material/ChevronRight";
import DnsIcon from "@mui/icons-material/Dns";
import HubIcon from "@mui/icons-material/Hub";
import KeyboardArrowDownIcon from "@mui/icons-material/KeyboardArrowDown";
import KeyboardArrowRightIcon from "@mui/icons-material/KeyboardArrowRight";
import LanIcon from "@mui/icons-material/Lan";
import ReportProblemIcon from "@mui/icons-material/ReportProblem";
import { Box, Divider, IconButton, List, ListItemButton, ListItemText, Stack, Typography, } from "@mui/material";
import { useEffect, useState } from "react";
export function ProjectTreeNav({ hosts, selectedHostId, selectedSection, isCollapsed, portsCount, endpointsCount, vulnerabilitiesCount, hostStatsById, autoExpandSelectedHost = true, onSelectProjectOverview, onToggleCollapsed, onSelectSection, onSelectHost, onOpenHost, }) {
    const [expandedHosts, setExpandedHosts] = useState(new Set());
    useEffect(() => {
        if (!autoExpandSelectedHost) {
            return;
        }
        if (!selectedHostId) {
            return;
        }
        setExpandedHosts((previous) => {
            if (previous.has(selectedHostId)) {
                return previous;
            }
            const next = new Set(previous);
            next.add(selectedHostId);
            return next;
        });
    }, [selectedHostId, autoExpandSelectedHost]);
    const toggleHostExpanded = (hostId) => {
        setExpandedHosts((previous) => {
            const next = new Set(previous);
            if (next.has(hostId)) {
                next.delete(hostId);
            }
            else {
                next.add(hostId);
            }
            return next;
        });
    };
    const selectHostAndSection = (hostId, section) => {
        onSelectHost(hostId);
        onSelectSection(section);
        if (onOpenHost) {
            onOpenHost(hostId);
        }
    };
    return (_jsxs(Box, { sx: {
            width: { xs: "100%", md: isCollapsed ? 88 : 320 },
            transition: "width .2s ease",
            borderRight: { xs: "none", md: "1px solid rgba(126,224,255,0.18)" },
            overflow: "hidden",
            flexShrink: 0,
            pr: { xs: 0, md: 1.5 },
        }, children: [_jsxs(Stack, { direction: "row", justifyContent: "space-between", alignItems: "center", sx: { px: 1.5, py: 1 }, children: [!isCollapsed && (_jsx(Typography, { variant: "subtitle2", fontWeight: 700, children: "\u0421\u0442\u0440\u0443\u043A\u0442\u0443\u0440\u0430 \u043F\u0440\u043E\u0435\u043A\u0442\u0430" })), _jsx(IconButton, { size: "small", onClick: onToggleCollapsed, children: isCollapsed ? _jsx(ChevronRightIcon, {}) : _jsx(ChevronLeftIcon, {}) })] }), _jsx(Divider, {}), _jsxs(List, { dense: true, disablePadding: true, children: [_jsxs(ListItemButton, { selected: selectedSection === "overview", onClick: () => (onSelectProjectOverview ? onSelectProjectOverview() : onSelectSection("overview")), children: [_jsx(HubIcon, { fontSize: "small" }), !isCollapsed && _jsx(ListItemText, { sx: { ml: 1 }, primary: "\u041E\u0431\u0437\u043E\u0440 \u043F\u0440\u043E\u0435\u043A\u0442\u0430" })] }), _jsx(Divider, { sx: { my: 0.5 } }), !isCollapsed && (_jsx(Typography, { sx: { px: 2, pt: 1, pb: 0.5 }, variant: "caption", color: "text.secondary", children: "\u0425\u043E\u0441\u0442\u044B" })), hosts.map((host) => {
                        const label = host.hostname || host.ip_address || "unknown-host";
                        const isActiveHost = selectedHostId === host.id;
                        const isExpanded = expandedHosts.has(host.id);
                        const hostStats = hostStatsById?.[host.id];
                        const hostPortsCount = hostStats?.portsCount ?? (isActiveHost ? portsCount : 0);
                        const hostEndpointsCount = hostStats?.endpointsCount ?? (isActiveHost ? endpointsCount : 0);
                        const hostVulnerabilitiesCount = hostStats?.vulnerabilitiesCount ?? (isActiveHost ? vulnerabilitiesCount : 0);
                        return (_jsxs(Box, { children: [_jsxs(ListItemButton, { selected: isActiveHost && (selectedSection === "hosts" || selectedSection === "overview"), onClick: () => selectHostAndSection(host.id, "overview"), children: [_jsx(DnsIcon, { fontSize: "small" }), !isCollapsed && _jsx(ListItemText, { sx: { ml: 1 }, primary: label, secondary: `Статус: ${host.status}` }), !isCollapsed && (_jsx(IconButton, { size: "small", edge: "end", onClick: (event) => {
                                                event.stopPropagation();
                                                toggleHostExpanded(host.id);
                                            }, children: isExpanded ? _jsx(KeyboardArrowDownIcon, { fontSize: "small" }) : _jsx(KeyboardArrowRightIcon, { fontSize: "small" }) }))] }), isExpanded && !isCollapsed && (_jsxs(Stack, { sx: { pl: 5, pr: 1, pb: 1 }, spacing: 0.5, children: [_jsxs(ListItemButton, { sx: { borderRadius: 0 }, selected: isActiveHost && selectedSection === "ports", onClick: () => selectHostAndSection(host.id, "ports"), children: [_jsx(LanIcon, { fontSize: "small" }), _jsx(ListItemText, { sx: { ml: 1 }, primary: `Порты (${hostPortsCount})` })] }), _jsxs(ListItemButton, { sx: { borderRadius: 0 }, selected: isActiveHost && selectedSection === "endpoints", onClick: () => selectHostAndSection(host.id, "endpoints"), children: [_jsx(HubIcon, { fontSize: "small" }), _jsx(ListItemText, { sx: { ml: 1 }, primary: `Эндпоинты (${hostEndpointsCount})` })] }), _jsxs(ListItemButton, { sx: { borderRadius: 0 }, selected: isActiveHost && selectedSection === "vulns", onClick: () => selectHostAndSection(host.id, "vulns"), children: [_jsx(ReportProblemIcon, { fontSize: "small" }), _jsx(ListItemText, { sx: { ml: 1 }, primary: `Уязвимости (${hostVulnerabilitiesCount})` })] })] }))] }, host.id));
                    })] })] }));
}
