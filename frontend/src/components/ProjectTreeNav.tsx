import ChevronLeftIcon from "@mui/icons-material/ChevronLeft";
import ChevronRightIcon from "@mui/icons-material/ChevronRight";
import DnsIcon from "@mui/icons-material/Dns";
import HubIcon from "@mui/icons-material/Hub";
import KeyboardArrowDownIcon from "@mui/icons-material/KeyboardArrowDown";
import KeyboardArrowRightIcon from "@mui/icons-material/KeyboardArrowRight";
import LanIcon from "@mui/icons-material/Lan";
import ReportProblemIcon from "@mui/icons-material/ReportProblem";
import {
  Box,
  Divider,
  IconButton,
  List,
  ListItemButton,
  ListItemText,
  Stack,
  Typography,
} from "@mui/material";
import { useEffect, useState } from "react";
import type { Host, HostTreeStats } from "../types";

export type DetailSection = "overview" | "hosts" | "ports" | "endpoints" | "vulns";

interface ProjectTreeNavProps {
  hosts: Host[];
  selectedHostId: string | null;
  selectedSection: DetailSection;
  isCollapsed: boolean;
  portsCount: number;
  endpointsCount: number;
  vulnerabilitiesCount: number;
  hostStatsById?: Record<string, HostTreeStats>;
  autoExpandSelectedHost?: boolean;
  onSelectProjectOverview?: () => void;
  onToggleCollapsed: () => void;
  onSelectSection: (section: DetailSection) => void;
  onSelectHost: (hostId: string) => void;
  onOpenHost?: (hostId: string) => void;
}

export function ProjectTreeNav({
  hosts,
  selectedHostId,
  selectedSection,
  isCollapsed,
  portsCount,
  endpointsCount,
  vulnerabilitiesCount,
  hostStatsById,
  autoExpandSelectedHost = true,
  onSelectProjectOverview,
  onToggleCollapsed,
  onSelectSection,
  onSelectHost,
  onOpenHost,
}: ProjectTreeNavProps) {
  const [expandedHosts, setExpandedHosts] = useState<Set<string>>(new Set());

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

  const toggleHostExpanded = (hostId: string) => {
    setExpandedHosts((previous) => {
      const next = new Set(previous);
      if (next.has(hostId)) {
        next.delete(hostId);
      } else {
        next.add(hostId);
      }
      return next;
    });
  };

  const selectHostAndSection = (hostId: string, section: DetailSection) => {
    onSelectHost(hostId);
    onSelectSection(section);
    if (onOpenHost) {
      onOpenHost(hostId);
    }
  };

  return (
    <Box
      sx={{
        width: { xs: "100%", md: isCollapsed ? 88 : 320 },
        transition: "width .2s ease",
        borderRight: { xs: "none", md: "1px solid rgba(126,224,255,0.18)" },
        overflow: "hidden",
        flexShrink: 0,
        pr: { xs: 0, md: 1.5 },
      }}
    >
      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ px: 1.5, py: 1 }}>
        {!isCollapsed && (
          <Typography variant="subtitle2" fontWeight={700}>
            Структура проекта
          </Typography>
        )}
        <IconButton size="small" onClick={onToggleCollapsed}>
          {isCollapsed ? <ChevronRightIcon /> : <ChevronLeftIcon />}
        </IconButton>
      </Stack>
      <Divider />
      <List dense disablePadding>
        <ListItemButton selected={selectedSection === "overview"} onClick={() => (onSelectProjectOverview ? onSelectProjectOverview() : onSelectSection("overview"))}>
          <HubIcon fontSize="small" />
          {!isCollapsed && <ListItemText sx={{ ml: 1 }} primary="Обзор проекта" />}
        </ListItemButton>

        <Divider sx={{ my: 0.5 }} />
        {!isCollapsed && (
          <Typography sx={{ px: 2, pt: 1, pb: 0.5 }} variant="caption" color="text.secondary">
            Хосты
          </Typography>
        )}
        {hosts.map((host) => {
          const label = host.hostname || host.ip_address || "unknown-host";
          const isActiveHost = selectedHostId === host.id;
          const isExpanded = expandedHosts.has(host.id);
          const hostStats = hostStatsById?.[host.id];
          const hostPortsCount = hostStats?.portsCount ?? (isActiveHost ? portsCount : 0);
          const hostEndpointsCount = hostStats?.endpointsCount ?? (isActiveHost ? endpointsCount : 0);
          const hostVulnerabilitiesCount = hostStats?.vulnerabilitiesCount ?? (isActiveHost ? vulnerabilitiesCount : 0);
          return (
            <Box key={host.id}>
              <ListItemButton selected={isActiveHost && (selectedSection === "hosts" || selectedSection === "overview")} onClick={() => selectHostAndSection(host.id, "overview")}>
                <DnsIcon fontSize="small" />
                {!isCollapsed && <ListItemText sx={{ ml: 1 }} primary={label} secondary={`Статус: ${host.status}`} />}
                {!isCollapsed && (
                  <IconButton
                    size="small"
                    edge="end"
                    onClick={(event) => {
                      event.stopPropagation();
                      toggleHostExpanded(host.id);
                    }}
                  >
                    {isExpanded ? <KeyboardArrowDownIcon fontSize="small" /> : <KeyboardArrowRightIcon fontSize="small" />}
                  </IconButton>
                )}
              </ListItemButton>
              {isExpanded && !isCollapsed && (
                <Stack sx={{ pl: 5, pr: 1, pb: 1 }} spacing={0.5}>
                  <ListItemButton sx={{ borderRadius: 0 }} selected={isActiveHost && selectedSection === "ports"} onClick={() => selectHostAndSection(host.id, "ports")}>
                    <LanIcon fontSize="small" />
                    <ListItemText sx={{ ml: 1 }} primary={`Порты (${hostPortsCount})`} />
                  </ListItemButton>
                  <ListItemButton
                    sx={{ borderRadius: 0 }}
                    selected={isActiveHost && selectedSection === "endpoints"}
                    onClick={() => selectHostAndSection(host.id, "endpoints")}
                  >
                    <HubIcon fontSize="small" />
                    <ListItemText sx={{ ml: 1 }} primary={`Эндпоинты (${hostEndpointsCount})`} />
                  </ListItemButton>
                  <ListItemButton sx={{ borderRadius: 0 }} selected={isActiveHost && selectedSection === "vulns"} onClick={() => selectHostAndSection(host.id, "vulns")}>
                    <ReportProblemIcon fontSize="small" />
                    <ListItemText sx={{ ml: 1 }} primary={`Уязвимости (${hostVulnerabilitiesCount})`} />
                  </ListItemButton>
                </Stack>
              )}
            </Box>
          );
        })}
      </List>
    </Box>
  );
}
