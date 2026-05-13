import AltRouteIcon from "@mui/icons-material/AltRoute";
import CableIcon from "@mui/icons-material/Cable";
import ChevronLeftIcon from "@mui/icons-material/ChevronLeft";
import ChevronRightIcon from "@mui/icons-material/ChevronRight";
import DescriptionIcon from "@mui/icons-material/Description";
import DnsIcon from "@mui/icons-material/Dns";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import HubIcon from "@mui/icons-material/Hub";
import ReportProblemIcon from "@mui/icons-material/ReportProblem";
import {
  Box,
  Collapse,
  Divider,
  IconButton,
  List,
  ListItemButton,
  ListItemText,
  Stack,
  Typography,
} from "@mui/material";
import { useState, type MouseEvent as ReactMouseEvent } from "react";
import type { Host, HostTreeStats, ProjectNote } from "../types";
import { HostOsIcon } from "./HostOsIcon";
import { NotesTreeInline } from "./NotesTreeInline";

export type DetailSection = "overview" | "notes" | "hosts" | "ports" | "endpoints" | "vulns";

interface ProjectTreeNavProps {
  hosts: Host[];
  selectedHostId: string | null;
  selectedSection: DetailSection;
  isCollapsed: boolean;
  portsCount: number;
  endpointsCount: number;
  vulnerabilitiesCount: number;
  hostStatsById?: Record<string, HostTreeStats>;
  onSelectProjectOverview?: () => void;
  notesCount?: number;
  notes?: ProjectNote[];
  selectedNoteId?: string | null;
  onToggleCollapsed: () => void;
  onSelectSection: (section: DetailSection) => void;
  onSelectNote?: (noteId: string) => void;
  onCreateNote?: (parentId: string | null) => void;
  onRenameNote?: (noteId: string) => void;
  onDeleteNote?: (noteId: string) => void;
  onMoveNote?: (noteId: string, newParentId: string | null) => Promise<void> | void;
  onReorderNotes?: (parentId: string | null, orderedIds: string[]) => Promise<void> | void;
  onSelectHost: (hostId: string | null) => void;
  onOpenHost?: (hostId: string, section: DetailSection) => void;
}

const STATUS_COLOR: Record<Host["status"], string> = {
  up: "rgba(76,175,80,0.85)",
  down: "rgba(244,67,54,0.85)",
  unknown: "rgba(160,160,160,0.55)",
};

export function ProjectTreeNav({
  hosts,
  selectedHostId,
  selectedSection,
  isCollapsed,
  portsCount,
  endpointsCount,
  vulnerabilitiesCount,
  hostStatsById,
  onSelectProjectOverview,
  notesCount = 0,
  notes = [],
  selectedNoteId = null,
  onToggleCollapsed,
  onSelectSection,
  onSelectNote,
  onCreateNote,
  onRenameNote,
  onDeleteNote,
  onMoveNote,
  onReorderNotes,
  onSelectHost,
  onOpenHost,
}: ProjectTreeNavProps) {
  const [notesExpanded, setNotesExpanded] = useState<boolean>(selectedSection === "notes");
  const [hostsExpanded, setHostsExpanded] = useState<boolean>(
    selectedSection === "hosts" || selectedSection === "ports" || selectedSection === "endpoints" || selectedSection === "vulns",
  );
  const [expandedHostIds, setExpandedHostIds] = useState<Set<string>>(
    () => new Set(selectedHostId ? [selectedHostId] : []),
  );

  const selectHostAndSection = (hostId: string, section: DetailSection) => {
    onSelectHost(hostId);
    onSelectSection(section);
    if (onOpenHost) {
      onOpenHost(hostId, section);
    }
  };

  const handleNotesLabelClick = (_event: ReactMouseEvent<HTMLDivElement>) => {
    onSelectSection("notes");
    setNotesExpanded(true);
  };

  const handleHostsLabelClick = () => {
    onSelectHost(null);
    onSelectSection("hosts");
    setHostsExpanded(true);
  };

  const toggleHostExpanded = (hostId: string) => {
    setExpandedHostIds((prev) => {
      const next = new Set(prev);
      if (next.has(hostId)) next.delete(hostId);
      else next.add(hostId);
      return next;
    });
  };

  return (
    <Box
      sx={{
        width: { xs: "100%", md: isCollapsed ? 88 : 340 },
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
        <ListItemButton
          selected={selectedSection === "overview"}
          onClick={() => (onSelectProjectOverview ? onSelectProjectOverview() : onSelectSection("overview"))}
        >
          <HubIcon fontSize="small" />
          {!isCollapsed && <ListItemText sx={{ ml: 1 }} primary="Обзор проекта" />}
        </ListItemButton>

        <Divider sx={{ my: 0.5 }} />

        {/* === Раздел Заметки === */}
        <Box sx={{ display: "flex", alignItems: "stretch" }}>
          <ListItemButton
            selected={selectedSection === "notes"}
            onClick={handleNotesLabelClick}
            sx={{ flex: 1, minWidth: 0 }}
          >
            <DescriptionIcon fontSize="small" />
            {!isCollapsed && (
              <ListItemText
                sx={{ ml: 1 }}
                primary={notesCount > 0 ? `Заметки (${notesCount})` : "Заметки"}
              />
            )}
          </ListItemButton>
          {!isCollapsed && (
            <IconButton
              size="small"
              aria-label={notesExpanded ? "Свернуть заметки" : "Развернуть заметки"}
              onClick={(event) => {
                event.stopPropagation();
                setNotesExpanded((v) => !v);
              }}
              sx={{
                alignSelf: "center",
                mr: 0.5,
                transform: notesExpanded ? "rotate(0deg)" : "rotate(-90deg)",
                transition: "transform .15s ease",
              }}
            >
              <ExpandMoreIcon fontSize="small" />
            </IconButton>
          )}
        </Box>
        {!isCollapsed && (
          <Collapse in={notesExpanded} unmountOnExit>
            <NotesTreeInline
              notes={notes}
              selectedNoteId={selectedNoteId}
              onSelect={(noteId) => {
                onSelectSection("notes");
                if (onSelectNote) onSelectNote(noteId);
              }}
              onCreateRoot={onCreateNote ? () => onCreateNote(null) : undefined}
              onCreateChild={onCreateNote}
              onRename={onRenameNote}
              onDelete={onDeleteNote}
              onMove={onMoveNote}
              onReorder={onReorderNotes}
            />
          </Collapse>
        )}

        <Divider sx={{ my: 0.5 }} />

        {/* === Раздел Хосты === */}
        <Box sx={{ display: "flex", alignItems: "stretch" }}>
          <ListItemButton
            selected={selectedSection === "hosts"}
            onClick={handleHostsLabelClick}
            sx={{ flex: 1, minWidth: 0 }}
          >
            <DnsIcon fontSize="small" />
            {!isCollapsed && (
              <ListItemText
                sx={{ ml: 1 }}
                primary={hosts.length > 0 ? `Хосты (${hosts.length})` : "Хосты"}
              />
            )}
          </ListItemButton>
          {!isCollapsed && (
            <IconButton
              size="small"
              aria-label={hostsExpanded ? "Свернуть хосты" : "Развернуть хосты"}
              onClick={(event) => {
                event.stopPropagation();
                setHostsExpanded((v) => !v);
              }}
              sx={{
                alignSelf: "center",
                mr: 0.5,
                transform: hostsExpanded ? "rotate(0deg)" : "rotate(-90deg)",
                transition: "transform .15s ease",
              }}
            >
              <ExpandMoreIcon fontSize="small" />
            </IconButton>
          )}
        </Box>

        {!isCollapsed && (
          <Collapse in={hostsExpanded} unmountOnExit>
            {hosts.map((host) => {
              const label = host.hostname || host.ip_address || "unknown-host";
              const isActiveHost = selectedHostId === host.id;
              const isHostExpanded = expandedHostIds.has(host.id);
              const hostStats = hostStatsById?.[host.id];
              const hostPortsCount = hostStats?.portsCount ?? (isActiveHost ? portsCount : 0);
              const hostEndpointsCount = hostStats?.endpointsCount ?? (isActiveHost ? endpointsCount : 0);
              const hostVulnerabilitiesCount = hostStats?.vulnerabilitiesCount ?? (isActiveHost ? vulnerabilitiesCount : 0);
              return (
                <Box key={host.id}>
                  <Box sx={{ display: "flex", alignItems: "stretch" }}>
                    <ListItemButton
                      selected={isActiveHost && selectedSection === "overview"}
                      onClick={() => selectHostAndSection(host.id, "overview")}
                      sx={{ flex: 1, minWidth: 0, pl: 2 }}
                    >
                      <HostOsIcon
                        os_type={host.os_type}
                        fontSize="small"
                        sx={{
                          borderRadius: "50%",
                          outline: `1px solid ${STATUS_COLOR[host.status]}`,
                          outlineOffset: 1,
                        }}
                      />
                      <ListItemText sx={{ ml: 1 }} primary={label} primaryTypographyProps={{ noWrap: true }} />
                    </ListItemButton>
                    <IconButton
                      size="small"
                      aria-label={isHostExpanded ? "Свернуть хост" : "Развернуть хост"}
                      onClick={(event) => {
                        event.stopPropagation();
                        toggleHostExpanded(host.id);
                      }}
                      sx={{
                        alignSelf: "center",
                        mr: 0.5,
                        transform: isHostExpanded ? "rotate(0deg)" : "rotate(-90deg)",
                        transition: "transform .15s ease",
                      }}
                    >
                      <ExpandMoreIcon fontSize="small" />
                    </IconButton>
                  </Box>
                  <Collapse in={isHostExpanded} unmountOnExit>
                    <Stack sx={{ pl: 5, pr: 1, pb: 1 }} spacing={0.5}>
                      <ListItemButton
                        sx={{ borderRadius: 0 }}
                        selected={isActiveHost && selectedSection === "ports"}
                        onClick={() => selectHostAndSection(host.id, "ports")}
                      >
                        <CableIcon fontSize="small" />
                        <ListItemText sx={{ ml: 1 }} primary={`Порты (${hostPortsCount})`} />
                      </ListItemButton>
                      <ListItemButton
                        sx={{ borderRadius: 0 }}
                        selected={isActiveHost && selectedSection === "endpoints"}
                        onClick={() => selectHostAndSection(host.id, "endpoints")}
                      >
                        <AltRouteIcon fontSize="small" />
                        <ListItemText sx={{ ml: 1 }} primary={`Эндпоинты (${hostEndpointsCount})`} />
                      </ListItemButton>
                      <ListItemButton
                        sx={{ borderRadius: 0 }}
                        selected={isActiveHost && selectedSection === "vulns"}
                        onClick={() => selectHostAndSection(host.id, "vulns")}
                      >
                        <ReportProblemIcon fontSize="small" />
                        <ListItemText sx={{ ml: 1 }} primary={`Уязвимости (${hostVulnerabilitiesCount})`} />
                      </ListItemButton>
                    </Stack>
                  </Collapse>
                </Box>
              );
            })}
          </Collapse>
        )}
      </List>
    </Box>
  );
}
