import AltRouteIcon from "@mui/icons-material/AltRoute";
import ChevronLeftIcon from "@mui/icons-material/ChevronLeft";
import ChevronRightIcon from "@mui/icons-material/ChevronRight";
import DescriptionIcon from "@mui/icons-material/Description";
import DnsIcon from "@mui/icons-material/Dns";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import HubIcon from "@mui/icons-material/Hub";
import LanIcon from "@mui/icons-material/Lan";
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
import { useCallback, useEffect, useMemo, useState, type MouseEvent as ReactMouseEvent } from "react";
import type { Host, HostTreeStats, ProjectNote } from "../types";
import { HostOsIcon } from "./HostOsIcon";
import { NotesTreeInline } from "./NotesTreeInline";

export type DetailSection = "overview" | "notes" | "hosts" | "ports" | "endpoints" | "vulns";

interface ProjectTreeNavProps {
  /** Ключ для сохранения состояния раскрытия дерева в localStorage (обычно — projectId). */
  projectId?: string | null;
  /**
   * "project" — открыт ProjectDetailPage: хост в дереве не подсвечивается даже если selectedHostId
   * выставлен (это нужно только для предзагрузки данных хоста), все секции по умолчанию свёрнуты.
   * "host" — открыт HostDetailPage: текущий хост раскрыт и подсвечен.
   */
  viewMode?: "project" | "host";
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
  /** Клик по самой плашке «Заметки» в дереве — без выбора конкретной заметки.
   *  Используется, чтобы родитель сбросил selectedNoteId и показал статистику. */
  onSelectNotesLabel?: () => void;
  onCreateNote?: (parentId: string | null) => void;
  onRenameNote?: (noteId: string) => void;
  onDeleteNote?: (noteId: string) => void;
  onMoveNote?: (noteId: string, newParentId: string | null) => Promise<void> | void;
  onReorderNotes?: (parentId: string | null, orderedIds: string[]) => Promise<void> | void;
  onSelectHost: (hostId: string | null) => void;
  onOpenHost?: (hostId: string, section: DetailSection) => void;
}

type PersistedTreeState = {
  notesExpanded: boolean;
  hostsExpanded: boolean;
  expandedHostIds: string[];
};

const storageKey = (projectId: string | null | undefined): string | null =>
  projectId ? `tree-nav:${projectId}` : null;

const loadPersistedState = (projectId: string | null | undefined): PersistedTreeState | null => {
  const key = storageKey(projectId);
  if (!key || typeof window === "undefined") return null;
  try {
    const raw = window.localStorage.getItem(key);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null) return null;
    return {
      notesExpanded: Boolean(parsed.notesExpanded),
      hostsExpanded: Boolean(parsed.hostsExpanded),
      expandedHostIds: Array.isArray(parsed.expandedHostIds) ? parsed.expandedHostIds.map(String) : [],
    };
  } catch {
    return null;
  }
};

export function ProjectTreeNav({
  projectId,
  viewMode = "project",
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
  onSelectNotesLabel,
  onCreateNote,
  onMoveNote,
  onReorderNotes,
  onSelectHost,
  onOpenHost,
}: ProjectTreeNavProps) {
  const persisted = useMemo(() => loadPersistedState(projectId), [projectId]);
  // На project-странице ВСЁ свёрнуто по умолчанию (когда нет персистентного состояния),
  // даже если у юзера выбрана секция или есть selectedHostId. Исключения:
  //   1) host-режим: раскрываем секцию хостов и текущий хост;
  //   2) первый рендер с selectedSection === "hosts"/"notes" (приход с location.state) —
  //      сразу раскрываем соответствующую ветку, чтобы юзер не видел свёрнутого дерева.
  const [notesExpanded, setNotesExpanded] = useState<boolean>(
    persisted?.notesExpanded ?? (selectedSection === "notes" || viewMode === "host"),
  );
  const [hostsExpanded, setHostsExpanded] = useState<boolean>(
    persisted?.hostsExpanded ??
      (selectedSection === "hosts" ||
        selectedSection === "ports" ||
        selectedSection === "endpoints" ||
        selectedSection === "vulns" ||
        viewMode === "host"),
  );
  const [expandedHostIds, setExpandedHostIds] = useState<Set<string>>(() => {
    const fromStorage = persisted?.expandedHostIds ?? [];
    const combined = new Set<string>(fromStorage);
    if (viewMode === "host" && selectedHostId) combined.add(selectedHostId);
    return combined;
  });

  // Сохраняем состояние раскрытия дерева в localStorage — переживает переходы между
  // ProjectDetailPage и HostDetailPage без сброса.
  useEffect(() => {
    const key = storageKey(projectId);
    if (!key || typeof window === "undefined") return;
    try {
      const payload: PersistedTreeState = {
        notesExpanded,
        hostsExpanded,
        expandedHostIds: Array.from(expandedHostIds),
      };
      window.localStorage.setItem(key, JSON.stringify(payload));
    } catch {
      /* quota or disabled storage — игнорируем */
    }
  }, [projectId, notesExpanded, hostsExpanded, expandedHostIds]);

  // Когда выбирается хост, разворачиваем секцию Хосты и сам хост — только в host-режиме.
  // В project-режиме selectedHostId меняется при подгрузке данных, но юзеру не нужно
  // автоматически раскрывать ветку, пока он не нажал на «Хосты» сам.
  useEffect(() => {
    if (viewMode !== "host") return;
    if (!selectedHostId) return;
    setHostsExpanded(true);
    setExpandedHostIds((prev) => (prev.has(selectedHostId) ? prev : new Set(prev).add(selectedHostId)));
  }, [selectedHostId, viewMode]);

  const selectHostAndSection = (hostId: string, section: DetailSection) => {
    onSelectHost(hostId);
    onSelectSection(section);
    if (onOpenHost) {
      onOpenHost(hostId, section);
    }
  };

  const handleNotesLabelClick = (_event: ReactMouseEvent<HTMLDivElement>) => {
    // Клик по плашке «Заметки» — открываем сводку (история изменений), а не
    // конкретную заметку. Родитель сбрасывает selectedNoteId через onSelectNotesLabel.
    if (onSelectNotesLabel) onSelectNotesLabel();
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
        flexShrink: 0,
        pr: { xs: 0, md: 1.5 },
        // Структура проекта зафиксирована: при скролле основного контента сайдбар остаётся на месте.
        position: { xs: "static", md: "sticky" },
        top: { md: 16 },
        alignSelf: { md: "flex-start" },
        maxHeight: { md: "calc(100vh - 32px)" },
        overflowY: { md: "auto" },
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
      {/*
        sx-стиль ниже снимает синюю подсветку активного пункта (`Mui-selected`)
        у всех ListItemButton'ов внутри этого List — по запросу: после выбора
        раздела/заметки/хоста ничего не подкрашиваем.
      */}
      <List
        dense
        disablePadding
        sx={{
          "& .MuiListItemButton-root.Mui-selected, & .MuiListItemButton-root.Mui-selected:hover": {
            backgroundColor: "transparent",
          },
        }}
      >
        <ListItemButton
          onClick={() => (onSelectProjectOverview ? onSelectProjectOverview() : onSelectSection("overview"))}
        >
          <HubIcon fontSize="small" />
          {!isCollapsed && <ListItemText sx={{ ml: 1 }} primary="Обзор проекта" />}
        </ListItemButton>

        <Divider sx={{ my: 0.5 }} />

        {/* === Раздел Заметки === */}
        <ListItemButton
          selected={selectedSection === "notes"}
          onClick={handleNotesLabelClick}
          sx={{ pr: 1 }}
        >
          <DescriptionIcon fontSize="small" />
          {!isCollapsed && (
            <ListItemText
              sx={{ ml: 1 }}
              primary={notesCount > 0 ? `Заметки (${notesCount})` : "Заметки"}
            />
          )}
          {!isCollapsed && (
            <Box
              role="button"
              aria-label={notesExpanded ? "Свернуть заметки" : "Развернуть заметки"}
              onClick={(event) => {
                event.stopPropagation();
                setNotesExpanded((v) => !v);
              }}
              sx={{
                display: "inline-flex",
                alignItems: "center",
                justifyContent: "center",
                ml: 0.5,
                cursor: "pointer",
                color: "inherit",
                transform: notesExpanded ? "rotate(0deg)" : "rotate(-90deg)",
                transition: "transform .2s ease",
                "&:hover": { backgroundColor: "transparent" },
              }}
            >
              <ExpandMoreIcon fontSize="small" />
            </Box>
          )}
        </ListItemButton>
        {!isCollapsed && (
          <Collapse in={notesExpanded} timeout={260} mountOnEnter>
            {/*
              Лёгкий правый отступ всему дереву, чтобы заметки визуально были
              «детьми» заголовка секции, как раньше до плоской вёрстки.
            */}
            <Box sx={{ pl: 1.25 }}>
              <NotesTreeInline
                notes={notes}
                selectedNoteId={selectedNoteId}
                onSelect={(noteId) => {
                  onSelectSection("notes");
                  if (onSelectNote) onSelectNote(noteId);
                }}
                onCreateChild={onCreateNote}
                onMove={onMoveNote}
                onReorder={onReorderNotes}
              />
            </Box>
          </Collapse>
        )}

        <Divider sx={{ my: 0.5 }} />

        {/* === Раздел Хосты === */}
        <ListItemButton
          selected={selectedSection === "hosts"}
          onClick={handleHostsLabelClick}
          sx={{ pr: 1 }}
        >
          <DnsIcon fontSize="small" />
          {!isCollapsed && (
            <ListItemText
              sx={{ ml: 1 }}
              primary={hosts.length > 0 ? `Хосты (${hosts.length})` : "Хосты"}
            />
          )}
          {!isCollapsed && (
            <Box
              role="button"
              aria-label={hostsExpanded ? "Свернуть хосты" : "Развернуть хосты"}
              onClick={(event) => {
                event.stopPropagation();
                setHostsExpanded((v) => !v);
              }}
              sx={{
                display: "inline-flex",
                alignItems: "center",
                justifyContent: "center",
                ml: 0.5,
                cursor: "pointer",
                color: "inherit",
                transform: hostsExpanded ? "rotate(0deg)" : "rotate(-90deg)",
                transition: "transform .2s ease",
                "&:hover": { backgroundColor: "transparent" },
              }}
            >
              <ExpandMoreIcon fontSize="small" />
            </Box>
          )}
        </ListItemButton>

        {!isCollapsed && (
          <Collapse in={hostsExpanded} timeout={260} mountOnEnter>
            {hosts.map((host) => {
              const label = host.hostname || host.ip_address || "unknown-host";
              const isActiveHost = selectedHostId === host.id;
              const isHostExpanded = expandedHostIds.has(host.id);
              const hostStats = hostStatsById?.[host.id];
              const hostIpAddressesCount = hostStats?.ipAddressesCount ?? host.ip_addresses.length;
              const hostEndpointsCount = hostStats?.endpointsCount ?? (isActiveHost ? endpointsCount : 0);
              const hostVulnerabilitiesCount = hostStats?.vulnerabilitiesCount ?? (isActiveHost ? vulnerabilitiesCount : 0);
              // На project-странице selectedHostId — это техническая «предзагрузка»
              // активов хоста. Внешне ничего не должно выглядеть как выбранное:
              // юзер открыл проект, а не хост. На host-странице — наоборот, подсвечиваем.
              const hostSelected = viewMode === "host" && isActiveHost && selectedSection === "overview";
              return (
                <Box key={host.id}>
                  <ListItemButton
                    selected={hostSelected}
                    onClick={() => selectHostAndSection(host.id, "overview")}
                    // 16px (паддинг заголовка «Хосты») + 20px (DnsIcon small) + 8px (ml=1)
                    // = 44px → иконка ОС хоста встаёт ровно под буквой «Х» в «Хосты».
                    sx={{ pl: "44px", pr: 1 }}
                  >
                    <HostOsIcon os_type={host.os_type} fontSize="small" />
                    <ListItemText sx={{ ml: 1 }} primary={label} primaryTypographyProps={{ noWrap: true }} />
                    <Box
                      role="button"
                      aria-label={isHostExpanded ? "Свернуть хост" : "Развернуть хост"}
                      onClick={(event) => {
                        event.stopPropagation();
                        toggleHostExpanded(host.id);
                      }}
                      sx={{
                        display: "inline-flex",
                        alignItems: "center",
                        justifyContent: "center",
                        ml: 0.5,
                        cursor: "pointer",
                        color: "inherit",
                        transform: isHostExpanded ? "rotate(0deg)" : "rotate(-90deg)",
                        transition: "transform .2s ease",
                        "&:hover": { backgroundColor: "transparent" },
                      }}
                    >
                      <ExpandMoreIcon fontSize="small" />
                    </Box>
                  </ListItemButton>
                  <Collapse in={isHostExpanded} timeout={260} mountOnEnter>
                    <ListItemButton
                      // Иконка под-секции встаёт под именем хоста (44px + 20px + 8px).
                      sx={{ pl: "72px", pr: 1 }}
                      selected={isActiveHost && selectedSection === "ports"}
                      onClick={() => selectHostAndSection(host.id, "ports")}
                    >
                      <LanIcon fontSize="small" />
                      <ListItemText sx={{ ml: 1 }} primary={`IP-адреса (${hostIpAddressesCount})`} />
                    </ListItemButton>
                    <ListItemButton
                      // Иконка под-секции встаёт под именем хоста (44px + 20px + 8px).
                      sx={{ pl: "72px", pr: 1 }}
                      selected={isActiveHost && selectedSection === "endpoints"}
                      onClick={() => selectHostAndSection(host.id, "endpoints")}
                    >
                      <AltRouteIcon fontSize="small" />
                      <ListItemText sx={{ ml: 1 }} primary={`Эндпоинты (${hostEndpointsCount})`} />
                    </ListItemButton>
                    <ListItemButton
                      // Иконка под-секции встаёт под именем хоста (44px + 20px + 8px).
                      sx={{ pl: "72px", pr: 1 }}
                      selected={isActiveHost && selectedSection === "vulns"}
                      onClick={() => selectHostAndSection(host.id, "vulns")}
                    >
                      <ReportProblemIcon fontSize="small" />
                      <ListItemText sx={{ ml: 1 }} primary={`Уязвимости (${hostVulnerabilitiesCount})`} />
                    </ListItemButton>
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
