import AddIcon from "@mui/icons-material/Add";
import DeleteOutlineIcon from "@mui/icons-material/DeleteOutline";
import EditOutlinedIcon from "@mui/icons-material/EditOutlined";
import InsertDriveFileOutlinedIcon from "@mui/icons-material/InsertDriveFileOutlined";
import KeyboardArrowDownIcon from "@mui/icons-material/KeyboardArrowDown";
import KeyboardArrowRightIcon from "@mui/icons-material/KeyboardArrowRight";
import SubdirectoryArrowRightIcon from "@mui/icons-material/SubdirectoryArrowRight";
import { Box, IconButton, ListItemButton, ListItemText, Stack, Typography } from "@mui/material";
import { useMemo, useRef, useState, type DragEvent } from "react";

import type { ProjectNote } from "../types";

type Props = {
  notes: ProjectNote[];
  selectedNoteId: string | null;
  onSelect: (noteId: string) => void;
  onCreateRoot?: () => void;
  onCreateChild?: (parentId: string | null) => void;
  onRename?: (noteId: string) => void;
  onDelete?: (noteId: string) => void;
  /** Перемещение заметки в другого родителя (drop на узле или на root). */
  onMove?: (noteId: string, newParentId: string | null) => Promise<void> | void;
  /** Изменение порядка соседей (drop на drop-line между siblings). */
  onReorder?: (parentId: string | null, orderedIds: string[]) => Promise<void> | void;
};

type DragPayload = { type: "note"; id: string };

const DRAG_MIME = "application/x-pcf-note";

/**
 * Inline-дерево заметок для боковой панели проекта. Поддерживает:
 *  - expand/collapse узлов
 *  - HTML5 DnD: drop на узел меняет parent, drop на drop-line между siblings меняет sort_order
 *  - CRUD-кнопки (create child / rename / delete)
 */
export function NotesTreeInline({
  notes,
  selectedNoteId,
  onSelect,
  onCreateRoot,
  onCreateChild,
  onRename,
  onDelete,
  onMove,
  onReorder,
}: Props) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [dragNoteId, setDragNoteId] = useState<string | null>(null);
  const [dragOverNodeId, setDragOverNodeId] = useState<string | null>(null);
  const [dropLineKey, setDropLineKey] = useState<string | null>(null);
  const noteById = useMemo(() => new Map(notes.map((n) => [n.id, n])), [notes]);

  const notesByParent = useMemo(() => {
    const map = new Map<string | null, ProjectNote[]>();
    notes.forEach((note) => {
      const parentKey = note.parent_id ?? null;
      const list = map.get(parentKey) ?? [];
      list.push(note);
      map.set(parentKey, list);
    });
    map.forEach((siblings) => {
      siblings.sort((a, b) => a.sort_order - b.sort_order || a.title.localeCompare(b.title, "ru-RU"));
    });
    return map;
  }, [notes]);

  const toggleExpanded = (noteId: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(noteId)) next.delete(noteId);
      else next.add(noteId);
      return next;
    });
  };

  const ancestorsOf = (noteId: string): Set<string> => {
    const result = new Set<string>([noteId]);
    let cursor: string | null = noteId;
    while (cursor) {
      result.add(cursor);
      const node = noteById.get(cursor);
      if (!node) break;
      cursor = node.parent_id ?? null;
    }
    return result;
  };

  const transparentDragImage = useRef<HTMLImageElement | null>(null);
  const ensureDragImage = (): HTMLImageElement => {
    if (transparentDragImage.current) return transparentDragImage.current;
    const img = new Image();
    img.src =
      "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7";
    transparentDragImage.current = img;
    return img;
  };

  const writePayload = (event: DragEvent, noteId: string) => {
    event.dataTransfer.effectAllowed = "move";
    try {
      event.dataTransfer.setData(DRAG_MIME, JSON.stringify({ type: "note", id: noteId }));
      event.dataTransfer.setData("text/plain", `note:${noteId}`);
    } catch {
      /* ignore */
    }
    try {
      event.dataTransfer.setDragImage(ensureDragImage(), 0, 0);
    } catch {
      /* ignore */
    }
  };

  const readPayload = (event: DragEvent): DragPayload | null => {
    const raw = event.dataTransfer.getData(DRAG_MIME) || event.dataTransfer.getData("text/plain");
    if (!raw) {
      return dragNoteId ? { type: "note", id: dragNoteId } : null;
    }
    if (raw.startsWith("note:")) return { type: "note", id: raw.slice(5) };
    try {
      const parsed = JSON.parse(raw);
      if (parsed && parsed.type === "note" && parsed.id) return parsed as DragPayload;
    } catch {
      /* fall through */
    }
    return null;
  };

  const canDrop = (sourceId: string, targetParentId: string | null): boolean => {
    if (!targetParentId) return true; // root всегда можно
    if (sourceId === targetParentId) return false;
    return !ancestorsOf(targetParentId).has(sourceId) || targetParentId === sourceId
      ? !ancestorsOf(targetParentId).has(sourceId)
      : false;
  };

  const handleDropOnNode = async (event: DragEvent, targetNoteId: string) => {
    event.preventDefault();
    event.stopPropagation();
    const payload = readPayload(event);
    setDragOverNodeId(null);
    setDropLineKey(null);
    setDragNoteId(null);
    if (!payload || payload.id === targetNoteId) return;
    if (!canDrop(payload.id, targetNoteId)) return;
    if (onMove) await onMove(payload.id, targetNoteId);
  };

  const handleDropOnLine = async (
    event: DragEvent,
    parentId: string | null,
    insertBefore: string | null,
  ) => {
    event.preventDefault();
    event.stopPropagation();
    const payload = readPayload(event);
    setDragOverNodeId(null);
    setDropLineKey(null);
    setDragNoteId(null);
    if (!payload) return;
    if (!canDrop(payload.id, parentId)) return;
    const source = noteById.get(payload.id);
    if (!source) return;

    if (source.parent_id !== parentId) {
      if (onMove) await onMove(payload.id, parentId);
      // После перемещения порядок установит backend (в конец), без явного reorder
      return;
    }
    // Reorder внутри одного parent
    const siblings = (notesByParent.get(parentId) ?? []).filter((n) => n.id !== payload.id);
    const insertIdx = insertBefore ? siblings.findIndex((n) => n.id === insertBefore) : siblings.length;
    const orderedIds: string[] = [];
    siblings.forEach((sib, idx) => {
      if (idx === insertIdx) orderedIds.push(payload.id);
      orderedIds.push(sib.id);
    });
    if (insertIdx >= siblings.length) orderedIds.push(payload.id);
    if (onReorder) await onReorder(parentId, orderedIds);
  };

  const renderDropLine = (parentId: string | null, insertBefore: string | null, depth: number) => {
    const key = `${parentId ?? "root"}->${insertBefore ?? "end"}`;
    const isActive = dropLineKey === key && dragNoteId !== null;
    return (
      <Box
        key={key}
        onDragOver={(event) => {
          event.preventDefault();
          event.dataTransfer.dropEffect = "move";
          setDropLineKey(key);
          setDragOverNodeId(null);
        }}
        onDragLeave={() => {
          if (dropLineKey === key) setDropLineKey(null);
        }}
        onDrop={(event) => void handleDropOnLine(event, parentId, insertBefore)}
        sx={{
          ml: 1 + depth * 1.5,
          mr: 1,
          height: 8,
          opacity: dragNoteId ? 1 : 0,
          pointerEvents: dragNoteId ? "auto" : "none",
          transition: "opacity .15s ease",
          "&::before": {
            content: '""',
            display: "block",
            height: isActive ? "2px" : "1px",
            backgroundColor: isActive ? "rgba(126,224,255,0.9)" : "rgba(126,224,255,0.25)",
            borderRadius: 1,
            marginTop: "3px",
          },
        }}
      />
    );
  };

  const renderTree = (parentId: string | null, depth: number): JSX.Element[] => {
    const children = notesByParent.get(parentId) ?? [];
    const out: JSX.Element[] = [];
    out.push(renderDropLine(parentId, children[0]?.id ?? null, depth));
    children.forEach((note, idx) => {
      const nested = notesByParent.get(note.id) ?? [];
      const isExpanded = expanded.has(note.id);
      const isDragOver = dragOverNodeId === note.id;
      out.push(
        <Box key={note.id}>
          <ListItemButton
            selected={selectedNoteId === note.id}
            draggable
            onDragStart={(event) => {
              setDragNoteId(note.id);
              writePayload(event, note.id);
            }}
            onDragEnd={() => {
              setDragNoteId(null);
              setDragOverNodeId(null);
              setDropLineKey(null);
            }}
            onDragOver={(event) => {
              if (!dragNoteId || dragNoteId === note.id) return;
              if (!canDrop(dragNoteId, note.id)) return;
              event.preventDefault();
              event.dataTransfer.dropEffect = "move";
              setDragOverNodeId(note.id);
              setDropLineKey(null);
            }}
            onDragLeave={() => {
              if (dragOverNodeId === note.id) setDragOverNodeId(null);
            }}
            onDrop={(event) => void handleDropOnNode(event, note.id)}
            onClick={() => onSelect(note.id)}
            sx={{
              pl: 1 + depth * 1.5,
              pr: 0.5,
              py: 0.5,
              ...(isDragOver
                ? {
                    backgroundColor: "rgba(126,224,255,0.14)",
                    outline: "1px dashed rgba(126,224,255,0.55)",
                    outlineOffset: "-1px",
                  }
                : {}),
            }}
          >
            {nested.length > 0 ? (
              <IconButton
                size="small"
                edge="start"
                onClick={(event) => {
                  event.stopPropagation();
                  toggleExpanded(note.id);
                }}
                sx={{ mr: 0.25 }}
              >
                {isExpanded ? <KeyboardArrowDownIcon fontSize="small" /> : <KeyboardArrowRightIcon fontSize="small" />}
              </IconButton>
            ) : (
              <Box sx={{ width: 28 }} />
            )}
            <InsertDriveFileOutlinedIcon fontSize="small" sx={{ color: "rgba(126,224,255,0.55)" }} />
            <ListItemText
              primary={note.title}
              primaryTypographyProps={{ noWrap: true, fontSize: "0.82rem" }}
              sx={{ ml: 0.75, mr: 0.5 }}
            />
            <Stack direction="row" spacing={0} sx={{ opacity: 0.55, "&:hover": { opacity: 1 } }}>
              {onCreateChild && (
                <IconButton
                  size="small"
                  aria-label="Добавить подстраницу"
                  onClick={(event) => {
                    event.stopPropagation();
                    onCreateChild(note.id);
                  }}
                >
                  <SubdirectoryArrowRightIcon fontSize="small" />
                </IconButton>
              )}
              {onRename && (
                <IconButton
                  size="small"
                  aria-label="Переименовать"
                  onClick={(event) => {
                    event.stopPropagation();
                    onRename(note.id);
                  }}
                >
                  <EditOutlinedIcon fontSize="small" />
                </IconButton>
              )}
              {onDelete && (
                <IconButton
                  size="small"
                  aria-label="Удалить"
                  onClick={(event) => {
                    event.stopPropagation();
                    onDelete(note.id);
                  }}
                >
                  <DeleteOutlineIcon fontSize="small" />
                </IconButton>
              )}
            </Stack>
          </ListItemButton>
          {isExpanded && nested.length > 0 && <Box>{renderTree(note.id, depth + 1)}</Box>}
        </Box>,
      );
      out.push(renderDropLine(parentId, children[idx + 1]?.id ?? null, depth));
    });
    return out;
  };

  return (
    <Box>
      {onCreateRoot && (
        <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ px: 1.25, py: 0.5 }}>
          <Typography variant="caption" sx={{ opacity: 0.7 }}>
            Дерево заметок
          </Typography>
          <IconButton size="small" aria-label="Создать корневую страницу" onClick={onCreateRoot}>
            <AddIcon fontSize="small" />
          </IconButton>
        </Stack>
      )}
      {notes.length === 0 ? (
        <Box sx={{ px: 1.5, py: 1 }}>
          <Typography variant="body2" color="text.secondary">
            Пока нет заметок.
          </Typography>
        </Box>
      ) : (
        <Box>{renderTree(null, 0)}</Box>
      )}
    </Box>
  );
}
