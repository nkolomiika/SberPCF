import AddIcon from "@mui/icons-material/Add";
import InsertDriveFileOutlinedIcon from "@mui/icons-material/InsertDriveFileOutlined";
import KeyboardArrowDownIcon from "@mui/icons-material/KeyboardArrowDown";
import KeyboardArrowRightIcon from "@mui/icons-material/KeyboardArrowRight";
import { Box, IconButton, ListItemButton, ListItemText, Typography } from "@mui/material";
import { useMemo, useRef, useState, type DragEvent } from "react";

import type { ProjectNote } from "../types";

type Props = {
  notes: ProjectNote[];
  selectedNoteId: string | null;
  onSelect: (noteId: string) => void;
  /** Создать подстраницу (parentId === null означает создать корневую страницу). */
  onCreateChild?: (parentId: string | null) => void;
  /** Перемещение заметки в другого родителя (drop на узле). */
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
 *  - кнопка «+» появляется при наведении на узел (создание подстраницы)
 *
 * Rename/delete вынесены в страницу самой заметки и здесь не отображаются.
 */
export function NotesTreeInline({
  notes,
  selectedNoteId,
  onSelect,
  onCreateChild,
  onMove,
  onReorder,
}: Props) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [dragNoteId, setDragNoteId] = useState<string | null>(null);
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
    img.src = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7";
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
    if (!targetParentId) return true;
    if (sourceId === targetParentId) return false;
    return !ancestorsOf(targetParentId).has(sourceId);
  };

  const handleDropOnNode = async (event: DragEvent, targetNoteId: string) => {
    event.preventDefault();
    event.stopPropagation();
    const payload = readPayload(event);
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
    setDropLineKey(null);
    setDragNoteId(null);
    if (!payload) return;
    if (!canDrop(payload.id, parentId)) return;
    const source = noteById.get(payload.id);
    if (!source) return;

    if (source.parent_id !== parentId) {
      if (onMove) await onMove(payload.id, parentId);
      return;
    }
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
    return (
      <Box
        key={key}
        onDragOver={(event) => {
          if (!dragNoteId) return;
          event.preventDefault();
          event.dataTransfer.dropEffect = "move";
          setDropLineKey(key);
        }}
        onDragLeave={() => {
          if (dropLineKey === key) setDropLineKey(null);
        }}
        onDrop={(event) => void handleDropOnLine(event, parentId, insertBefore)}
        sx={{
          ml: 1 + depth * 1.5,
          mr: 1,
          height: 6,
          pointerEvents: dragNoteId ? "auto" : "none",
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
      out.push(
        <Box key={note.id} sx={{ "&:hover .note-tree-add-btn": { opacity: 1 } }}>
          <ListItemButton
            selected={selectedNoteId === note.id}
            draggable
            onDragStart={(event) => {
              setDragNoteId(note.id);
              writePayload(event, note.id);
            }}
            onDragEnd={() => {
              setDragNoteId(null);
              setDropLineKey(null);
            }}
            onDragOver={(event) => {
              if (!dragNoteId || dragNoteId === note.id) return;
              if (!canDrop(dragNoteId, note.id)) return;
              event.preventDefault();
              event.dataTransfer.dropEffect = "move";
            }}
            onDrop={(event) => void handleDropOnNode(event, note.id)}
            onClick={() => onSelect(note.id)}
            sx={{ pl: 1 + depth * 1.5, pr: 0.5, py: 0.5, color: "inherit" }}
          >
            {nested.length > 0 ? (
              <IconButton
                size="small"
                edge="start"
                disableRipple
                onClick={(event) => {
                  event.stopPropagation();
                  toggleExpanded(note.id);
                }}
                sx={{ mr: 0.25, color: "inherit", "&:hover": { backgroundColor: "transparent" } }}
              >
                {isExpanded ? <KeyboardArrowDownIcon fontSize="small" /> : <KeyboardArrowRightIcon fontSize="small" />}
              </IconButton>
            ) : (
              <Box sx={{ width: 28 }} />
            )}
            <InsertDriveFileOutlinedIcon fontSize="small" sx={{ color: "inherit" }} />
            <ListItemText
              primary={note.title}
              primaryTypographyProps={{ noWrap: true, fontSize: "0.82rem" }}
              sx={{ ml: 0.75, mr: 0.5 }}
            />
            {onCreateChild && (
              <IconButton
                size="small"
                aria-label="Добавить подстраницу"
                className="note-tree-add-btn"
                onClick={(event) => {
                  event.stopPropagation();
                  onCreateChild(note.id);
                }}
                sx={{ opacity: 0, transition: "opacity .15s ease", color: "inherit" }}
              >
                <AddIcon fontSize="small" />
              </IconButton>
            )}
          </ListItemButton>
          {nested.length > 0 && (
            <Box
              sx={{
                maxHeight: isExpanded ? 4000 : 0,
                overflow: "hidden",
                transition: "max-height .26s ease",
              }}
            >
              {renderTree(note.id, depth + 1)}
            </Box>
          )}
        </Box>,
      );
      out.push(renderDropLine(parentId, children[idx + 1]?.id ?? null, depth));
    });
    return out;
  };

  return (
    <Box>
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
