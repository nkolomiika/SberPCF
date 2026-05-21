import AddIcon from "@mui/icons-material/Add";
import ArrowDownwardIcon from "@mui/icons-material/ArrowDownward";
import ArrowUpwardIcon from "@mui/icons-material/ArrowUpward";
import DeleteOutlineIcon from "@mui/icons-material/DeleteOutline";
import DriveFileMoveIcon from "@mui/icons-material/DriveFileMove";
import EditIcon from "@mui/icons-material/Edit";
import MoreVertIcon from "@mui/icons-material/MoreVert";
import {
  Avatar,
  Box,
  Button,
  Card,
  CardContent,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  IconButton,
  List,
  ListItem,
  Menu,
  MenuItem,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  createProjectNote,
  createProjectNoteComment,
  deleteProjectNote,
  deleteProjectNoteComment,
  getApiErrorMessage,
  listProjectNoteComments,
  listProjectNotes,
  moveProjectNote,
  reorderProjectNotes,
  updateProjectNote,
  updateProjectNoteComment,
} from "../api";
import { useAuthStore, useToastStore } from "../store";
import type { ProjectNote, ProjectNoteComment } from "../types";
import { MarkdownEditor } from "./MarkdownEditor";

type DialogMode = "create-root" | "create-child" | "rename" | "move" | null;

export function ProjectNotesSection({
  projectId,
  notes: externalNotes,
  selectedNoteId,
  onSelectNote,
  onNotesChange,
  commentsTick = 0,
  highlightCommentId = null,
  onHighlightHandled,
}: {
  projectId: string;
  /** Список заметок проекта — берём из родителя, чтобы не дублировать fetch и
   *  избежать гонок (родитель синхронизирует своё projectNotes по WS). */
  notes: ProjectNote[];
  selectedNoteId: string | null;
  onSelectNote: (noteId: string | null) => void;
  onNotesChange: (notes: ProjectNote[]) => void;
  /** Тик из WS-пуша — бампится при entity=project_note_comment. Перетягивает comments. */
  commentsTick?: number;
  /** ID комментария, который нужно подсветить (3 секунды) после перехода по уведомлению. */
  highlightCommentId?: string | null;
  onHighlightHandled?: () => void;
}) {
  const user = useAuthStore((state) => state.user);
  const pushToast = useToastStore((state) => state.pushToast);
  // notes теперь приходят сверху; локальный fetch удалён — это убирает
  // двойную загрузку и предыдущий рантайм-цикл «selectedNoteId not in notes →
  // refetch → setNotes → effect re-runs → refetch …».
  const notes = externalNotes;
  const [draftContent, setDraftContent] = useState("");
  const [busy, setBusy] = useState(false);
  const [dialogMode, setDialogMode] = useState<DialogMode>(null);
  const [dialogValue, setDialogValue] = useState("");
  const [moveTargetParentId, setMoveTargetParentId] = useState<string>("");
  const [actionsAnchorEl, setActionsAnchorEl] = useState<HTMLElement | null>(null);
  const [comments, setComments] = useState<ProjectNoteComment[]>([]);
  const [newComment, setNewComment] = useState("");
  const [error, setError] = useState<string | null>(null);
  // Меню действий комментария (троеточие) + диалог редактирования —
  // тот же UX, что в комментариях уязвимостей.
  const [commentActionsAnchorEl, setCommentActionsAnchorEl] = useState<HTMLElement | null>(null);
  const [activeComment, setActiveComment] = useState<ProjectNoteComment | null>(null);
  const [commentEditOpen, setCommentEditOpen] = useState(false);
  const [commentEditDraft, setCommentEditDraft] = useState("");
  const [commentEditBusy, setCommentEditBusy] = useState(false);

  const selectedNote = useMemo(
    () => notes.find((note) => note.id === selectedNoteId) ?? null,
    [notes, selectedNoteId]
  );

  const childrenByParent = useMemo(() => {
    const grouped = new Map<string | null, ProjectNote[]>();
    notes.forEach((note) => {
      const key = note.parent_id ?? null;
      const current = grouped.get(key) ?? [];
      current.push(note);
      grouped.set(key, current);
    });
    grouped.forEach((value) => {
      value.sort((left, right) => left.sort_order - right.sort_order || left.title.localeCompare(right.title, "ru-RU"));
    });
    return grouped;
  }, [notes]);

  const loadComments = useCallback(async () => {
    if (!selectedNoteId) {
      setComments([]);
      return;
    }
    try {
      const page = await listProjectNoteComments(projectId, selectedNoteId);
      setComments(page.items);
    } catch (loadError) {
      setError(getApiErrorMessage(loadError, "Не удалось загрузить комментарии"));
    }
  }, [projectId, selectedNoteId]);

  useEffect(() => {
    void loadComments();
    // commentsTick — внешний триггер (WS-пуш «изменился комментарий заметки»),
    // заставляет перетянуть список без поллинга.
  }, [loadComments, commentsTick]);

  useEffect(() => {
    if (!selectedNote) {
      setDraftContent("");
      return;
    }
    setDraftContent(selectedNote.content ?? "");
  }, [selectedNote]);

  const openCreateRootDialog = () => {
    setDialogMode("create-root");
    setDialogValue("");
  };

  const openCreateChildDialog = () => {
    if (!selectedNote) {
      return;
    }
    setDialogMode("create-child");
    setDialogValue("");
  };

  const openRenameDialog = () => {
    if (!selectedNote) {
      return;
    }
    setDialogMode("rename");
    setDialogValue(selectedNote.title);
  };

  const openMoveDialog = () => {
    if (!selectedNote) {
      return;
    }
    setDialogMode("move");
    setMoveTargetParentId(selectedNote.parent_id ?? "");
  };

  const descendants = useMemo(() => {
    if (!selectedNoteId) {
      return new Set<string>();
    }
    const ids = new Set<string>();
    const queue = [selectedNoteId];
    while (queue.length) {
      const currentId = queue.pop()!;
      const children = childrenByParent.get(currentId) ?? [];
      children.forEach((child) => {
        ids.add(child.id);
        queue.push(child.id);
      });
    }
    return ids;
  }, [childrenByParent, selectedNoteId]);

  const submitDialog = async () => {
    if (!dialogMode) {
      return;
    }
    try {
      setBusy(true);
      setError(null);
      if (dialogMode === "create-root") {
        const created = await createProjectNote(projectId, { title: dialogValue.trim(), parent_id: null, content: null });
        onNotesChange(await listProjectNotes(projectId));
        onSelectNote(created.id);
      } else if (dialogMode === "create-child" && selectedNote) {
        const created = await createProjectNote(projectId, { title: dialogValue.trim(), parent_id: selectedNote.id, content: null });
        onNotesChange(await listProjectNotes(projectId));
        onSelectNote(created.id);
      } else if (dialogMode === "rename" && selectedNote) {
        await updateProjectNote(projectId, selectedNote.id, { title: dialogValue.trim() });
        onNotesChange(await listProjectNotes(projectId));
      } else if (dialogMode === "move" && selectedNote) {
        await moveProjectNote(projectId, selectedNote.id, { parent_id: moveTargetParentId || null });
        onNotesChange(await listProjectNotes(projectId));
      }
      setDialogMode(null);
      setDialogValue("");
    } catch (submitError) {
      setError(getApiErrorMessage(submitError, "Не удалось выполнить операцию с заметкой"));
    } finally {
      setBusy(false);
    }
  };

  const saveSelectedNote = async () => {
    if (!selectedNote) {
      return;
    }
    try {
      setBusy(true);
      setError(null);
      await updateProjectNote(projectId, selectedNote.id, {
        content: draftContent.trim() || null,
      });
      onNotesChange(await listProjectNotes(projectId));
      pushToast("Заметка сохранена", "success");
    } catch (saveError) {
      setError(getApiErrorMessage(saveError, "Не удалось сохранить страницу заметки"));
    } finally {
      setBusy(false);
    }
  };

  const removeSelectedNote = async () => {
    if (!selectedNote) {
      return;
    }
    if (!window.confirm(`Удалить страницу "${selectedNote.title}" и все вложенные страницы?`)) {
      return;
    }
    try {
      setBusy(true);
      setError(null);
      await deleteProjectNote(projectId, selectedNote.id);
      onNotesChange(await listProjectNotes(projectId));
    } catch (deleteError) {
      setError(getApiErrorMessage(deleteError, "Не удалось удалить страницу заметки"));
    } finally {
      setBusy(false);
    }
  };

  const reorderWithinSiblings = async (note: ProjectNote, direction: "up" | "down") => {
    const siblings = [...(childrenByParent.get(note.parent_id ?? null) ?? [])];
    const currentIndex = siblings.findIndex((item) => item.id === note.id);
    if (currentIndex < 0) {
      return;
    }
    const nextIndex = direction === "up" ? currentIndex - 1 : currentIndex + 1;
    if (nextIndex < 0 || nextIndex >= siblings.length) {
      return;
    }
    const [moved] = siblings.splice(currentIndex, 1);
    siblings.splice(nextIndex, 0, moved);
    try {
      setBusy(true);
      setError(null);
      await reorderProjectNotes(projectId, {
        parent_id: note.parent_id,
        items: siblings.map((item, index) => ({ id: item.id, sort_order: index + 1 })),
      });
      onNotesChange(await listProjectNotes(projectId));
    } catch (reorderError) {
      setError(getApiErrorMessage(reorderError, "Не удалось изменить порядок страниц"));
    } finally {
      setBusy(false);
    }
  };

  const actionsMenuOpen = Boolean(actionsAnchorEl);

  const submitComment = async () => {
    if (!selectedNoteId || !newComment.trim()) {
      return;
    }
    try {
      await createProjectNoteComment(projectId, selectedNoteId, newComment.trim());
      setNewComment("");
      await loadComments();
    } catch (commentError) {
      setError(getApiErrorMessage(commentError, "Не удалось добавить комментарий"));
    }
  };

  const deleteComment = async (commentId: string) => {
    if (!selectedNoteId) {
      return;
    }
    try {
      await deleteProjectNoteComment(projectId, selectedNoteId, commentId);
      await loadComments();
    } catch (commentError) {
      setError(getApiErrorMessage(commentError, "Не удалось удалить комментарий"));
    }
  };

  const openCommentActionsMenu = (event: React.MouseEvent<HTMLElement>, comment: ProjectNoteComment) => {
    event.stopPropagation();
    setCommentActionsAnchorEl(event.currentTarget);
    setActiveComment(comment);
  };

  const closeCommentActionsMenu = () => {
    setCommentActionsAnchorEl(null);
    setActiveComment(null);
  };

  const openCommentEdit = (comment: ProjectNoteComment) => {
    setActiveComment(comment);
    setCommentEditDraft(comment.content);
    setCommentEditOpen(true);
  };

  const submitCommentEdit = async () => {
    if (!selectedNoteId || !activeComment) return;
    const next = commentEditDraft.trim();
    if (!next || next === activeComment.content) {
      setCommentEditOpen(false);
      return;
    }
    setCommentEditBusy(true);
    try {
      await updateProjectNoteComment(projectId, selectedNoteId, activeComment.id, next);
      await loadComments();
      setCommentEditOpen(false);
    } catch (commentError) {
      setError(getApiErrorMessage(commentError, "Не удалось обновить комментарий"));
    } finally {
      setCommentEditBusy(false);
    }
  };

  const formatCommentTimestamp = (iso: string) => new Date(iso).toLocaleString("ru-RU");

  // Подсветка одного комментария на 3 секунды (по приходу из уведомления).
  // Логика 1-в-1 с уязвимостями (HostDetailPage.mentionHighlightFade):
  //   - Стабильный ключ commentIdsKey (отсортированные id через \n) — useEffect
  //     не перезапускается при каждом setComments на тот же набор.
  //   - Активация только когда DOM-элемент комментария фактически существует,
  //     иначе откладываем до следующего рендера (когда DOM появится).
  //   - 3-секундный таймер плавно гасит зелёную рамку.
  const [mentionHighlightActive, setMentionHighlightActive] = useState(false);
  const commentIdsKey = useMemo(
    () => comments.map((c) => c.id).sort().join("\n"),
    [comments],
  );
  useEffect(() => {
    if (!highlightCommentId) {
      setMentionHighlightActive(false);
      return;
    }
    const idsSet = new Set(commentIdsKey.split("\n").filter(Boolean));
    if (!idsSet.has(highlightCommentId)) {
      setMentionHighlightActive(false);
      return;
    }
    const element = document.getElementById(`note-comment-${highlightCommentId}`);
    if (!element) {
      // DOM ещё не дорендерил элемент (например, родительский Box с
      // selectedNoteId только что монтировался) — выйдем, при следующем
      // рендере эффект сработает с уже существующим элементом.
      return;
    }
    window.setTimeout(() => element.scrollIntoView({ behavior: "smooth", block: "center" }), 0);
    setMentionHighlightActive(true);
    const timer = window.setTimeout(() => {
      setMentionHighlightActive(false);
      if (onHighlightHandled) onHighlightHandled();
    }, 3000);
    return () => window.clearTimeout(timer);
  }, [highlightCommentId, commentIdsKey, onHighlightHandled]);

  return (
    <Stack spacing={2}>
      {error && (
        <Typography color="error" variant="body2">
          {error}
        </Typography>
      )}
      <Stack spacing={2}>
          <Card sx={{ border: "1px solid rgba(126,224,255,0.14)" }}>
            <CardContent>
              {!selectedNote ? (
                <Typography color="text.secondary">Выберите страницу слева или создайте новую заметку.</Typography>
              ) : (
                <Stack spacing={1.5}>
                  {/*
                    Заголовок и троеточие убраны из карточки — название теперь
                    в шапке страницы как «Заметка: <title>», а действия
                    (Создать/Редактировать/Удалить) — в верхнем троеточии раздела.
                  */}
                  <MarkdownEditor
                    label="Контент страницы"
                    showLabel={false}
                    value={draftContent || null}
                    onChange={(next) => setDraftContent(next ?? "")}
                    onImageTooLarge={() => pushToast("Изображение слишком крупное (максимум ~1,5 МБ).", "warning")}
                    minRows={7}
                  />
                  <Stack direction="row" justifyContent="flex-end" spacing={1}>
                    <Button
                      variant="outlined"
                      onClick={() => {
                        setDraftContent(selectedNote.content ?? "");
                      }}
                    >
                      Отменить
                    </Button>
                    <Button variant="contained" disabled={busy} onClick={() => void saveSelectedNote()}>
                      Сохранить страницу
                    </Button>
                  </Stack>
                </Stack>
              )}
            </CardContent>
          </Card>

          {/*
            Блок комментариев рендерим по selectedNoteId, а не по selectedNote: на
            переходе с уведомления (например, из списка проектов) родительские
            projectNotes ещё грузятся, но комментарии уже доступны (loadComments
            не зависит от notes). Иначе блок не появляется в DOM, и 3-секундная
            подсветка истекает раньше, чем элемент рендерится.
          */}
          {selectedNoteId && (
            <Card sx={{ border: "1px solid rgba(126,224,255,0.14)" }}>
              <CardContent>
                {/*
                  Дизайн комментариев — единый с уязвимостями (см. renderCommentsSection
                  в HostDetailPage). Список с Divider'ами вместо «карточек», троеточие-меню
                  по hover, Avatar 28x28, имя жирным, таймстамп справа.
                */}
                <Stack spacing={1.25}>
                  <Typography variant="subtitle1" fontWeight={700}>
                    Комментарии ({comments.length})
                  </Typography>
                  <List dense disablePadding>
                    {comments.map((comment, commentIndex) => {
                      const canManage = user?.id === comment.user_id;
                      const isHighlighted = highlightCommentId === comment.id && mentionHighlightActive;
                      return (
                        <Box component="li" key={comment.id} sx={{ listStyle: "none" }}>
                          <ListItem
                            id={`note-comment-${comment.id}`}
                            alignItems="flex-start"
                            sx={{
                              mb: 0,
                              py: 1.25,
                              border: "1px solid transparent",
                              scrollMarginTop: 96,
                              ...(isHighlighted
                                ? {
                                    animation: "noteMentionHighlightFade 3s ease forwards",
                                    "@keyframes noteMentionHighlightFade": {
                                      "0%": {
                                        backgroundColor: "rgba(76,175,80,0.28)",
                                        borderColor: "rgba(76,175,80,0.75)",
                                      },
                                      "66%": {
                                        backgroundColor: "rgba(76,175,80,0.28)",
                                        borderColor: "rgba(76,175,80,0.75)",
                                      },
                                      "100%": {
                                        backgroundColor: "transparent",
                                        borderColor: "transparent",
                                      },
                                    },
                                  }
                                : {}),
                              ...(canManage
                                ? {
                                    "&:hover .comment-row-actions, &:focus-within .comment-row-actions": {
                                      opacity: 1,
                                      pointerEvents: "auto",
                                    },
                                  }
                                : {}),
                            }}
                          >
                            <Stack spacing={0.75} sx={{ width: "100%" }}>
                              <Stack direction="row" justifyContent="space-between" alignItems="center" spacing={2}>
                                <Stack direction="row" alignItems="center" spacing={1.25} minWidth={0}>
                                  <Avatar
                                    src={comment.avatar_url || undefined}
                                    alt={comment.username}
                                    sx={{ width: 28, height: 28, fontSize: "0.8rem", bgcolor: "rgba(126,224,255,0.18)" }}
                                  >
                                    {comment.username.slice(0, 1).toUpperCase()}
                                  </Avatar>
                                  <Typography fontWeight={700} color="text.primary" noWrap>
                                    {comment.username}
                                  </Typography>
                                </Stack>
                                <Stack direction="row" alignItems="center" spacing={0} sx={{ flexShrink: 0 }}>
                                  <Typography
                                    variant="caption"
                                    color="text.secondary"
                                    sx={{ whiteSpace: "nowrap", textAlign: "right", minWidth: "7.75rem", pr: 0.5 }}
                                  >
                                    {formatCommentTimestamp(comment.created_at)}
                                  </Typography>
                                  <Box sx={{ width: 36, display: "flex", justifyContent: "flex-end", flexShrink: 0 }}>
                                    {canManage ? (
                                      <IconButton
                                        className="comment-row-actions"
                                        size="small"
                                        onClick={(event) => openCommentActionsMenu(event, comment)}
                                        sx={{
                                          mr: -0.75,
                                          opacity: 0,
                                          pointerEvents: "none",
                                          transition: "opacity 0.15s ease",
                                          color: "rgba(148,163,184,0.85)",
                                          "&:hover": {
                                            color: "rgba(148,163,184,1)",
                                            backgroundColor: "rgba(126,224,255,0.06)",
                                          },
                                        }}
                                      >
                                        <MoreVertIcon fontSize="small" />
                                      </IconButton>
                                    ) : null}
                                  </Box>
                                </Stack>
                              </Stack>
                              <Typography variant="body2" color="rgba(235,245,255,0.92)" sx={{ whiteSpace: "pre-wrap", pr: 1 }}>
                                {comment.content}
                              </Typography>
                            </Stack>
                          </ListItem>
                        </Box>
                      );
                    })}
                    {comments.length === 0 && <Typography color="text.secondary">Комментариев пока нет.</Typography>}
                  </List>
                  <TextField
                    label="Комментарий"
                    multiline
                    minRows={3}
                    value={newComment}
                    onChange={(event) => setNewComment(event.target.value)}
                  />
                  <Stack direction="row" justifyContent="flex-end">
                    <Button variant="contained" disabled={!newComment.trim()} onClick={() => void submitComment()}>
                      Добавить комментарий
                    </Button>
                  </Stack>
                </Stack>
              </CardContent>
            </Card>
          )}
      </Stack>

      <Menu
        anchorEl={actionsAnchorEl}
        open={actionsMenuOpen}
        onClose={() => setActionsAnchorEl(null)}
        anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
        transformOrigin={{ vertical: "top", horizontal: "right" }}
      >
        <MenuItem
          onClick={() => {
            setActionsAnchorEl(null);
            openCreateRootDialog();
          }}
        >
          <AddIcon fontSize="small" sx={{ mr: 1 }} />
          Новая корневая страница
        </MenuItem>
        <MenuItem
          onClick={() => {
            setActionsAnchorEl(null);
            openCreateChildDialog();
          }}
          disabled={!selectedNote}
        >
          <AddIcon fontSize="small" sx={{ mr: 1 }} />
          Новая вложенная страница
        </MenuItem>
        <MenuItem
          onClick={() => {
            setActionsAnchorEl(null);
            openRenameDialog();
          }}
          disabled={!selectedNote}
        >
          <EditIcon fontSize="small" sx={{ mr: 1 }} />
          Переименовать
        </MenuItem>
        <MenuItem
          onClick={() => {
            setActionsAnchorEl(null);
            openMoveDialog();
          }}
          disabled={!selectedNote}
        >
          <DriveFileMoveIcon fontSize="small" sx={{ mr: 1 }} />
          Переместить
        </MenuItem>
        <MenuItem
          onClick={() => {
            setActionsAnchorEl(null);
            if (selectedNote) {
              void reorderWithinSiblings(selectedNote, "up");
            }
          }}
          disabled={!selectedNote}
        >
          <ArrowUpwardIcon fontSize="small" sx={{ mr: 1 }} />
          Вверх среди соседей
        </MenuItem>
        <MenuItem
          onClick={() => {
            setActionsAnchorEl(null);
            if (selectedNote) {
              void reorderWithinSiblings(selectedNote, "down");
            }
          }}
          disabled={!selectedNote}
        >
          <ArrowDownwardIcon fontSize="small" sx={{ mr: 1 }} />
          Вниз среди соседей
        </MenuItem>
        <MenuItem
          onClick={() => {
            setActionsAnchorEl(null);
            void removeSelectedNote();
          }}
          disabled={!selectedNote}
        >
          <DeleteOutlineIcon fontSize="small" sx={{ mr: 1 }} />
          Удалить страницу
        </MenuItem>
      </Menu>

      <Dialog open={dialogMode !== null} onClose={() => setDialogMode(null)} fullWidth maxWidth="sm">
        <DialogTitle>
          {dialogMode === "create-root" && "Новая корневая страница"}
          {dialogMode === "create-child" && "Новая вложенная страница"}
          {dialogMode === "rename" && "Переименовать страницу"}
          {dialogMode === "move" && "Переместить страницу"}
        </DialogTitle>
        <DialogContent>
          {(dialogMode === "create-root" || dialogMode === "create-child" || dialogMode === "rename") && (
            <TextField
              autoFocus
              fullWidth
              label="Название страницы"
              value={dialogValue}
              onChange={(event) => setDialogValue(event.target.value)}
              sx={{ mt: 1 }}
            />
          )}
          {dialogMode === "move" && (
            <TextField
              select
              fullWidth
              label="Новый родитель"
              value={moveTargetParentId}
              onChange={(event) => setMoveTargetParentId(event.target.value)}
              sx={{ mt: 1 }}
            >
              <MenuItem value="">Корень заметок</MenuItem>
              {notes
                .filter((item) => item.id !== selectedNoteId && !descendants.has(item.id))
                .map((item) => (
                  <MenuItem key={item.id} value={item.id}>
                    {item.title}
                  </MenuItem>
                ))}
            </TextField>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialogMode(null)}>Отмена</Button>
          <Button
            variant="contained"
            disabled={
              busy ||
              ((dialogMode === "create-root" || dialogMode === "create-child" || dialogMode === "rename") && !dialogValue.trim())
            }
            onClick={() => void submitDialog()}
          >
            Сохранить
          </Button>
        </DialogActions>
      </Dialog>

      <Menu
        anchorEl={commentActionsAnchorEl}
        open={Boolean(commentActionsAnchorEl)}
        onClose={closeCommentActionsMenu}
        anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
        transformOrigin={{ vertical: "top", horizontal: "right" }}
      >
        <MenuItem
          onClick={() => {
            if (activeComment) openCommentEdit(activeComment);
            closeCommentActionsMenu();
          }}
        >
          <EditIcon fontSize="small" sx={{ mr: 1 }} />
          Редактировать
        </MenuItem>
        <MenuItem
          onClick={() => {
            if (activeComment) void deleteComment(activeComment.id);
            closeCommentActionsMenu();
          }}
        >
          <DeleteOutlineIcon fontSize="small" sx={{ mr: 1 }} />
          Удалить
        </MenuItem>
      </Menu>

      <Dialog
        open={commentEditOpen}
        onClose={() => {
          if (commentEditBusy) return;
          setCommentEditOpen(false);
        }}
        fullWidth
        maxWidth="sm"
      >
        <DialogTitle>Редактировать комментарий</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            fullWidth
            multiline
            minRows={3}
            label="Комментарий"
            value={commentEditDraft}
            onChange={(event) => setCommentEditDraft(event.target.value)}
            sx={{ mt: 1 }}
            disabled={commentEditBusy}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCommentEditOpen(false)} disabled={commentEditBusy}>
            Отмена
          </Button>
          <Button
            variant="contained"
            disabled={commentEditBusy || !commentEditDraft.trim()}
            onClick={() => void submitCommentEdit()}
          >
            Сохранить
          </Button>
        </DialogActions>
      </Dialog>
    </Stack>
  );
}
