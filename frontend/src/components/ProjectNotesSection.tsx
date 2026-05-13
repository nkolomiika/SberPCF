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
  Menu,
  MenuItem,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { useCallback, useEffect, useMemo, useState } from "react";
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
  selectedNoteId,
  onSelectNote,
  onNotesChange,
}: {
  projectId: string;
  selectedNoteId: string | null;
  onSelectNote: (noteId: string | null) => void;
  onNotesChange: (notes: ProjectNote[]) => void;
}) {
  const user = useAuthStore((state) => state.user);
  const pushToast = useToastStore((state) => state.pushToast);
  const [notes, setNotes] = useState<ProjectNote[]>([]);
  const [draftContent, setDraftContent] = useState("");
  const [busy, setBusy] = useState(false);
  const [dialogMode, setDialogMode] = useState<DialogMode>(null);
  const [dialogValue, setDialogValue] = useState("");
  const [moveTargetParentId, setMoveTargetParentId] = useState<string>("");
  const [actionsAnchorEl, setActionsAnchorEl] = useState<HTMLElement | null>(null);
  const [comments, setComments] = useState<ProjectNoteComment[]>([]);
  const [newComment, setNewComment] = useState("");
  const [error, setError] = useState<string | null>(null);

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

  const loadNotes = useCallback(async () => {
    try {
      const items = await listProjectNotes(projectId);
      let finalItems = items;
      if (items.length === 0) {
        const createdRoot = await createProjectNote(projectId, { title: "Главная страница", parent_id: null, content: null });
        finalItems = [createdRoot];
      }
      setNotes(finalItems);
      onNotesChange(finalItems);
      if (selectedNoteId && finalItems.some((item) => item.id === selectedNoteId)) {
        return;
      }
      onSelectNote(finalItems[0]?.id ?? null);
    } catch (loadError) {
      setError(getApiErrorMessage(loadError, "Не удалось загрузить заметки"));
    }
  }, [onNotesChange, onSelectNote, projectId, selectedNoteId]);

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
    void loadNotes();
  }, [loadNotes]);

  useEffect(() => {
    void loadComments();
  }, [loadComments]);

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
        await loadNotes();
        onSelectNote(created.id);
      } else if (dialogMode === "create-child" && selectedNote) {
        const created = await createProjectNote(projectId, { title: dialogValue.trim(), parent_id: selectedNote.id, content: null });
        await loadNotes();
        onSelectNote(created.id);
      } else if (dialogMode === "rename" && selectedNote) {
        await updateProjectNote(projectId, selectedNote.id, { title: dialogValue.trim() });
        await loadNotes();
      } else if (dialogMode === "move" && selectedNote) {
        await moveProjectNote(projectId, selectedNote.id, { parent_id: moveTargetParentId || null });
        await loadNotes();
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
      await loadNotes();
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
      await loadNotes();
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
      await loadNotes();
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

  const editComment = async (comment: ProjectNoteComment) => {
    if (!selectedNoteId) {
      return;
    }
    const nextContent = window.prompt("Изменить комментарий", comment.content);
    if (!nextContent || !nextContent.trim()) {
      return;
    }
    try {
      await updateProjectNoteComment(projectId, selectedNoteId, comment.id, nextContent.trim());
      await loadComments();
    } catch (commentError) {
      setError(getApiErrorMessage(commentError, "Не удалось обновить комментарий"));
    }
  };

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
                  <Stack direction="row" justifyContent="space-between" alignItems="center">
                    <Typography variant="h6" fontWeight={700}>
                      {selectedNote.title}
                    </Typography>
                    <IconButton size="small" onClick={(event) => setActionsAnchorEl(event.currentTarget)}>
                      <MoreVertIcon fontSize="small" />
                    </IconButton>
                  </Stack>
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

          {selectedNote && (
            <Card sx={{ border: "1px solid rgba(126,224,255,0.14)" }}>
              <CardContent>
                <Stack spacing={1.2}>
                  <Typography variant="h6" fontWeight={700}>
                    Комментарии ({comments.length})
                  </Typography>
                  {comments.map((comment) => {
                    const canManage = user?.id === comment.user_id;
                    return (
                      <Box key={comment.id} sx={{ border: "1px solid rgba(126,224,255,0.12)", p: 1.2, backgroundColor: "rgba(8,17,31,0.24)" }}>
                        <Stack direction="row" justifyContent="space-between" spacing={1}>
                          <Stack direction="row" spacing={1} alignItems="center">
                            <Avatar src={comment.avatar_url || undefined} sx={{ width: 26, height: 26 }}>
                              {comment.username.slice(0, 1).toUpperCase()}
                            </Avatar>
                            <Typography fontWeight={700}>{comment.username}</Typography>
                            <Typography variant="caption" color="text.secondary">
                              {new Date(comment.created_at).toLocaleString("ru-RU")}
                            </Typography>
                          </Stack>
                          {canManage && (
                            <Stack direction="row">
                              <IconButton size="small" onClick={() => void editComment(comment)}>
                                <EditIcon fontSize="small" />
                              </IconButton>
                              <IconButton size="small" onClick={() => void deleteComment(comment.id)}>
                                <DeleteOutlineIcon fontSize="small" />
                              </IconButton>
                            </Stack>
                          )}
                        </Stack>
                        <Typography variant="body2" sx={{ mt: 1, whiteSpace: "pre-wrap" }}>
                          {comment.content}
                        </Typography>
                      </Box>
                    );
                  })}
                  {comments.length === 0 && <Typography color="text.secondary">Комментариев пока нет.</Typography>}
                  <TextField
                    label="Новый комментарий"
                    multiline
                    minRows={3}
                    value={newComment}
                    onChange={(event) => setNewComment(event.target.value)}
                    sx={{ "& .MuiInputBase-input": { color: "#ffffff" } }}
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
    </Stack>
  );
}
