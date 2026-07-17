import DeleteIcon from "@mui/icons-material/Delete";
import DeleteOutlineIcon from "@mui/icons-material/DeleteOutline";
import EditIcon from "@mui/icons-material/Edit";
import KeyIcon from "@mui/icons-material/Key";
import MoreVertIcon from "@mui/icons-material/MoreVert";
import PersonAddAlt1Icon from "@mui/icons-material/PersonAddAlt1";
import {
  Avatar,
  Box,
  Button,
  Card,
  CardContent,
  Checkbox,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  IconButton,
  Menu,
  MenuItem,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import { useCallback, useEffect, useMemo, useState, type MouseEvent } from "react";
import { createUser, deleteUser, getApiErrorMessage, getUsers, resetUserPassword, updateUser } from "../api";
import type { User, UserRole } from "../types";
import { useErrorToast, useToastMessage } from "../useErrorToast";

const ROLE_OPTIONS: Array<{ value: UserRole; label: string }> = [
  { value: "admin", label: "Администратор" },
  { value: "pentester", label: "Пентестер" },
];

function roleLabel(role: UserRole): string {
  return ROLE_OPTIONS.find((option) => option.value === role)?.label ?? role;
}

export function UsersAdminPage() {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [infoMessage, setInfoMessage] = useState<string | null>(null);
  const [pageActionsAnchorEl, setPageActionsAnchorEl] = useState<HTMLElement | null>(null);
  const [userActionsAnchorEl, setUserActionsAnchorEl] = useState<HTMLElement | null>(null);

  const [isCreateOpen, setCreateOpen] = useState(false);
  const [isEditOpen, setEditOpen] = useState(false);
  const [isResetOpen, setResetOpen] = useState(false);
  const [activeUser, setActiveUser] = useState<User | null>(null);

  const [createUsername, setCreateUsername] = useState("");
  const [createEmail, setCreateEmail] = useState("");
  const [createFullName, setCreateFullName] = useState("");
  const [createPassword, setCreatePassword] = useState("");
  const [createRole, setCreateRole] = useState<UserRole>("pentester");
  const [createSendInviteEmail, setCreateSendInviteEmail] = useState(true);

  const [editUsername, setEditUsername] = useState("");
  const [editFullName, setEditFullName] = useState("");
  const [editRole, setEditRole] = useState<UserRole>("pentester");
  const [editIsActive, setEditIsActive] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [userBulkDeleteMode, setUserBulkDeleteMode] = useState(false);
  const [selectedUserIds, setSelectedUserIds] = useState<Set<number>>(() => new Set());
  const [bulkDeletingUsers, setBulkDeletingUsers] = useState(false);

  useErrorToast(error);
  useToastMessage(infoMessage, "success");

  const loadUsers = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const pageSize = 200;
      let page = 1;
      let pages = 1;
      const nextUsers: User[] = [];
      do {
        const response = await getUsers(page, pageSize);
        nextUsers.push(...response.items);
        pages = response.pages;
        page += 1;
      } while (page <= pages);
      setUsers(nextUsers);
    } catch (loadError) {
      setError(getApiErrorMessage(loadError, "Не удалось загрузить пользователей."));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadUsers();
  }, [loadUsers]);

  const activeUsers = useMemo(() => users.filter((user) => user.is_active).length, [users]);
  const filteredUsers = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    if (!query) {
      return users;
    }
    return users.filter((user) =>
      [user.username, user.full_name || "", user.email, roleLabel(user.role)].some((value) => value.toLowerCase().includes(query))
    );
  }, [searchQuery, users]);

  const closeCreateDialog = () => {
    setCreateOpen(false);
    setCreateUsername("");
    setCreateEmail("");
    setCreateFullName("");
    setCreatePassword("");
    setCreateRole("pentester");
    setCreateSendInviteEmail(true);
  };

  const closeEditDialog = () => {
    setEditOpen(false);
    setActiveUser(null);
  };

  const closeResetDialog = () => {
    setResetOpen(false);
    setActiveUser(null);
  };

  const closePageActions = () => setPageActionsAnchorEl(null);
  const closeUserActions = () => setUserActionsAnchorEl(null);

  const openEditDialog = (user: User) => {
    setActiveUser(user);
    setEditUsername(user.username);
    setEditFullName(user.full_name ?? "");
    setEditRole(user.role);
    setEditIsActive(user.is_active);
    setEditOpen(true);
  };

  const openResetDialog = (user: User) => {
    setActiveUser(user);
    setResetOpen(true);
  };

  const handleCreateUser = async () => {
    try {
      await createUser({
        username: createUsername.trim(),
        email: createEmail.trim(),
        full_name: createFullName.trim() || undefined,
        password: createPassword || undefined,
        role: createRole,
        send_invite_email: createSendInviteEmail,
      });
      setInfoMessage(createSendInviteEmail ? "Пользователь создан, письмо с временным паролем отправлено." : "Пользователь создан.");
      closeCreateDialog();
      await loadUsers();
    } catch (submitError) {
      setError(getApiErrorMessage(submitError, "Не удалось создать пользователя."));
    }
  };

  const handleUpdateUser = async () => {
    if (!activeUser) {
      return;
    }
    try {
      await updateUser(activeUser.id, {
        username: editUsername.trim(),
        full_name: editFullName.trim() || undefined,
        role: editRole,
        is_active: editIsActive,
      });
      setInfoMessage("Пользователь обновлён.");
      closeEditDialog();
      await loadUsers();
    } catch (submitError) {
      setError(getApiErrorMessage(submitError, "Не удалось обновить пользователя."));
    }
  };

  const handleResetPassword = async () => {
    if (!activeUser) {
      return;
    }
    try {
      const result = await resetUserPassword(activeUser.id);
      setInfoMessage(
        result.mail_preview_url
          ? `Временный пароль для ${activeUser.username} отправлен в локальный почтовый inbox: ${result.mail_preview_url}. Адрес получателя: ${result.email_sent_to}.`
          : `Временный пароль для ${activeUser.username} отправлен на ${result.email_sent_to}.`
      );
      closeResetDialog();
      await loadUsers();
    } catch (submitError) {
      setError(getApiErrorMessage(submitError, "Не удалось сбросить пароль."));
    }
  };

  const handleDeleteUser = async (user: User) => {
    if (!window.confirm(`Удалить пользователя ${user.username}?`)) {
      return;
    }
    try {
      await deleteUser(user.id);
      setInfoMessage("Пользователь удалён.");
      await loadUsers();
    } catch (deleteError) {
      setError(getApiErrorMessage(deleteError, "Не удалось удалить пользователя."));
    }
  };

  const toggleUserSelection = (id: number) => {
    setSelectedUserIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const cancelUserBulkDelete = () => {
    setUserBulkDeleteMode(false);
    setSelectedUserIds(new Set());
  };

  const handleBulkDeleteUsers = async () => {
    if (selectedUserIds.size === 0) {
      return;
    }
    if (!window.confirm(`Удалить выбранных пользователей (${selectedUserIds.size})?`)) {
      return;
    }
    setBulkDeletingUsers(true);
    setError(null);
    const failures: string[] = [];
    try {
      for (const userId of Array.from(selectedUserIds)) {
        try {
          await deleteUser(userId);
        } catch (deleteError) {
          failures.push(getApiErrorMessage(deleteError, "Не удалось удалить пользователя."));
        }
      }
      setSelectedUserIds(new Set());
      setUserBulkDeleteMode(false);
      await loadUsers();
      if (failures.length) {
        setError(failures.join("\n"));
      } else {
        setInfoMessage("Выбранные пользователи удалены.");
      }
    } finally {
      setBulkDeletingUsers(false);
    }
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" py={6}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Stack spacing={2.5}>
      <Stack direction={{ xs: "column", sm: "row" }} justifyContent="space-between" alignItems={{ sm: "center" }} gap={1.5}>
        <Stack spacing={0.3}>
          <Typography variant="h4" fontWeight={700}>
            Пользователи
          </Typography>
          <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
            <Chip label={`Всего: ${users.length}`} variant="outlined" />
            <Chip label={`Активных: ${activeUsers}`} variant="outlined" />
            <Chip label={`Показано: ${filteredUsers.length}`} variant="outlined" />
          </Stack>
        </Stack>
        <Stack direction="row" spacing={1} alignItems="center">
          {userBulkDeleteMode ? (
            <>
              <Button
                size="small"
                color="error"
                variant="outlined"
                startIcon={<DeleteIcon fontSize="small" />}
                disabled={bulkDeletingUsers || selectedUserIds.size === 0}
                onClick={() => void handleBulkDeleteUsers()}
              >
                Удалить ({selectedUserIds.size})
              </Button>
              <Button size="small" variant="outlined" onClick={cancelUserBulkDelete} disabled={bulkDeletingUsers}>
                Отменить
              </Button>
            </>
          ) : null}
          <Tooltip title="Действия">
            <IconButton onClick={(event) => setPageActionsAnchorEl(event.currentTarget)} sx={{ border: "1px solid rgba(126,224,255,0.18)" }}>
              <MoreVertIcon />
            </IconButton>
          </Tooltip>
        </Stack>
      </Stack>

      <Menu
        anchorEl={pageActionsAnchorEl}
        open={Boolean(pageActionsAnchorEl)}
        onClose={closePageActions}
        anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
        transformOrigin={{ vertical: "top", horizontal: "right" }}
      >
        <MenuItem
          onClick={() => {
            closePageActions();
            setCreateOpen(true);
          }}
        >
          <PersonAddAlt1Icon fontSize="small" sx={{ mr: 1 }} />
          Создать пользователя
        </MenuItem>
        <MenuItem
          disabled={!users.length}
          onClick={() => {
            closePageActions();
            setSelectedUserIds(new Set());
            setUserBulkDeleteMode(true);
          }}
        >
          <DeleteOutlineIcon fontSize="small" sx={{ mr: 1 }} />
          Выбрать пользователей для удаления
        </MenuItem>
      </Menu>

      <TextField
        placeholder="Поиск по имени, логину, email, роли или тегу"
        value={searchQuery}
        onChange={(event) => setSearchQuery(event.target.value)}
        fullWidth
      />

      <Stack spacing={0.75}>
        {filteredUsers.map((user) => (
          <Card
            key={user.id}
            sx={{
              border: "1px solid rgba(126,224,255,0.14)",
              backgroundColor: "rgba(15,27,45,0.72)",
              "& .user-actions-trigger": {
                opacity: 0,
                pointerEvents: "none",
                transition: "opacity 0.18s ease",
              },
              "&:hover .user-actions-trigger": {
                opacity: 1,
                pointerEvents: "auto",
              },
            }}
          >
            <CardContent sx={{ p: 1.25, "&:last-child": { pb: 1.25 } }}>
              <Stack direction="row" spacing={1.25} alignItems="center">
                {userBulkDeleteMode ? (
                  <Checkbox
                    size="small"
                    checked={selectedUserIds.has(user.id)}
                    onChange={() => toggleUserSelection(user.id)}
                    sx={{ p: 0.25 }}
                  />
                ) : null}
                <Tooltip title={`Создан: ${new Date(user.created_at).toLocaleString()} · ${user.email}`}>
                  <Avatar src={user.avatar_url ?? undefined} sx={{ width: 36, height: 36, fontSize: 15 }}>
                    {(user.full_name || user.username)[0]?.toUpperCase()}
                  </Avatar>
                </Tooltip>
                <Stack direction="row" spacing={1} alignItems="center" sx={{ minWidth: 0, flex: 1, flexWrap: "wrap", rowGap: 0.5 }}>
                  <Typography variant="body2" fontWeight={600} noWrap>
                    {user.full_name || user.username}
                  </Typography>
                  <Typography variant="caption" color="text.secondary" noWrap>
                    @{user.username}
                  </Typography>
                  <Chip size="small" label={roleLabel(user.role)} sx={{ height: 20 }} />
                  <Chip
                    size="small"
                    label={user.is_active ? "Активен" : "Отключен"}
                    color={user.is_active ? "success" : "default"}
                    variant={user.is_active ? "filled" : "outlined"}
                    sx={{ height: 20 }}
                  />
                </Stack>
                {userBulkDeleteMode ? null : (
                  <IconButton
                    className="user-actions-trigger"
                    size="small"
                    onClick={(event: MouseEvent<HTMLElement>) => {
                      setActiveUser(user);
                      setUserActionsAnchorEl(event.currentTarget);
                    }}
                  >
                    <MoreVertIcon fontSize="small" />
                  </IconButton>
                )}
              </Stack>
            </CardContent>
          </Card>
        ))}
        {filteredUsers.length === 0 && <Typography color="text.secondary">Пользователи не найдены.</Typography>}
      </Stack>

      <Menu
        anchorEl={userActionsAnchorEl}
        open={Boolean(userActionsAnchorEl)}
        onClose={closeUserActions}
        anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
        transformOrigin={{ vertical: "top", horizontal: "right" }}
      >
        <MenuItem
          onClick={() => {
            if (activeUser) {
              openEditDialog(activeUser);
            }
            closeUserActions();
          }}
        >
          <EditIcon fontSize="small" sx={{ mr: 1 }} />
          Редактировать
        </MenuItem>
        <MenuItem
          onClick={() => {
            if (activeUser) {
              openResetDialog(activeUser);
            }
            closeUserActions();
          }}
        >
          <KeyIcon fontSize="small" sx={{ mr: 1 }} />
          Сбросить пароль
        </MenuItem>
        <MenuItem
          onClick={() => {
            if (activeUser) {
              void handleDeleteUser(activeUser);
            }
            closeUserActions();
          }}
        >
          <DeleteIcon fontSize="small" sx={{ mr: 1 }} />
          Удалить
        </MenuItem>
      </Menu>

      <Dialog open={isCreateOpen} onClose={closeCreateDialog} fullWidth maxWidth="sm">
        <DialogTitle>Создать пользователя</DialogTitle>
        <DialogContent sx={{ display: "grid", gap: 2, pt: 2 }}>
          <TextField label="Логин" value={createUsername} onChange={(event) => setCreateUsername(event.target.value)} fullWidth />
          <TextField label="Email" value={createEmail} onChange={(event) => setCreateEmail(event.target.value)} fullWidth />
          <TextField label="Имя" value={createFullName} onChange={(event) => setCreateFullName(event.target.value)} fullWidth />
          <TextField
            label="Пароль"
            type="password"
            value={createPassword}
            onChange={(event) => setCreatePassword(event.target.value)}
            helperText={createSendInviteEmail ? "Можно оставить пустым: система сгенерирует временный пароль." : "Минимум 8 символов."}
            fullWidth
          />
          <FormControlLabel
            control={<Checkbox checked={createSendInviteEmail} onChange={(event) => setCreateSendInviteEmail(event.target.checked)} />}
            label="Отправить приглашение и временный пароль на email"
          />
          <TextField select label="Роль" value={createRole} onChange={(event) => setCreateRole(event.target.value as UserRole)} fullWidth>
            {ROLE_OPTIONS.map((option) => (
              <MenuItem key={option.value} value={option.value}>
                {option.label}
              </MenuItem>
            ))}
          </TextField>
        </DialogContent>
        <DialogActions>
          <Button onClick={closeCreateDialog}>Отмена</Button>
          <Button
            variant="contained"
            onClick={() => void handleCreateUser()}
            disabled={!createUsername.trim() || !createEmail.trim() || (!createSendInviteEmail && createPassword.length < 8)}
          >
            Создать
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={isEditOpen} onClose={closeEditDialog} fullWidth maxWidth="sm">
        <DialogTitle>Редактировать пользователя</DialogTitle>
        <DialogContent sx={{ display: "grid", gap: 2, pt: 2 }}>
          <TextField label="Логин" value={editUsername} onChange={(event) => setEditUsername(event.target.value)} fullWidth />
          <TextField label="Email" value={activeUser?.email ?? ""} fullWidth disabled helperText="Email может изменить только сам пользователь в профиле." />
          <TextField label="Имя" value={editFullName} onChange={(event) => setEditFullName(event.target.value)} fullWidth />
          <TextField select label="Роль" value={editRole} onChange={(event) => setEditRole(event.target.value as UserRole)} fullWidth>
            {ROLE_OPTIONS.map((option) => (
              <MenuItem key={option.value} value={option.value}>
                {option.label}
              </MenuItem>
            ))}
          </TextField>
          <TextField
            select
            label="Статус"
            value={editIsActive ? "active" : "disabled"}
            onChange={(event) => setEditIsActive(event.target.value === "active")}
            fullWidth
          >
            <MenuItem value="active">Активен</MenuItem>
            <MenuItem value="disabled">Отключен</MenuItem>
          </TextField>
        </DialogContent>
        <DialogActions>
          <Button onClick={closeEditDialog}>Отмена</Button>
          <Button variant="contained" onClick={() => void handleUpdateUser()} disabled={!editUsername.trim()}>
            Сохранить
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={isResetOpen} onClose={closeResetDialog} fullWidth maxWidth="sm">
        <DialogTitle>Сбросить пароль</DialogTitle>
        <DialogContent sx={{ display: "grid", gap: 2, pt: 2 }}>
          <Typography color="text.secondary">
            {activeUser
              ? `Система сгенерирует временный пароль для ${activeUser.username} и отправит его на ${activeUser.email}. При первом входе пользователь должен будет сменить пароль.`
              : "Система отправит временный пароль на email пользователя."}
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={closeResetDialog}>Отмена</Button>
          <Button variant="contained" onClick={() => void handleResetPassword()} disabled={!activeUser}>
            Сбросить пароль
          </Button>
        </DialogActions>
      </Dialog>
    </Stack>
  );
}
