import AddIcon from "@mui/icons-material/Add";
import DeleteIcon from "@mui/icons-material/Delete";
import EditIcon from "@mui/icons-material/Edit";
import KeyIcon from "@mui/icons-material/Key";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  IconButton,
  MenuItem,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { useCallback, useEffect, useMemo, useState } from "react";
import { createUser, deleteUser, getUsers, resetUserPassword, updateUser } from "../api";
import type { User, UserRole } from "../types";

const ROLE_OPTIONS: Array<{ value: UserRole; label: string }> = [
  { value: "admin", label: "Администратор" },
  { value: "pentester", label: "Пентестер" },
  { value: "developer", label: "Разработчик" },
];

function roleLabel(role: UserRole): string {
  return ROLE_OPTIONS.find((option) => option.value === role)?.label ?? role;
}

export function UsersAdminPage() {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [infoMessage, setInfoMessage] = useState<string | null>(null);

  const [isCreateOpen, setCreateOpen] = useState(false);
  const [isEditOpen, setEditOpen] = useState(false);
  const [isResetOpen, setResetOpen] = useState(false);
  const [activeUser, setActiveUser] = useState<User | null>(null);

  const [createUsername, setCreateUsername] = useState("");
  const [createEmail, setCreateEmail] = useState("");
  const [createPassword, setCreatePassword] = useState("");
  const [createRole, setCreateRole] = useState<UserRole>("pentester");

  const [editUsername, setEditUsername] = useState("");
  const [editEmail, setEditEmail] = useState("");
  const [editRole, setEditRole] = useState<UserRole>("pentester");
  const [editIsActive, setEditIsActive] = useState(true);

  const [resetPasswordValue, setResetPasswordValue] = useState("");

  const loadUsers = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await getUsers(1, 200);
      setUsers(response.items);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Не удалось загрузить пользователей.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadUsers();
  }, [loadUsers]);

  const activeUsers = useMemo(() => users.filter((user) => user.is_active).length, [users]);

  const closeCreateDialog = () => {
    setCreateOpen(false);
    setCreateUsername("");
    setCreateEmail("");
    setCreatePassword("");
    setCreateRole("pentester");
  };

  const closeEditDialog = () => {
    setEditOpen(false);
    setActiveUser(null);
  };

  const closeResetDialog = () => {
    setResetOpen(false);
    setActiveUser(null);
    setResetPasswordValue("");
  };

  const openEditDialog = (user: User) => {
    setActiveUser(user);
    setEditUsername(user.username);
    setEditEmail(user.email);
    setEditRole(user.role);
    setEditIsActive(user.is_active);
    setEditOpen(true);
  };

  const openResetDialog = (user: User) => {
    setActiveUser(user);
    setResetPasswordValue("");
    setResetOpen(true);
  };

  const handleCreateUser = async () => {
    try {
      await createUser({
        username: createUsername.trim(),
        email: createEmail.trim(),
        password: createPassword,
        role: createRole,
      });
      setInfoMessage("Пользователь создан.");
      closeCreateDialog();
      await loadUsers();
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : "Не удалось создать пользователя.");
    }
  };

  const handleUpdateUser = async () => {
    if (!activeUser) {
      return;
    }
    try {
      await updateUser(activeUser.id, {
        username: editUsername.trim(),
        email: editEmail.trim(),
        role: editRole,
        is_active: editIsActive,
      });
      setInfoMessage("Пользователь обновлён.");
      closeEditDialog();
      await loadUsers();
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : "Не удалось обновить пользователя.");
    }
  };

  const handleResetPassword = async () => {
    if (!activeUser) {
      return;
    }
    try {
      await resetUserPassword(activeUser.id, resetPasswordValue);
      setInfoMessage(`Пароль пользователя ${activeUser.username} сброшен.`);
      closeResetDialog();
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : "Не удалось сбросить пароль.");
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
      setError(deleteError instanceof Error ? deleteError.message : "Не удалось удалить пользователя.");
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
      {error && <Alert severity="error">{error}</Alert>}
      {infoMessage && <Alert severity="success">{infoMessage}</Alert>}

      <Stack direction={{ xs: "column", sm: "row" }} justifyContent="space-between" alignItems={{ sm: "center" }} gap={1.5}>
        <Stack spacing={0.3}>
          <Typography variant="h4" fontWeight={700}>
            Пользователи
          </Typography>
          <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
            <Chip label={`Всего: ${users.length}`} variant="outlined" />
            <Chip label={`Активных: ${activeUsers}`} variant="outlined" />
          </Stack>
        </Stack>
        <Button variant="contained" startIcon={<AddIcon />} onClick={() => setCreateOpen(true)}>
          Создать пользователя
        </Button>
      </Stack>

      <Stack spacing={1.5}>
        {users.map((user) => (
          <Card key={user.id} sx={{ border: "1px solid rgba(126,224,255,0.14)", backgroundColor: "rgba(15,27,45,0.72)" }}>
            <CardContent sx={{ p: 2 }}>
              <Stack direction={{ xs: "column", md: "row" }} justifyContent="space-between" gap={1.5}>
                <Stack spacing={0.8}>
                  <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                    <Typography variant="h6">{user.username}</Typography>
                    <Chip size="small" label={roleLabel(user.role)} />
                    <Chip
                      size="small"
                      label={user.is_active ? "Активен" : "Отключен"}
                      color={user.is_active ? "success" : "default"}
                      variant={user.is_active ? "filled" : "outlined"}
                    />
                  </Stack>
                  <Typography color="text.secondary">{user.email}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Создан: {new Date(user.created_at).toLocaleString()}
                  </Typography>
                </Stack>
                <Stack direction="row" spacing={0.5} alignItems="flex-start">
                  <IconButton size="small" onClick={() => openEditDialog(user)}>
                    <EditIcon fontSize="small" />
                  </IconButton>
                  <IconButton size="small" onClick={() => openResetDialog(user)}>
                    <KeyIcon fontSize="small" />
                  </IconButton>
                  <IconButton size="small" onClick={() => void handleDeleteUser(user)}>
                    <DeleteIcon fontSize="small" />
                  </IconButton>
                </Stack>
              </Stack>
            </CardContent>
          </Card>
        ))}
      </Stack>

      <Dialog open={isCreateOpen} onClose={closeCreateDialog} fullWidth maxWidth="sm">
        <DialogTitle>Создать пользователя</DialogTitle>
        <DialogContent sx={{ display: "grid", gap: 2, pt: 2 }}>
          <TextField label="Логин" value={createUsername} onChange={(event) => setCreateUsername(event.target.value)} fullWidth />
          <TextField label="Email" value={createEmail} onChange={(event) => setCreateEmail(event.target.value)} fullWidth />
          <TextField
            label="Пароль"
            type="password"
            value={createPassword}
            onChange={(event) => setCreatePassword(event.target.value)}
            fullWidth
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
            disabled={!createUsername.trim() || !createEmail.trim() || createPassword.length < 8}
          >
            Создать
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={isEditOpen} onClose={closeEditDialog} fullWidth maxWidth="sm">
        <DialogTitle>Редактировать пользователя</DialogTitle>
        <DialogContent sx={{ display: "grid", gap: 2, pt: 2 }}>
          <TextField label="Логин" value={editUsername} onChange={(event) => setEditUsername(event.target.value)} fullWidth />
          <TextField label="Email" value={editEmail} onChange={(event) => setEditEmail(event.target.value)} fullWidth />
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
          <Button variant="contained" onClick={() => void handleUpdateUser()} disabled={!editUsername.trim() || !editEmail.trim()}>
            Сохранить
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={isResetOpen} onClose={closeResetDialog} fullWidth maxWidth="sm">
        <DialogTitle>Сбросить пароль</DialogTitle>
        <DialogContent sx={{ display: "grid", gap: 2, pt: 2 }}>
          <Typography color="text.secondary">
            {activeUser ? `Новый пароль для ${activeUser.username}` : "Новый пароль"}
          </Typography>
          <TextField
            label="Новый пароль"
            type="password"
            value={resetPasswordValue}
            onChange={(event) => setResetPasswordValue(event.target.value)}
            fullWidth
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={closeResetDialog}>Отмена</Button>
          <Button variant="contained" onClick={() => void handleResetPassword()} disabled={resetPasswordValue.length < 8}>
            Сбросить пароль
          </Button>
        </DialogActions>
      </Dialog>
    </Stack>
  );
}
