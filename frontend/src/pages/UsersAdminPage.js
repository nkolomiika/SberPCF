import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import AddIcon from "@mui/icons-material/Add";
import DeleteIcon from "@mui/icons-material/Delete";
import EditIcon from "@mui/icons-material/Edit";
import KeyIcon from "@mui/icons-material/Key";
import { Alert, Box, Button, Card, CardContent, Chip, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, IconButton, MenuItem, Stack, TextField, Typography, } from "@mui/material";
import { useCallback, useEffect, useMemo, useState } from "react";
import { createUser, deleteUser, getUsers, resetUserPassword, updateUser } from "../api";
const ROLE_OPTIONS = [
    { value: "admin", label: "Администратор" },
    { value: "pentester", label: "Пентестер" },
    { value: "developer", label: "Разработчик" },
];
function roleLabel(role) {
    return ROLE_OPTIONS.find((option) => option.value === role)?.label ?? role;
}
export function UsersAdminPage() {
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [infoMessage, setInfoMessage] = useState(null);
    const [isCreateOpen, setCreateOpen] = useState(false);
    const [isEditOpen, setEditOpen] = useState(false);
    const [isResetOpen, setResetOpen] = useState(false);
    const [activeUser, setActiveUser] = useState(null);
    const [createUsername, setCreateUsername] = useState("");
    const [createEmail, setCreateEmail] = useState("");
    const [createPassword, setCreatePassword] = useState("");
    const [createRole, setCreateRole] = useState("pentester");
    const [editUsername, setEditUsername] = useState("");
    const [editEmail, setEditEmail] = useState("");
    const [editRole, setEditRole] = useState("pentester");
    const [editIsActive, setEditIsActive] = useState(true);
    const [resetPasswordValue, setResetPasswordValue] = useState("");
    const loadUsers = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            const response = await getUsers(1, 200);
            setUsers(response.items);
        }
        catch (loadError) {
            setError(loadError instanceof Error ? loadError.message : "Не удалось загрузить пользователей.");
        }
        finally {
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
    const openEditDialog = (user) => {
        setActiveUser(user);
        setEditUsername(user.username);
        setEditEmail(user.email);
        setEditRole(user.role);
        setEditIsActive(user.is_active);
        setEditOpen(true);
    };
    const openResetDialog = (user) => {
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
        }
        catch (submitError) {
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
        }
        catch (submitError) {
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
        }
        catch (submitError) {
            setError(submitError instanceof Error ? submitError.message : "Не удалось сбросить пароль.");
        }
    };
    const handleDeleteUser = async (user) => {
        if (!window.confirm(`Удалить пользователя ${user.username}?`)) {
            return;
        }
        try {
            await deleteUser(user.id);
            setInfoMessage("Пользователь удалён.");
            await loadUsers();
        }
        catch (deleteError) {
            setError(deleteError instanceof Error ? deleteError.message : "Не удалось удалить пользователя.");
        }
    };
    if (loading) {
        return (_jsx(Box, { display: "flex", justifyContent: "center", py: 6, children: _jsx(CircularProgress, {}) }));
    }
    return (_jsxs(Stack, { spacing: 2.5, children: [error && _jsx(Alert, { severity: "error", children: error }), infoMessage && _jsx(Alert, { severity: "success", children: infoMessage }), _jsxs(Stack, { direction: { xs: "column", sm: "row" }, justifyContent: "space-between", alignItems: { sm: "center" }, gap: 1.5, children: [_jsxs(Stack, { spacing: 0.3, children: [_jsx(Typography, { variant: "h4", fontWeight: 700, children: "\u041F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u0438" }), _jsxs(Stack, { direction: "row", spacing: 1, flexWrap: "wrap", useFlexGap: true, children: [_jsx(Chip, { label: `Всего: ${users.length}`, variant: "outlined" }), _jsx(Chip, { label: `Активных: ${activeUsers}`, variant: "outlined" })] })] }), _jsx(Button, { variant: "contained", startIcon: _jsx(AddIcon, {}), onClick: () => setCreateOpen(true), children: "\u0421\u043E\u0437\u0434\u0430\u0442\u044C \u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u044F" })] }), _jsx(Stack, { spacing: 1.5, children: users.map((user) => (_jsx(Card, { sx: { border: "1px solid rgba(126,224,255,0.14)", backgroundColor: "rgba(15,27,45,0.72)" }, children: _jsx(CardContent, { sx: { p: 2 }, children: _jsxs(Stack, { direction: { xs: "column", md: "row" }, justifyContent: "space-between", gap: 1.5, children: [_jsxs(Stack, { spacing: 0.8, children: [_jsxs(Stack, { direction: "row", spacing: 1, alignItems: "center", flexWrap: "wrap", useFlexGap: true, children: [_jsx(Typography, { variant: "h6", children: user.username }), _jsx(Chip, { size: "small", label: roleLabel(user.role) }), _jsx(Chip, { size: "small", label: user.is_active ? "Активен" : "Отключен", color: user.is_active ? "success" : "default", variant: user.is_active ? "filled" : "outlined" })] }), _jsx(Typography, { color: "text.secondary", children: user.email }), _jsxs(Typography, { variant: "body2", color: "text.secondary", children: ["\u0421\u043E\u0437\u0434\u0430\u043D: ", new Date(user.created_at).toLocaleString()] })] }), _jsxs(Stack, { direction: "row", spacing: 0.5, alignItems: "flex-start", children: [_jsx(IconButton, { size: "small", onClick: () => openEditDialog(user), children: _jsx(EditIcon, { fontSize: "small" }) }), _jsx(IconButton, { size: "small", onClick: () => openResetDialog(user), children: _jsx(KeyIcon, { fontSize: "small" }) }), _jsx(IconButton, { size: "small", onClick: () => void handleDeleteUser(user), children: _jsx(DeleteIcon, { fontSize: "small" }) })] })] }) }) }, user.id))) }), _jsxs(Dialog, { open: isCreateOpen, onClose: closeCreateDialog, fullWidth: true, maxWidth: "sm", children: [_jsx(DialogTitle, { children: "\u0421\u043E\u0437\u0434\u0430\u0442\u044C \u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u044F" }), _jsxs(DialogContent, { sx: { display: "grid", gap: 2, pt: 2 }, children: [_jsx(TextField, { label: "\u041B\u043E\u0433\u0438\u043D", value: createUsername, onChange: (event) => setCreateUsername(event.target.value), fullWidth: true }), _jsx(TextField, { label: "Email", value: createEmail, onChange: (event) => setCreateEmail(event.target.value), fullWidth: true }), _jsx(TextField, { label: "\u041F\u0430\u0440\u043E\u043B\u044C", type: "password", value: createPassword, onChange: (event) => setCreatePassword(event.target.value), fullWidth: true }), _jsx(TextField, { select: true, label: "\u0420\u043E\u043B\u044C", value: createRole, onChange: (event) => setCreateRole(event.target.value), fullWidth: true, children: ROLE_OPTIONS.map((option) => (_jsx(MenuItem, { value: option.value, children: option.label }, option.value))) })] }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: closeCreateDialog, children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", onClick: () => void handleCreateUser(), disabled: !createUsername.trim() || !createEmail.trim() || createPassword.length < 8, children: "\u0421\u043E\u0437\u0434\u0430\u0442\u044C" })] })] }), _jsxs(Dialog, { open: isEditOpen, onClose: closeEditDialog, fullWidth: true, maxWidth: "sm", children: [_jsx(DialogTitle, { children: "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u044F" }), _jsxs(DialogContent, { sx: { display: "grid", gap: 2, pt: 2 }, children: [_jsx(TextField, { label: "\u041B\u043E\u0433\u0438\u043D", value: editUsername, onChange: (event) => setEditUsername(event.target.value), fullWidth: true }), _jsx(TextField, { label: "Email", value: editEmail, onChange: (event) => setEditEmail(event.target.value), fullWidth: true }), _jsx(TextField, { select: true, label: "\u0420\u043E\u043B\u044C", value: editRole, onChange: (event) => setEditRole(event.target.value), fullWidth: true, children: ROLE_OPTIONS.map((option) => (_jsx(MenuItem, { value: option.value, children: option.label }, option.value))) }), _jsxs(TextField, { select: true, label: "\u0421\u0442\u0430\u0442\u0443\u0441", value: editIsActive ? "active" : "disabled", onChange: (event) => setEditIsActive(event.target.value === "active"), fullWidth: true, children: [_jsx(MenuItem, { value: "active", children: "\u0410\u043A\u0442\u0438\u0432\u0435\u043D" }), _jsx(MenuItem, { value: "disabled", children: "\u041E\u0442\u043A\u043B\u044E\u0447\u0435\u043D" })] })] }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: closeEditDialog, children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", onClick: () => void handleUpdateUser(), disabled: !editUsername.trim() || !editEmail.trim(), children: "\u0421\u043E\u0445\u0440\u0430\u043D\u0438\u0442\u044C" })] })] }), _jsxs(Dialog, { open: isResetOpen, onClose: closeResetDialog, fullWidth: true, maxWidth: "sm", children: [_jsx(DialogTitle, { children: "\u0421\u0431\u0440\u043E\u0441\u0438\u0442\u044C \u043F\u0430\u0440\u043E\u043B\u044C" }), _jsxs(DialogContent, { sx: { display: "grid", gap: 2, pt: 2 }, children: [_jsx(Typography, { color: "text.secondary", children: activeUser ? `Новый пароль для ${activeUser.username}` : "Новый пароль" }), _jsx(TextField, { label: "\u041D\u043E\u0432\u044B\u0439 \u043F\u0430\u0440\u043E\u043B\u044C", type: "password", value: resetPasswordValue, onChange: (event) => setResetPasswordValue(event.target.value), fullWidth: true })] }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: closeResetDialog, children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", onClick: () => void handleResetPassword(), disabled: resetPasswordValue.length < 8, children: "\u0421\u0431\u0440\u043E\u0441\u0438\u0442\u044C \u043F\u0430\u0440\u043E\u043B\u044C" })] })] })] }));
}
