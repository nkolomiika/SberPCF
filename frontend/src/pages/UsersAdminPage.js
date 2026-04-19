import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import DeleteIcon from "@mui/icons-material/Delete";
import EditIcon from "@mui/icons-material/Edit";
import KeyIcon from "@mui/icons-material/Key";
import MoreVertIcon from "@mui/icons-material/MoreVert";
import { Alert, Avatar, Box, Button, Card, CardContent, Checkbox, Chip, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, IconButton, Menu, MenuItem, Stack, TextField, Tooltip, Typography, } from "@mui/material";
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
    const [pageActionsAnchorEl, setPageActionsAnchorEl] = useState(null);
    const [userActionsAnchorEl, setUserActionsAnchorEl] = useState(null);
    const [isCreateOpen, setCreateOpen] = useState(false);
    const [isEditOpen, setEditOpen] = useState(false);
    const [isResetOpen, setResetOpen] = useState(false);
    const [activeUser, setActiveUser] = useState(null);
    const [createUsername, setCreateUsername] = useState("");
    const [createEmail, setCreateEmail] = useState("");
    const [createFullName, setCreateFullName] = useState("");
    const [createTagsText, setCreateTagsText] = useState("");
    const [createPassword, setCreatePassword] = useState("");
    const [createRole, setCreateRole] = useState("pentester");
    const [createSendInviteEmail, setCreateSendInviteEmail] = useState(true);
    const [editUsername, setEditUsername] = useState("");
    const [editEmail, setEditEmail] = useState("");
    const [editFullName, setEditFullName] = useState("");
    const [editTagsText, setEditTagsText] = useState("");
    const [editRole, setEditRole] = useState("pentester");
    const [editIsActive, setEditIsActive] = useState(true);
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
        setCreateFullName("");
        setCreateTagsText("");
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
    const parseTags = (value) => value
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean);
    const openEditDialog = (user) => {
        setActiveUser(user);
        setEditUsername(user.username);
        setEditEmail(user.email);
        setEditFullName(user.full_name ?? "");
        setEditTagsText(user.tags.join(", "));
        setEditRole(user.role);
        setEditIsActive(user.is_active);
        setEditOpen(true);
    };
    const openResetDialog = (user) => {
        setActiveUser(user);
        setResetOpen(true);
    };
    const handleCreateUser = async () => {
        try {
            await createUser({
                username: createUsername.trim(),
                email: createEmail.trim(),
                full_name: createFullName.trim() || undefined,
                tags: parseTags(createTagsText),
                password: createPassword || undefined,
                role: createRole,
                send_invite_email: createSendInviteEmail,
            });
            setInfoMessage(createSendInviteEmail ? "Пользователь создан, письмо с временным паролем отправлено." : "Пользователь создан.");
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
                full_name: editFullName.trim() || undefined,
                tags: parseTags(editTagsText),
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
            const result = await resetUserPassword(activeUser.id);
            setInfoMessage(`Временный пароль для ${activeUser.username} отправлен на ${result.email_sent_to}.`);
            closeResetDialog();
            await loadUsers();
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
    return (_jsxs(Stack, { spacing: 2.5, children: [error && _jsx(Alert, { severity: "error", children: error }), infoMessage && _jsx(Alert, { severity: "success", children: infoMessage }), _jsxs(Stack, { direction: { xs: "column", sm: "row" }, justifyContent: "space-between", alignItems: { sm: "center" }, gap: 1.5, children: [_jsxs(Stack, { spacing: 0.3, children: [_jsx(Typography, { variant: "h4", fontWeight: 700, children: "\u041F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u0438" }), _jsxs(Stack, { direction: "row", spacing: 1, flexWrap: "wrap", useFlexGap: true, children: [_jsx(Chip, { label: `Всего: ${users.length}`, variant: "outlined" }), _jsx(Chip, { label: `Активных: ${activeUsers}`, variant: "outlined" })] })] }), _jsx(Tooltip, { title: "\u0414\u0435\u0439\u0441\u0442\u0432\u0438\u044F", children: _jsx(IconButton, { onClick: (event) => setPageActionsAnchorEl(event.currentTarget), sx: { border: "1px solid rgba(126,224,255,0.18)" }, children: _jsx(MoreVertIcon, {}) }) })] }), _jsx(Menu, { anchorEl: pageActionsAnchorEl, open: Boolean(pageActionsAnchorEl), onClose: closePageActions, anchorOrigin: { vertical: "bottom", horizontal: "right" }, transformOrigin: { vertical: "top", horizontal: "right" }, children: _jsx(MenuItem, { onClick: () => {
                        closePageActions();
                        setCreateOpen(true);
                    }, children: "\u0421\u043E\u0437\u0434\u0430\u0442\u044C \u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u044F" }) }), _jsx(Stack, { spacing: 1.5, children: users.map((user) => (_jsx(Card, { sx: {
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
                    }, children: _jsx(CardContent, { sx: { p: 2 }, children: _jsxs(Stack, { direction: { xs: "column", md: "row" }, justifyContent: "space-between", gap: 1.5, children: [_jsxs(Stack, { spacing: 0.8, sx: { minWidth: 0 }, children: [_jsxs(Stack, { direction: "row", spacing: 1.2, alignItems: "center", children: [_jsx(Avatar, { src: user.avatar_url ?? undefined, children: (user.full_name || user.username)[0]?.toUpperCase() }), _jsxs(Stack, { spacing: 0.3, sx: { minWidth: 0 }, children: [_jsx(Typography, { variant: "h6", noWrap: true, children: user.full_name || user.username }), _jsxs(Typography, { color: "text.secondary", noWrap: true, children: ["@", user.username] })] })] }), _jsxs(Stack, { direction: "row", spacing: 1, alignItems: "center", flexWrap: "wrap", useFlexGap: true, children: [_jsx(Chip, { size: "small", label: roleLabel(user.role) }), _jsx(Chip, { size: "small", label: user.is_active ? "Активен" : "Отключен", color: user.is_active ? "success" : "default", variant: user.is_active ? "filled" : "outlined" }), user.must_change_password && _jsx(Chip, { size: "small", color: "warning", label: "\u0422\u0440\u0435\u0431\u0443\u0435\u0442\u0441\u044F \u0441\u043C\u0435\u043D\u0430 \u043F\u0430\u0440\u043E\u043B\u044F" }), user.tags.map((tag) => (_jsx(Chip, { size: "small", variant: "outlined", label: tag }, `${user.id}-${tag}`)))] }), _jsx(Typography, { color: "text.secondary", children: user.email }), _jsxs(Typography, { variant: "body2", color: "text.secondary", children: ["\u0421\u043E\u0437\u0434\u0430\u043D: ", new Date(user.created_at).toLocaleString()] })] }), _jsx(Stack, { direction: "row", spacing: 0.5, alignItems: "flex-start", children: _jsx(IconButton, { className: "user-actions-trigger", size: "small", onClick: (event) => {
                                            setActiveUser(user);
                                            setUserActionsAnchorEl(event.currentTarget);
                                        }, children: _jsx(MoreVertIcon, { fontSize: "small" }) }) })] }) }) }, user.id))) }), _jsxs(Menu, { anchorEl: userActionsAnchorEl, open: Boolean(userActionsAnchorEl), onClose: closeUserActions, anchorOrigin: { vertical: "bottom", horizontal: "right" }, transformOrigin: { vertical: "top", horizontal: "right" }, children: [_jsxs(MenuItem, { onClick: () => {
                            if (activeUser) {
                                openEditDialog(activeUser);
                            }
                            closeUserActions();
                        }, children: [_jsx(EditIcon, { fontSize: "small", sx: { mr: 1 } }), "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C"] }), _jsxs(MenuItem, { onClick: () => {
                            if (activeUser) {
                                openResetDialog(activeUser);
                            }
                            closeUserActions();
                        }, children: [_jsx(KeyIcon, { fontSize: "small", sx: { mr: 1 } }), "\u0421\u0431\u0440\u043E\u0441\u0438\u0442\u044C \u043F\u0430\u0440\u043E\u043B\u044C"] }), _jsxs(MenuItem, { onClick: () => {
                            if (activeUser) {
                                void handleDeleteUser(activeUser);
                            }
                            closeUserActions();
                        }, children: [_jsx(DeleteIcon, { fontSize: "small", sx: { mr: 1 } }), "\u0423\u0434\u0430\u043B\u0438\u0442\u044C"] })] }), _jsxs(Dialog, { open: isCreateOpen, onClose: closeCreateDialog, fullWidth: true, maxWidth: "sm", children: [_jsx(DialogTitle, { children: "\u0421\u043E\u0437\u0434\u0430\u0442\u044C \u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u044F" }), _jsxs(DialogContent, { sx: { display: "grid", gap: 2, pt: 2 }, children: [_jsx(TextField, { label: "\u041B\u043E\u0433\u0438\u043D", value: createUsername, onChange: (event) => setCreateUsername(event.target.value), fullWidth: true }), _jsx(TextField, { label: "Email", value: createEmail, onChange: (event) => setCreateEmail(event.target.value), fullWidth: true }), _jsx(TextField, { label: "\u0418\u043C\u044F", value: createFullName, onChange: (event) => setCreateFullName(event.target.value), fullWidth: true }), _jsx(TextField, { label: "\u0422\u0435\u0433\u0438", value: createTagsText, onChange: (event) => setCreateTagsText(event.target.value), helperText: "\u0427\u0435\u0440\u0435\u0437 \u0437\u0430\u043F\u044F\u0442\u0443\u044E", fullWidth: true }), _jsx(TextField, { label: "\u041F\u0430\u0440\u043E\u043B\u044C", type: "password", value: createPassword, onChange: (event) => setCreatePassword(event.target.value), helperText: createSendInviteEmail ? "Можно оставить пустым: система сгенерирует временный пароль." : "Минимум 8 символов.", fullWidth: true }), _jsx(FormControlLabel, { control: _jsx(Checkbox, { checked: createSendInviteEmail, onChange: (event) => setCreateSendInviteEmail(event.target.checked) }), label: "\u041E\u0442\u043F\u0440\u0430\u0432\u0438\u0442\u044C \u043F\u0440\u0438\u0433\u043B\u0430\u0448\u0435\u043D\u0438\u0435 \u0438 \u0432\u0440\u0435\u043C\u0435\u043D\u043D\u044B\u0439 \u043F\u0430\u0440\u043E\u043B\u044C \u043D\u0430 email" }), _jsx(TextField, { select: true, label: "\u0420\u043E\u043B\u044C", value: createRole, onChange: (event) => setCreateRole(event.target.value), fullWidth: true, children: ROLE_OPTIONS.map((option) => (_jsx(MenuItem, { value: option.value, children: option.label }, option.value))) })] }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: closeCreateDialog, children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", onClick: () => void handleCreateUser(), disabled: !createUsername.trim() || !createEmail.trim() || (!createSendInviteEmail && createPassword.length < 8), children: "\u0421\u043E\u0437\u0434\u0430\u0442\u044C" })] })] }), _jsxs(Dialog, { open: isEditOpen, onClose: closeEditDialog, fullWidth: true, maxWidth: "sm", children: [_jsx(DialogTitle, { children: "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u044F" }), _jsxs(DialogContent, { sx: { display: "grid", gap: 2, pt: 2 }, children: [_jsx(TextField, { label: "\u041B\u043E\u0433\u0438\u043D", value: editUsername, onChange: (event) => setEditUsername(event.target.value), fullWidth: true }), _jsx(TextField, { label: "Email", value: editEmail, onChange: (event) => setEditEmail(event.target.value), fullWidth: true }), _jsx(TextField, { label: "\u0418\u043C\u044F", value: editFullName, onChange: (event) => setEditFullName(event.target.value), fullWidth: true }), _jsx(TextField, { label: "\u0422\u0435\u0433\u0438", value: editTagsText, onChange: (event) => setEditTagsText(event.target.value), helperText: "\u0427\u0435\u0440\u0435\u0437 \u0437\u0430\u043F\u044F\u0442\u0443\u044E", fullWidth: true }), _jsx(TextField, { select: true, label: "\u0420\u043E\u043B\u044C", value: editRole, onChange: (event) => setEditRole(event.target.value), fullWidth: true, children: ROLE_OPTIONS.map((option) => (_jsx(MenuItem, { value: option.value, children: option.label }, option.value))) }), _jsxs(TextField, { select: true, label: "\u0421\u0442\u0430\u0442\u0443\u0441", value: editIsActive ? "active" : "disabled", onChange: (event) => setEditIsActive(event.target.value === "active"), fullWidth: true, children: [_jsx(MenuItem, { value: "active", children: "\u0410\u043A\u0442\u0438\u0432\u0435\u043D" }), _jsx(MenuItem, { value: "disabled", children: "\u041E\u0442\u043A\u043B\u044E\u0447\u0435\u043D" })] })] }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: closeEditDialog, children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", onClick: () => void handleUpdateUser(), disabled: !editUsername.trim() || !editEmail.trim(), children: "\u0421\u043E\u0445\u0440\u0430\u043D\u0438\u0442\u044C" })] })] }), _jsxs(Dialog, { open: isResetOpen, onClose: closeResetDialog, fullWidth: true, maxWidth: "sm", children: [_jsx(DialogTitle, { children: "\u0421\u0431\u0440\u043E\u0441\u0438\u0442\u044C \u043F\u0430\u0440\u043E\u043B\u044C" }), _jsx(DialogContent, { sx: { display: "grid", gap: 2, pt: 2 }, children: _jsx(Typography, { color: "text.secondary", children: activeUser
                                ? `Система сгенерирует временный пароль для ${activeUser.username} и отправит его на ${activeUser.email}. При первом входе пользователь должен будет сменить пароль.`
                                : "Система отправит временный пароль на email пользователя." }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: closeResetDialog, children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", onClick: () => void handleResetPassword(), disabled: !activeUser, children: "\u0421\u0431\u0440\u043E\u0441\u0438\u0442\u044C \u043F\u0430\u0440\u043E\u043B\u044C" })] })] })] }));
}
