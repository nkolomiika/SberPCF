import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { Alert, Box, Button, Paper, Stack, TextField, Typography } from "@mui/material";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { forceChangePassword } from "../api";
import { useAuthStore } from "../store";
export function ForceChangePasswordPage() {
    const navigate = useNavigate();
    const user = useAuthStore((s) => s.user);
    const setUser = useAuthStore((s) => s.setUser);
    const signOut = useAuthStore((s) => s.signOut);
    const [newPassword, setNewPassword] = useState("");
    const [confirmPassword, setConfirmPassword] = useState("");
    const [error, setError] = useState(null);
    const [saving, setSaving] = useState(false);
    if (!user) {
        return null;
    }
    return (_jsx(Box, { display: "flex", minHeight: "70vh", alignItems: "center", justifyContent: "center", children: _jsx(Paper, { elevation: 0, sx: { width: 520, maxWidth: "100%", p: 4, borderRadius: 0 }, children: _jsxs(Stack, { spacing: 2.5, children: [_jsxs(Stack, { spacing: 0.5, children: [_jsx(Typography, { variant: "h4", fontWeight: 700, children: "\u0421\u043C\u0435\u043D\u0438\u0442\u0435 \u043F\u0430\u0440\u043E\u043B\u044C" }), _jsxs(Typography, { color: "text.secondary", children: ["\u0414\u043B\u044F \u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u044F ", user.username, " \u0432\u044B\u0434\u0430\u043D \u0432\u0440\u0435\u043C\u0435\u043D\u043D\u044B\u0439 \u043F\u0430\u0440\u043E\u043B\u044C. \u041F\u0435\u0440\u0435\u0434 \u043D\u0430\u0447\u0430\u043B\u043E\u043C \u0440\u0430\u0431\u043E\u0442\u044B \u043D\u0443\u0436\u043D\u043E \u0437\u0430\u0434\u0430\u0442\u044C \u043D\u043E\u0432\u044B\u0439."] })] }), error && _jsx(Alert, { severity: "error", children: error }), _jsx(TextField, { label: "\u041D\u043E\u0432\u044B\u0439 \u043F\u0430\u0440\u043E\u043B\u044C", type: "password", value: newPassword, onChange: (event) => setNewPassword(event.target.value), fullWidth: true }), _jsx(TextField, { label: "\u041F\u043E\u0434\u0442\u0432\u0435\u0440\u0434\u0438\u0442\u0435 \u043F\u0430\u0440\u043E\u043B\u044C", type: "password", value: confirmPassword, onChange: (event) => setConfirmPassword(event.target.value), error: Boolean(confirmPassword && newPassword !== confirmPassword), helperText: confirmPassword && newPassword !== confirmPassword ? "Пароли не совпадают" : " ", fullWidth: true }), _jsxs(Stack, { direction: "row", spacing: 1.5, children: [_jsx(Button, { variant: "contained", disabled: saving || newPassword.length < 8 || newPassword !== confirmPassword, onClick: () => {
                                    setSaving(true);
                                    setError(null);
                                    void forceChangePassword(newPassword)
                                        .then((updatedUser) => {
                                        setUser(updatedUser);
                                        navigate("/", { replace: true });
                                    })
                                        .catch((submitError) => {
                                        setError(submitError instanceof Error ? submitError.message : "Не удалось сменить пароль.");
                                    })
                                        .finally(() => setSaving(false));
                                }, children: saving ? "Сохранение..." : "Сохранить пароль" }), _jsx(Button, { variant: "outlined", onClick: () => {
                                    void signOut();
                                    navigate("/login", { replace: true });
                                }, children: "\u0412\u044B\u0439\u0442\u0438" })] })] }) }) }));
}
