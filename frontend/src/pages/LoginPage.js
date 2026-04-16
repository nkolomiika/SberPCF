import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { Alert, Box, Button, Paper, Stack, TextField, Typography } from "@mui/material";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuthStore } from "../store";
export function LoginPage() {
    const navigate = useNavigate();
    const signIn = useAuthStore((s) => s.signIn);
    const isLoading = useAuthStore((s) => s.isLoading);
    const error = useAuthStore((s) => s.error);
    const [username, setUsername] = useState("admin");
    const [password, setPassword] = useState("admin");
    const handleSubmit = async (event) => {
        event.preventDefault();
        await signIn(username, password);
        navigate("/");
    };
    return (_jsx(Box, { display: "flex", minHeight: "100vh", alignItems: "center", justifyContent: "center", sx: {
            p: 2,
            background: "linear-gradient(180deg, #08111F 0%, #0B1220 100%)",
        }, children: _jsxs(Paper, { elevation: 6, sx: { width: 460, maxWidth: "100%", p: 4.5, borderRadius: 0 }, children: [_jsx(Typography, { variant: "overline", color: "primary.main", sx: { letterSpacing: 1.8, fontWeight: 700 }, children: "Pentest Workspace" }), _jsx(Typography, { variant: "h4", fontWeight: 700, gutterBottom: true, children: "\u0412\u0445\u043E\u0434 \u0432 PCF" }), _jsx(Typography, { color: "text.secondary", sx: { mb: 3 }, children: "\u041E\u0442\u043A\u0440\u043E\u0439 \u043F\u0440\u043E\u0435\u043A\u0442\u044B, \u0430\u043A\u0442\u0438\u0432\u044B \u0438 \u0440\u0430\u0431\u043E\u0447\u0438\u0435 \u0437\u0430\u043C\u0435\u0442\u043A\u0438 \u043A\u043E\u043C\u0430\u043D\u0434\u044B \u0432 \u0435\u0434\u0438\u043D\u043E\u043C \u0438\u043D\u0442\u0435\u0440\u0444\u0435\u0439\u0441\u0435." }), _jsxs(Stack, { component: "form", spacing: 2, onSubmit: handleSubmit, children: [error && _jsx(Alert, { severity: "error", children: error }), _jsx(TextField, { label: "\u041B\u043E\u0433\u0438\u043D", value: username, onChange: (e) => setUsername(e.target.value), required: true }), _jsx(TextField, { label: "\u041F\u0430\u0440\u043E\u043B\u044C", value: password, onChange: (e) => setPassword(e.target.value), required: true, type: "password" }), _jsx(Button, { disabled: isLoading, type: "submit", variant: "contained", size: "large", children: isLoading ? "Вход..." : "Войти" })] })] }) }));
}
