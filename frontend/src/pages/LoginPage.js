import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { Box, Button, Paper, Stack, TextField, Typography } from "@mui/material";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuthStore } from "../store";
import { useErrorToast } from "../useErrorToast";
export function LoginPage() {
    const navigate = useNavigate();
    const signIn = useAuthStore((s) => s.signIn);
    const isLoading = useAuthStore((s) => s.isLoading);
    const error = useAuthStore((s) => s.error);
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    useErrorToast(error);
    const handleSubmit = async (event) => {
        event.preventDefault();
        try {
            const currentUser = await signIn(username, password);
            navigate(currentUser.must_change_password ? "/force-change-password" : "/");
        }
        catch {
            // Ошибка уже положена в store и показана на форме.
        }
    };
    return (_jsx(Box, { display: "flex", minHeight: "100vh", alignItems: "center", justifyContent: "center", sx: {
            p: 2,
            background: "linear-gradient(180deg, #08111F 0%, #0B1220 100%)",
        }, children: _jsxs(Paper, { elevation: 6, sx: { width: 460, maxWidth: "100%", p: 4.5, borderRadius: 0 }, children: [_jsx(Typography, { variant: "h4", fontWeight: 700, gutterBottom: true, children: "\u0412\u0445\u043E\u0434 \u0432 PCF" }), _jsxs(Stack, { component: "form", spacing: 2, onSubmit: handleSubmit, children: [_jsx(TextField, { label: "\u041B\u043E\u0433\u0438\u043D", value: username, onChange: (e) => setUsername(e.target.value), required: true }), _jsx(TextField, { label: "\u041F\u0430\u0440\u043E\u043B\u044C", value: password, onChange: (e) => setPassword(e.target.value), required: true, type: "password" }), _jsx(Button, { disabled: isLoading, type: "submit", variant: "contained", size: "large", children: isLoading ? "Вход..." : "Войти" })] })] }) }));
}
