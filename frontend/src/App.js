import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useEffect, useState } from "react";
import { Badge, Box, Button, CircularProgress, Container, IconButton, Stack, Typography } from "@mui/material";
import NotificationsIcon from "@mui/icons-material/Notifications";
import { Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { unreadCount } from "./api";
import { useAuthStore } from "./store";
import { LoginPage } from "./pages/LoginPage";
import { ProjectDetailPage } from "./pages/ProjectDetailPage";
import { ProjectsPage } from "./pages/ProjectsPage";
function PrivateLayout() {
    const navigate = useNavigate();
    const user = useAuthStore((s) => s.user);
    const signOut = useAuthStore((s) => s.signOut);
    const [count, setCount] = useState(0);
    useEffect(() => {
        const load = async () => {
            const unread = await unreadCount();
            setCount(unread);
        };
        void load();
    }, []);
    if (!user) {
        return _jsx(Navigate, { to: "/login", replace: true });
    }
    return (_jsxs(Box, { sx: { minHeight: "100vh", background: "linear-gradient(180deg,#0f1726 0%, #101d31 100%)" }, children: [_jsx(Box, { sx: { borderBottom: "1px solid #23314f", backdropFilter: "blur(6px)" }, children: _jsx(Container, { sx: { py: 2 }, children: _jsxs(Stack, { direction: "row", justifyContent: "space-between", alignItems: "center", children: [_jsx(Typography, { variant: "h5", fontWeight: 700, children: "Pentest Collaboration Framework" }), _jsxs(Stack, { direction: "row", spacing: 1, alignItems: "center", children: [_jsx(IconButton, { color: "inherit", onClick: () => navigate("/"), children: _jsx(Badge, { color: "error", badgeContent: count, children: _jsx(NotificationsIcon, {}) }) }), _jsx(Typography, { color: "text.secondary", children: user.username }), _jsx(Button, { variant: "outlined", onClick: () => void signOut(), children: "\u0412\u044B\u0439\u0442\u0438" })] })] }) }) }), _jsx(Container, { sx: { py: 3 }, children: _jsxs(Routes, { children: [_jsx(Route, { path: "/", element: _jsx(ProjectsPage, {}) }), _jsx(Route, { path: "/projects/:projectId", element: _jsx(ProjectDetailPage, {}) }), _jsx(Route, { path: "*", element: _jsx(Navigate, { to: "/", replace: true }) })] }) })] }));
}
export default function App() {
    const initialize = useAuthStore((s) => s.initialize);
    const isInitialized = useAuthStore((s) => s.isInitialized);
    const user = useAuthStore((s) => s.user);
    useEffect(() => {
        void initialize();
    }, [initialize]);
    if (!isInitialized) {
        return (_jsx(Box, { display: "flex", minHeight: "100vh", alignItems: "center", justifyContent: "center", children: _jsx(CircularProgress, {}) }));
    }
    return (_jsxs(Routes, { children: [_jsx(Route, { path: "/login", element: user ? _jsx(Navigate, { to: "/", replace: true }) : _jsx(LoginPage, {}) }), _jsx(Route, { path: "/*", element: _jsx(PrivateLayout, {}) })] }));
}
