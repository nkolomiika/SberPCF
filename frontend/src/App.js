import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useEffect, useState } from "react";
import { AppBar, Avatar, Badge, Button, Box, CircularProgress, Container, Divider, ListItemIcon, List, ListItemButton, ListItemText, IconButton, Menu, MenuItem, Popover, Paper, Stack, Toolbar, Typography, } from "@mui/material";
import HomeIcon from "@mui/icons-material/Home";
import KeyboardArrowDownIcon from "@mui/icons-material/KeyboardArrowDown";
import LogoutIcon from "@mui/icons-material/Logout";
import NotificationsIcon from "@mui/icons-material/Notifications";
import HistoryIcon from "@mui/icons-material/History";
import { Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { listNotifications, unreadCount } from "./api";
import { useAuthStore } from "./store";
import { LoginPage } from "./pages/LoginPage";
import { HostDetailPage } from "./pages/HostDetailPage";
import { ProjectDetailPage } from "./pages/ProjectDetailPage";
import { ProjectsPage } from "./pages/ProjectsPage";
import { AuditLogsPage } from "./pages/AuditLogsPage";
function PrivateLayout({ themeMode }) {
    const navigate = useNavigate();
    const user = useAuthStore((s) => s.user);
    const signOut = useAuthStore((s) => s.signOut);
    const [count, setCount] = useState(0);
    const [notifications, setNotifications] = useState([]);
    const [notificationsLoading, setNotificationsLoading] = useState(false);
    const [notificationsAnchorEl, setNotificationsAnchorEl] = useState(null);
    const [profileAnchorEl, setProfileAnchorEl] = useState(null);
    useEffect(() => {
        const load = async () => {
            const unread = await unreadCount();
            setCount(unread);
        };
        void load();
    }, []);
    const openNotifications = async (event) => {
        setNotificationsAnchorEl(event.currentTarget);
        setNotificationsLoading(true);
        try {
            const response = await listNotifications();
            setNotifications(response.items);
        }
        finally {
            setNotificationsLoading(false);
        }
    };
    const closeNotifications = () => {
        setNotificationsAnchorEl(null);
    };
    const notificationsOpen = Boolean(notificationsAnchorEl);
    const profileMenuOpen = Boolean(profileAnchorEl);
    const openProfileMenu = (event) => {
        setProfileAnchorEl(event.currentTarget);
    };
    const closeProfileMenu = () => {
        setProfileAnchorEl(null);
    };
    if (!user) {
        return _jsx(Navigate, { to: "/login", replace: true });
    }
    const roleLabel = user.role === "admin" ? "Администратор" : user.role === "developer" ? "Разработчик" : "Пентестер";
    return (_jsxs(Box, { sx: {
            minHeight: "100vh",
            position: "relative",
            "&::before": {
                content: '""',
                position: "fixed",
                inset: 0,
                pointerEvents: "none",
                opacity: 0,
            },
        }, children: [_jsx(AppBar, { position: "sticky", elevation: 0, color: "transparent", sx: {
                    borderBottom: "1px solid rgba(126,224,255,0.12)",
                    backdropFilter: "none",
                    backgroundColor: "rgba(8,17,31,0.94)",
                }, children: _jsx(Toolbar, { sx: { py: 1.25 }, children: _jsxs(Container, { maxWidth: false, sx: {
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "center",
                            px: { xs: 2, md: 3 },
                            maxWidth: "min(1800px, 100vw)",
                        }, children: [_jsxs(Stack, { spacing: 0.3, children: [_jsx(Typography, { variant: "overline", color: "primary.main", sx: { letterSpacing: 1.6, fontWeight: 700 }, children: "Pentest Workspace" }), _jsx(Typography, { variant: "h5", fontWeight: 700, children: "Pentest Collaboration Framework" }), _jsx(Typography, { variant: "body2", color: "text.secondary", children: "\u041F\u0440\u043E\u0435\u043A\u0442\u044B, \u0430\u043A\u0442\u0438\u0432\u044B, \u0443\u044F\u0437\u0432\u0438\u043C\u043E\u0441\u0442\u0438 \u0438 \u043E\u0442\u0447\u0435\u0442\u044B \u0432 \u043E\u0434\u043D\u043E\u043C \u0440\u0430\u0431\u043E\u0447\u0435\u043C \u043A\u043E\u043D\u0442\u0443\u0440\u0435" })] }), _jsxs(Stack, { direction: "row", spacing: 1.5, alignItems: "center", children: [_jsx(IconButton, { color: "inherit", onClick: openNotifications, sx: {
                                            border: "1px solid rgba(126,224,255,0.18)",
                                            width: 44,
                                            height: 44,
                                            backgroundColor: "rgba(15,27,45,0.72)",
                                            "&:hover": {
                                                backgroundColor: "rgba(20,36,58,0.92)",
                                            },
                                        }, children: _jsx(Badge, { color: "error", badgeContent: count, children: _jsx(NotificationsIcon, {}) }) }), _jsx(Button, { color: "inherit", onClick: openProfileMenu, sx: {
                                            border: "1px solid rgba(126,224,255,0.18)",
                                            textTransform: "none",
                                            px: 1.4,
                                            py: 0,
                                            height: 44,
                                            minHeight: 44,
                                            minWidth: 220,
                                            justifyContent: "flex-end",
                                            backgroundColor: "rgba(15,27,45,0.72)",
                                            "&:hover": {
                                                backgroundColor: "rgba(20,36,58,0.92)",
                                            },
                                        }, children: _jsxs(Stack, { direction: "row", spacing: 1.2, alignItems: "center", justifyContent: "flex-end", sx: { width: "100%" }, children: [_jsx(Avatar, { sx: { width: 30, height: 30, bgcolor: "primary.main" }, children: user.username[0]?.toUpperCase() }), _jsxs(Stack, { spacing: 0, sx: { flex: 1, minWidth: 0 }, children: [_jsx(Typography, { color: "text.primary", textAlign: "right", noWrap: true, children: user.username }), _jsx(Typography, { variant: "caption", color: "text.secondary", textAlign: "right", noWrap: true, children: roleLabel })] }), _jsx(KeyboardArrowDownIcon, { fontSize: "small", sx: { color: "text.secondary" } })] }) })] })] }) }) }), _jsxs(Menu, { anchorEl: profileAnchorEl, open: profileMenuOpen, onClose: closeProfileMenu, anchorOrigin: { vertical: "bottom", horizontal: "right" }, transformOrigin: { vertical: "top", horizontal: "right" }, slotProps: {
                    paper: {
                        sx: {
                            width: 220,
                        },
                    },
                }, children: [_jsxs(MenuItem, { onClick: () => {
                            navigate("/");
                            closeProfileMenu();
                        }, sx: { minWidth: 220 }, children: [_jsx(ListItemIcon, { sx: { minWidth: 30 }, children: _jsx(HomeIcon, { fontSize: "small" }) }), _jsx(ListItemText, { children: "\u0414\u043E\u043C\u043E\u0439" })] }), user.role === "admin" && (_jsxs(MenuItem, { onClick: () => {
                            navigate("/audit-logs");
                            closeProfileMenu();
                        }, sx: { minWidth: 220 }, children: [_jsx(ListItemIcon, { sx: { minWidth: 30 }, children: _jsx(HistoryIcon, { fontSize: "small" }) }), _jsx(ListItemText, { children: "\u0416\u0443\u0440\u043D\u0430\u043B \u0434\u0435\u0439\u0441\u0442\u0432\u0438\u0439" })] })), _jsxs(MenuItem, { onClick: () => {
                            closeProfileMenu();
                            void signOut();
                        }, sx: { minWidth: 220 }, children: [_jsx(ListItemIcon, { sx: { minWidth: 30 }, children: _jsx(LogoutIcon, { fontSize: "small" }) }), _jsx(ListItemText, { children: "\u0412\u044B\u0439\u0442\u0438" })] })] }), _jsx(Popover, { open: notificationsOpen, anchorEl: notificationsAnchorEl, onClose: closeNotifications, anchorOrigin: { vertical: "bottom", horizontal: "right" }, transformOrigin: { vertical: "top", horizontal: "right" }, children: _jsxs(Box, { sx: { width: 360, maxWidth: "90vw" }, children: [_jsxs(Box, { sx: { px: 2, py: 1.5 }, children: [_jsx(Typography, { variant: "subtitle1", fontWeight: 700, children: "\u0423\u0432\u0435\u0434\u043E\u043C\u043B\u0435\u043D\u0438\u044F" }), _jsxs(Typography, { variant: "body2", color: "text.secondary", children: ["\u041D\u0435\u043F\u0440\u043E\u0447\u0438\u0442\u0430\u043D\u043D\u044B\u0445: ", count] })] }), _jsx(Divider, {}), notificationsLoading ? (_jsx(Box, { sx: { p: 2, display: "flex", justifyContent: "center" }, children: _jsx(CircularProgress, { size: 20 }) })) : notifications.length === 0 ? (_jsx(Box, { sx: { p: 2 }, children: _jsx(Typography, { variant: "body2", color: "text.secondary", children: "\u041D\u043E\u0432\u044B\u0445 \u0443\u0432\u0435\u0434\u043E\u043C\u043B\u0435\u043D\u0438\u0439 \u043D\u0435\u0442." }) })) : (_jsx(List, { dense: true, disablePadding: true, children: notifications.map((notification) => (_jsx(ListItemButton, { onClick: closeNotifications, children: _jsx(ListItemText, { primary: notification.context?.vulnerability_title ?? "Уведомление", secondary: notification.context?.commenter_username
                                        ? `Упоминание от ${notification.context.commenter_username}`
                                        : "Обновление в проекте" }) }, notification.id))) }))] }) }), _jsx(Container, { maxWidth: false, sx: {
                    py: { xs: 2.5, md: 3.5 },
                    px: { xs: 2, md: 3 },
                    maxWidth: "min(1800px, 100vw)",
                }, children: _jsxs(Routes, { children: [_jsx(Route, { path: "/", element: _jsx(Paper, { sx: {
                                    p: { xs: 2, md: 3 },
                                    borderRadius: 0,
                                    backgroundColor: themeMode === "dark" ? "rgba(15,27,45,0.78)" : "rgba(255,255,255,0.8)",
                                }, children: _jsx(ProjectsPage, {}) }) }), _jsx(Route, { path: "/projects/:projectId", element: _jsx(ProjectDetailPage, {}) }), _jsx(Route, { path: "/projects/:projectId/hosts/:hostId", element: _jsx(HostDetailPage, {}) }), _jsx(Route, { path: "/audit-logs", element: user.role === "admin" ? _jsx(AuditLogsPage, {}) : _jsx(Navigate, { to: "/", replace: true }) }), _jsx(Route, { path: "*", element: _jsx(Navigate, { to: "/", replace: true }) })] }) })] }));
}
export default function App({ themeMode }) {
    const initialize = useAuthStore((s) => s.initialize);
    const isInitialized = useAuthStore((s) => s.isInitialized);
    const user = useAuthStore((s) => s.user);
    useEffect(() => {
        void initialize();
    }, [initialize]);
    if (!isInitialized) {
        return (_jsx(Box, { display: "flex", minHeight: "100vh", alignItems: "center", justifyContent: "center", children: _jsx(CircularProgress, {}) }));
    }
    return (_jsxs(Routes, { children: [_jsx(Route, { path: "/login", element: user ? _jsx(Navigate, { to: "/", replace: true }) : _jsx(LoginPage, {}) }), _jsx(Route, { path: "/*", element: _jsx(PrivateLayout, { themeMode: themeMode }) })] }));
}
