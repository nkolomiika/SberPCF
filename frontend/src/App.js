import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useEffect, useState } from "react";
import { AppBar, Avatar, Badge, Button, Box, CircularProgress, Container, Divider, ListItemIcon, List, ListItemButton, ListItemText, IconButton, Menu, MenuItem, Popover, Paper, Stack, Toolbar, Typography, } from "@mui/material";
import HomeIcon from "@mui/icons-material/Home";
import KeyboardArrowDownIcon from "@mui/icons-material/KeyboardArrowDown";
import LogoutIcon from "@mui/icons-material/Logout";
import NotificationsIcon from "@mui/icons-material/Notifications";
import DarkModeIcon from "@mui/icons-material/DarkMode";
import LightModeIcon from "@mui/icons-material/LightMode";
import { Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { listNotifications, unreadCount } from "./api";
import { useAuthStore } from "./store";
import { LoginPage } from "./pages/LoginPage";
import { HostDetailPage } from "./pages/HostDetailPage";
import { ProjectDetailPage } from "./pages/ProjectDetailPage";
import { ProjectsPage } from "./pages/ProjectsPage";
function PrivateLayout({ themeMode, onToggleTheme }) {
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
    return (_jsxs(Box, { sx: {
            minHeight: "100vh",
            background: themeMode === "dark"
                ? "radial-gradient(130% 80% at 0% 0%, rgba(110,168,254,0.18) 0%, rgba(11,18,32,1) 55%), radial-gradient(120% 80% at 100% 0%, rgba(126,224,255,0.14) 0%, rgba(11,18,32,0.98) 45%)"
                : "radial-gradient(130% 80% at 0% 0%, rgba(110,168,254,0.2) 0%, rgba(244,248,255,1) 65%), radial-gradient(120% 80% at 100% 0%, rgba(126,224,255,0.18) 0%, rgba(239,246,255,1) 55%)",
        }, children: [_jsx(AppBar, { position: "sticky", elevation: 0, color: "transparent", sx: { borderBottom: "1px solid rgba(126,224,255,0.18)", backdropFilter: "blur(10px)" }, children: _jsx(Toolbar, { sx: { py: 1 }, children: _jsxs(Container, { maxWidth: false, sx: {
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "center",
                            px: { xs: 2, md: 3 },
                            maxWidth: "min(1800px, 100vw)",
                        }, children: [_jsx(Stack, { spacing: 0, children: _jsx(Typography, { variant: "h5", fontWeight: 700, letterSpacing: 0.2, children: "Pentest Collaboration Framework" }) }), _jsxs(Stack, { direction: "row", spacing: 1.5, alignItems: "center", children: [_jsx(IconButton, { color: "inherit", onClick: onToggleTheme, sx: {
                                            border: "1px solid rgba(126,224,255,0.28)",
                                            borderRadius: 2,
                                            width: 44,
                                            height: 44,
                                            backgroundColor: "rgba(22,36,58,0.12)",
                                        }, children: themeMode === "dark" ? _jsx(LightModeIcon, {}) : _jsx(DarkModeIcon, {}) }), _jsx(IconButton, { color: "inherit", onClick: openNotifications, sx: {
                                            border: "1px solid rgba(126,224,255,0.28)",
                                            borderRadius: 2,
                                            width: 44,
                                            height: 44,
                                            backgroundColor: "rgba(22,36,58,0.55)",
                                            "&:hover": {
                                                backgroundColor: "rgba(28,46,72,0.7)",
                                            },
                                        }, children: _jsx(Badge, { color: "error", badgeContent: count, children: _jsx(NotificationsIcon, {}) }) }), _jsx(Button, { color: "inherit", onClick: openProfileMenu, sx: {
                                            border: "1px solid rgba(126,224,255,0.28)",
                                            borderRadius: 2,
                                            textTransform: "none",
                                            px: 1.4,
                                            py: 0,
                                            height: 44,
                                            minHeight: 44,
                                            minWidth: 220,
                                            justifyContent: "flex-end",
                                            backgroundColor: "rgba(22,36,58,0.55)",
                                            "&:hover": {
                                                backgroundColor: "rgba(28,46,72,0.7)",
                                            },
                                        }, children: _jsxs(Stack, { direction: "row", spacing: 1.2, alignItems: "center", justifyContent: "flex-end", sx: { width: "100%" }, children: [_jsx(Avatar, { sx: { width: 30, height: 30, bgcolor: "primary.main" }, children: user.username[0]?.toUpperCase() }), _jsxs(Stack, { spacing: 0, sx: { flex: 1, minWidth: 0 }, children: [_jsx(Typography, { color: "text.primary", textAlign: "right", noWrap: true, children: user.username }), _jsx(Typography, { variant: "caption", color: "text.secondary", textAlign: "right", noWrap: true, children: user.role === "admin" ? "Администратор" : "Пентестер" })] }), _jsx(KeyboardArrowDownIcon, { fontSize: "small", sx: { color: "text.secondary" } })] }) })] })] }) }) }), _jsxs(Menu, { anchorEl: profileAnchorEl, open: profileMenuOpen, onClose: closeProfileMenu, anchorOrigin: { vertical: "bottom", horizontal: "right" }, transformOrigin: { vertical: "top", horizontal: "right" }, slotProps: {
                    paper: {
                        sx: {
                            width: 220,
                        },
                    },
                }, children: [_jsxs(MenuItem, { onClick: () => {
                            navigate("/");
                            closeProfileMenu();
                        }, sx: { minWidth: 220 }, children: [_jsx(ListItemIcon, { sx: { minWidth: 30 }, children: _jsx(HomeIcon, { fontSize: "small" }) }), _jsx(ListItemText, { children: "\u0414\u043E\u043C\u043E\u0439" })] }), _jsxs(MenuItem, { onClick: () => {
                            closeProfileMenu();
                            void signOut();
                        }, sx: { minWidth: 220 }, children: [_jsx(ListItemIcon, { sx: { minWidth: 30 }, children: _jsx(LogoutIcon, { fontSize: "small" }) }), _jsx(ListItemText, { children: "\u0412\u044B\u0439\u0442\u0438" })] })] }), _jsx(Popover, { open: notificationsOpen, anchorEl: notificationsAnchorEl, onClose: closeNotifications, anchorOrigin: { vertical: "bottom", horizontal: "right" }, transformOrigin: { vertical: "top", horizontal: "right" }, children: _jsxs(Box, { sx: { width: 360, maxWidth: "90vw" }, children: [_jsxs(Box, { sx: { px: 2, py: 1.5 }, children: [_jsx(Typography, { variant: "subtitle1", fontWeight: 700, children: "\u0423\u0432\u0435\u0434\u043E\u043C\u043B\u0435\u043D\u0438\u044F" }), _jsxs(Typography, { variant: "body2", color: "text.secondary", children: ["\u041D\u0435\u043F\u0440\u043E\u0447\u0438\u0442\u0430\u043D\u043D\u044B\u0445: ", count] })] }), _jsx(Divider, {}), notificationsLoading ? (_jsx(Box, { sx: { p: 2, display: "flex", justifyContent: "center" }, children: _jsx(CircularProgress, { size: 20 }) })) : notifications.length === 0 ? (_jsx(Box, { sx: { p: 2 }, children: _jsx(Typography, { variant: "body2", color: "text.secondary", children: "\u041D\u043E\u0432\u044B\u0445 \u0443\u0432\u0435\u0434\u043E\u043C\u043B\u0435\u043D\u0438\u0439 \u043D\u0435\u0442." }) })) : (_jsx(List, { dense: true, disablePadding: true, children: notifications.map((notification) => (_jsx(ListItemButton, { onClick: closeNotifications, children: _jsx(ListItemText, { primary: notification.context?.vulnerability_title ?? "Уведомление", secondary: notification.context?.commenter_username
                                        ? `Упоминание от ${notification.context.commenter_username}`
                                        : "Обновление в проекте" }) }, notification.id))) }))] }) }), _jsx(Container, { maxWidth: false, sx: {
                    py: 3,
                    px: { xs: 2, md: 3 },
                    maxWidth: "min(1800px, 100vw)",
                }, children: _jsxs(Routes, { children: [_jsx(Route, { path: "/", element: _jsx(Paper, { sx: {
                                    p: { xs: 2, md: 3 },
                                    borderRadius: 0,
                                    backgroundColor: themeMode === "dark" ? "rgba(18,29,49,0.68)" : "rgba(255,255,255,0.8)",
                                }, children: _jsx(ProjectsPage, {}) }) }), _jsx(Route, { path: "/projects/:projectId", element: _jsx(ProjectDetailPage, {}) }), _jsx(Route, { path: "/projects/:projectId/hosts/:hostId", element: _jsx(HostDetailPage, {}) }), _jsx(Route, { path: "*", element: _jsx(Navigate, { to: "/", replace: true }) })] }) })] }));
}
export default function App({ themeMode, onToggleTheme }) {
    const initialize = useAuthStore((s) => s.initialize);
    const isInitialized = useAuthStore((s) => s.isInitialized);
    const user = useAuthStore((s) => s.user);
    useEffect(() => {
        void initialize();
    }, [initialize]);
    if (!isInitialized) {
        return (_jsx(Box, { display: "flex", minHeight: "100vh", alignItems: "center", justifyContent: "center", children: _jsx(CircularProgress, {}) }));
    }
    return (_jsxs(Routes, { children: [_jsx(Route, { path: "/login", element: user ? _jsx(Navigate, { to: "/", replace: true }) : _jsx(LoginPage, {}) }), _jsx(Route, { path: "/*", element: _jsx(PrivateLayout, { themeMode: themeMode, onToggleTheme: onToggleTheme }) })] }));
}
