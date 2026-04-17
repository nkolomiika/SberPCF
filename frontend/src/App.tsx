import { useCallback, useEffect, useState } from "react";
import {
  AppBar,
  Avatar,
  Badge,
  Button,
  Box,
  CircularProgress,
  Container,
  Divider,
  ListItemIcon,
  List,
  ListItemButton,
  ListItemText,
  IconButton,
  Menu,
  MenuItem,
  Popover,
  Paper,
  Stack,
  Toolbar,
  Typography,
} from "@mui/material";
import HomeIcon from "@mui/icons-material/Home";
import KeyboardArrowDownIcon from "@mui/icons-material/KeyboardArrowDown";
import LogoutIcon from "@mui/icons-material/Logout";
import ManageAccountsIcon from "@mui/icons-material/ManageAccounts";
import NotificationsIcon from "@mui/icons-material/Notifications";
import HistoryIcon from "@mui/icons-material/History";
import PersonOutlineIcon from "@mui/icons-material/PersonOutline";
import type { PaletteMode } from "@mui/material";
import { Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { listNotifications, unreadCount } from "./api";
import type { Notification } from "./types";
import { useAuthStore } from "./store";
import { ForceChangePasswordPage } from "./pages/ForceChangePasswordPage";
import { LoginPage } from "./pages/LoginPage";
import { HostDetailPage } from "./pages/HostDetailPage";
import { ProjectDetailPage } from "./pages/ProjectDetailPage";
import { ProfilePage } from "./pages/ProfilePage";
import { ProjectsPage } from "./pages/ProjectsPage";
import { AuditLogsPage } from "./pages/AuditLogsPage";
import { UsersAdminPage } from "./pages/UsersAdminPage";

type PrivateLayoutProps = {
  themeMode: PaletteMode;
};

function PrivateLayout({ themeMode }: PrivateLayoutProps) {
  const navigate = useNavigate();
  const location = useLocation();
  const user = useAuthStore((s) => s.user);
  const signOut = useAuthStore((s) => s.signOut);
  const [count, setCount] = useState<number>(0);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [notificationsLoading, setNotificationsLoading] = useState(false);
  const [notificationsAnchorEl, setNotificationsAnchorEl] = useState<HTMLElement | null>(null);
  const [profileAnchorEl, setProfileAnchorEl] = useState<HTMLElement | null>(null);

  const loadUnreadNotifications = useCallback(async () => {
    const unread = await unreadCount();
    setCount(unread);
  }, []);

  const loadNotificationsList = useCallback(async () => {
    const response = await listNotifications();
    setNotifications(response.items);
  }, []);
  const notificationsOpen = Boolean(notificationsAnchorEl);
  const profileMenuOpen = Boolean(profileAnchorEl);

  useEffect(() => {
    void loadUnreadNotifications();
    const intervalId = window.setInterval(() => {
      void loadUnreadNotifications();
    }, 30000);
    return () => {
      window.clearInterval(intervalId);
    };
  }, [loadUnreadNotifications]);

  useEffect(() => {
    if (!user) {
      return;
    }
    const protocol = window.location.protocol === "https:" ? "wss" : "ws";
    const socket = new WebSocket(`${protocol}://${window.location.host}/ws/notifications`);
    socket.onmessage = () => {
      void loadUnreadNotifications();
      if (notificationsOpen) {
        void loadNotificationsList();
      }
    };
    return () => {
      socket.close();
    };
  }, [loadNotificationsList, loadUnreadNotifications, notificationsOpen, user]);

  const openNotifications = async (event: React.MouseEvent<HTMLElement>) => {
    setNotificationsAnchorEl(event.currentTarget);
    setNotificationsLoading(true);
    try {
      await loadNotificationsList();
      await loadUnreadNotifications();
    } finally {
      setNotificationsLoading(false);
    }
  };

  const closeNotifications = () => {
    setNotificationsAnchorEl(null);
  };

  const openProfileMenu = (event: React.MouseEvent<HTMLElement>) => {
    setProfileAnchorEl(event.currentTarget);
  };

  const closeProfileMenu = () => {
    setProfileAnchorEl(null);
  };

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  if (user.must_change_password && location.pathname !== "/force-change-password") {
    return <Navigate to="/force-change-password" replace />;
  }

  const roleLabel = user.role === "admin" ? "Администратор" : user.role === "developer" ? "Разработчик" : "Пентестер";

  return (
    <Box
      sx={{
        minHeight: "100vh",
        position: "relative",
        "&::before": {
          content: '""',
          position: "fixed",
          inset: 0,
          pointerEvents: "none",
          opacity: 0,
        },
      }}
    >
      <AppBar
        position="sticky"
        elevation={0}
        color="transparent"
        sx={{
          borderBottom: "1px solid rgba(126,224,255,0.12)",
          backdropFilter: "none",
          backgroundColor: "rgba(8,17,31,0.94)",
        }}
      >
        <Toolbar sx={{ py: 1.25 }}>
          <Container
            maxWidth={false}
            sx={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              px: { xs: 2, md: 3 },
              maxWidth: "min(1800px, 100vw)",
            }}
          >
            <Stack spacing={0.3}>
              <Typography variant="h5" fontWeight={700}>
                Pentest Collaboration Framework
              </Typography>
            </Stack>
            <Stack direction="row" spacing={1.5} alignItems="center">
              <IconButton
                color="inherit"
                onClick={openNotifications}
                sx={{
                  border: "1px solid rgba(126,224,255,0.18)",
                  width: 44,
                  height: 44,
                  backgroundColor: "rgba(15,27,45,0.72)",
                  "&:hover": {
                    backgroundColor: "rgba(20,36,58,0.92)",
                  },
                }}
              >
                <Badge color="error" badgeContent={count}>
                  <NotificationsIcon />
                </Badge>
              </IconButton>
              <Button
                color="inherit"
                onClick={openProfileMenu}
                sx={{
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
                }}
              >
                <Stack direction="row" spacing={1.2} alignItems="center" justifyContent="flex-end" sx={{ width: "100%" }}>
                  <Avatar src={user.avatar_url ?? undefined} sx={{ width: 30, height: 30, bgcolor: "primary.main" }}>
                    {(user.full_name || user.username)[0]?.toUpperCase()}
                  </Avatar>
                  <Stack spacing={0} sx={{ flex: 1, minWidth: 0 }}>
                    <Typography color="text.primary" textAlign="right" noWrap>
                      {user.full_name || user.username}
                    </Typography>
                    <Typography variant="caption" color="text.secondary" textAlign="right" noWrap>
                      {roleLabel}
                    </Typography>
                  </Stack>
                  <KeyboardArrowDownIcon fontSize="small" sx={{ color: "text.secondary" }} />
                </Stack>
              </Button>
            </Stack>
          </Container>
        </Toolbar>
      </AppBar>
      <Menu
        anchorEl={profileAnchorEl}
        open={profileMenuOpen}
        onClose={closeProfileMenu}
        anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
        transformOrigin={{ vertical: "top", horizontal: "right" }}
        slotProps={{
          paper: {
            sx: {
              width: profileAnchorEl?.clientWidth ?? 220,
            },
          },
        }}
      >
        <MenuItem
          onClick={() => {
            navigate("/profile");
            closeProfileMenu();
          }}
          sx={{ minWidth: 220 }}
        >
          <ListItemIcon sx={{ minWidth: 30 }}>
            <PersonOutlineIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Профиль</ListItemText>
        </MenuItem>
        <MenuItem
          onClick={() => {
            navigate("/");
            closeProfileMenu();
          }}
          sx={{ minWidth: 220 }}
        >
          <ListItemIcon sx={{ minWidth: 30 }}>
            <HomeIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Домой</ListItemText>
        </MenuItem>
        {user.role === "admin" && (
          <MenuItem
            onClick={() => {
              navigate("/users");
              closeProfileMenu();
            }}
            sx={{ minWidth: 220 }}
          >
            <ListItemIcon sx={{ minWidth: 30 }}>
              <ManageAccountsIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText>Пользователи</ListItemText>
          </MenuItem>
        )}
        {user.role === "admin" && (
          <MenuItem
            onClick={() => {
              navigate("/audit-logs");
              closeProfileMenu();
            }}
            sx={{ minWidth: 220 }}
          >
            <ListItemIcon sx={{ minWidth: 30 }}>
              <HistoryIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText>Журнал действий</ListItemText>
          </MenuItem>
        )}
        <MenuItem
          onClick={() => {
            closeProfileMenu();
            void signOut();
          }}
          sx={{ minWidth: 220 }}
        >
          <ListItemIcon sx={{ minWidth: 30 }}>
            <LogoutIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Выйти</ListItemText>
        </MenuItem>
      </Menu>
      <Popover
        open={notificationsOpen}
        anchorEl={notificationsAnchorEl}
        onClose={closeNotifications}
        anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
        transformOrigin={{ vertical: "top", horizontal: "right" }}
      >
        <Box sx={{ width: 360, maxWidth: "90vw" }}>
          <Box sx={{ px: 2, py: 1.5 }}>
            <Typography variant="subtitle1" fontWeight={700}>
              Уведомления
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Непрочитанных: {count}
            </Typography>
          </Box>
          <Divider />
          {notificationsLoading ? (
            <Box sx={{ p: 2, display: "flex", justifyContent: "center" }}>
              <CircularProgress size={20} />
            </Box>
          ) : notifications.length === 0 ? (
            <Box sx={{ p: 2 }}>
              <Typography variant="body2" color="text.secondary">
                Новых уведомлений нет.
              </Typography>
            </Box>
          ) : (
            <List dense disablePadding>
              {notifications.map((notification) => (
                <ListItemButton key={notification.id} onClick={closeNotifications}>
                  <ListItemText
                    primary={notification.context?.vulnerability_title ?? "Уведомление"}
                    secondary={
                      notification.context?.commenter_username
                        ? `Упоминание от ${notification.context.commenter_username}`
                        : "Обновление в проекте"
                    }
                  />
                </ListItemButton>
              ))}
            </List>
          )}
        </Box>
      </Popover>
      <Container
        maxWidth={false}
        sx={{
          py: { xs: 2.5, md: 3.5 },
          px: { xs: 2, md: 3 },
          maxWidth: "min(1800px, 100vw)",
        }}
      >
        <Routes>
          <Route path="/force-change-password" element={<ForceChangePasswordPage />} />
          <Route
            path="/"
            element={
              <Paper
                sx={{
                  p: { xs: 2, md: 3 },
                  borderRadius: 0,
                  backgroundColor: themeMode === "dark" ? "rgba(15,27,45,0.78)" : "rgba(255,255,255,0.8)",
                }}
              >
                <ProjectsPage />
              </Paper>
            }
          />
          <Route path="/profile" element={<ProfilePage />} />
          <Route path="/projects/:projectId" element={<ProjectDetailPage />} />
          <Route path="/projects/:projectId/hosts/:hostId" element={<HostDetailPage />} />
          <Route path="/users" element={user.role === "admin" ? <UsersAdminPage /> : <Navigate to="/" replace />} />
          <Route path="/audit-logs" element={user.role === "admin" ? <AuditLogsPage /> : <Navigate to="/" replace />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Container>
    </Box>
  );
}

type AppProps = {
  themeMode: PaletteMode;
};

export default function App({ themeMode }: AppProps) {
  const initialize = useAuthStore((s) => s.initialize);
  const isInitialized = useAuthStore((s) => s.isInitialized);
  const user = useAuthStore((s) => s.user);

  useEffect(() => {
    void initialize();
  }, [initialize]);

  if (!isInitialized) {
    return (
      <Box display="flex" minHeight="100vh" alignItems="center" justifyContent="center">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Routes>
      <Route path="/login" element={user ? <Navigate to={user.must_change_password ? "/force-change-password" : "/"} replace /> : <LoginPage />} />
      <Route path="/*" element={<PrivateLayout themeMode={themeMode} />} />
    </Routes>
  );
}
