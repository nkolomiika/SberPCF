import { useEffect, useState } from "react";
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
import NotificationsIcon from "@mui/icons-material/Notifications";
import DarkModeIcon from "@mui/icons-material/DarkMode";
import LightModeIcon from "@mui/icons-material/LightMode";
import type { PaletteMode } from "@mui/material";
import { Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { listNotifications, unreadCount } from "./api";
import type { Notification } from "./types";
import { useAuthStore } from "./store";
import { LoginPage } from "./pages/LoginPage";
import { HostDetailPage } from "./pages/HostDetailPage";
import { ProjectDetailPage } from "./pages/ProjectDetailPage";
import { ProjectsPage } from "./pages/ProjectsPage";

type PrivateLayoutProps = {
  themeMode: PaletteMode;
  onToggleTheme: () => void;
};

function PrivateLayout({ themeMode, onToggleTheme }: PrivateLayoutProps) {
  const navigate = useNavigate();
  const user = useAuthStore((s) => s.user);
  const signOut = useAuthStore((s) => s.signOut);
  const [count, setCount] = useState<number>(0);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [notificationsLoading, setNotificationsLoading] = useState(false);
  const [notificationsAnchorEl, setNotificationsAnchorEl] = useState<HTMLElement | null>(null);
  const [profileAnchorEl, setProfileAnchorEl] = useState<HTMLElement | null>(null);

  useEffect(() => {
    const load = async () => {
      const unread = await unreadCount();
      setCount(unread);
    };
    void load();
  }, []);

  const openNotifications = async (event: React.MouseEvent<HTMLElement>) => {
    setNotificationsAnchorEl(event.currentTarget);
    setNotificationsLoading(true);
    try {
      const response = await listNotifications();
      setNotifications(response.items);
    } finally {
      setNotificationsLoading(false);
    }
  };

  const closeNotifications = () => {
    setNotificationsAnchorEl(null);
  };

  const notificationsOpen = Boolean(notificationsAnchorEl);
  const profileMenuOpen = Boolean(profileAnchorEl);

  const openProfileMenu = (event: React.MouseEvent<HTMLElement>) => {
    setProfileAnchorEl(event.currentTarget);
  };

  const closeProfileMenu = () => {
    setProfileAnchorEl(null);
  };

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  const isDark = themeMode === "dark";
  const appBarBorder = isDark ? "1px solid rgba(126,224,255,0.18)" : "1px solid rgba(148,163,184,0.28)";
  const controlBorder = isDark ? "1px solid rgba(126,224,255,0.28)" : "1px solid rgba(148,163,184,0.42)";
  const controlBackground = isDark ? "rgba(22,36,58,0.55)" : "rgba(255,255,255,0.9)";
  const controlHover = isDark ? "rgba(28,46,72,0.7)" : "rgba(241,245,249,0.98)";

  return (
    <Box
      sx={{
        minHeight: "100vh",
        background:
          isDark
            ? "radial-gradient(130% 80% at 0% 0%, rgba(110,168,254,0.18) 0%, rgba(11,18,32,1) 55%), radial-gradient(120% 80% at 100% 0%, rgba(126,224,255,0.14) 0%, rgba(11,18,32,0.98) 45%)"
            : "radial-gradient(130% 80% at 0% 0%, rgba(59,130,246,0.14) 0%, rgba(243,246,251,1) 65%), radial-gradient(120% 80% at 100% 0%, rgba(34,197,94,0.08) 0%, rgba(241,245,249,1) 55%)",
      }}
    >
      <AppBar
        position="sticky"
        elevation={0}
        color="transparent"
        sx={{
          borderBottom: appBarBorder,
          backdropFilter: "blur(10px)",
          backgroundColor: isDark ? "rgba(11,18,32,0.55)" : "rgba(255,255,255,0.72)",
        }}
      >
        <Toolbar sx={{ py: 1 }}>
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
            <Stack spacing={0}>
              <Typography variant="h5" fontWeight={700} letterSpacing={0.2}>
                Pentest Collaboration Framework
              </Typography>
            </Stack>
            <Stack direction="row" spacing={1.5} alignItems="center">
              <IconButton
                color="inherit"
                onClick={onToggleTheme}
                sx={{
                  border: controlBorder,
                  borderRadius: 2,
                  width: 44,
                  height: 44,
                  backgroundColor: controlBackground,
                  "&:hover": {
                    backgroundColor: controlHover,
                  },
                }}
              >
                {themeMode === "dark" ? <LightModeIcon /> : <DarkModeIcon />}
              </IconButton>
              <IconButton
                color="inherit"
                onClick={openNotifications}
                sx={{
                  border: controlBorder,
                  borderRadius: 2,
                  width: 44,
                  height: 44,
                  backgroundColor: controlBackground,
                  "&:hover": {
                    backgroundColor: controlHover,
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
                  border: controlBorder,
                  borderRadius: 2,
                  textTransform: "none",
                  px: 1.4,
                  py: 0,
                  height: 44,
                  minHeight: 44,
                  minWidth: 220,
                  justifyContent: "flex-end",
                  backgroundColor: controlBackground,
                  "&:hover": {
                    backgroundColor: controlHover,
                  },
                }}
              >
                <Stack direction="row" spacing={1.2} alignItems="center" justifyContent="flex-end" sx={{ width: "100%" }}>
                  <Avatar sx={{ width: 30, height: 30, bgcolor: "primary.main" }}>{user.username[0]?.toUpperCase()}</Avatar>
                  <Stack spacing={0} sx={{ flex: 1, minWidth: 0 }}>
                    <Typography color="text.primary" textAlign="right" noWrap>
                      {user.username}
                    </Typography>
                    <Typography variant="caption" color="text.secondary" textAlign="right" noWrap>
                      {user.role === "admin" ? "Администратор" : "Пентестер"}
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
              width: 220,
            },
          },
        }}
      >
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
          py: 3,
          px: { xs: 2, md: 3 },
          maxWidth: "min(1800px, 100vw)",
        }}
      >
        <Routes>
          <Route
            path="/"
            element={
              <Paper
                sx={{
                  p: { xs: 2, md: 3 },
                  borderRadius: 0,
                  backgroundColor: themeMode === "dark" ? "rgba(18,29,49,0.68)" : "rgba(255,255,255,0.8)",
                  boxShadow: themeMode === "dark" ? undefined : "0 8px 30px rgba(15, 23, 42, 0.08)",
                }}
              >
                <ProjectsPage />
              </Paper>
            }
          />
          <Route path="/projects/:projectId" element={<ProjectDetailPage />} />
          <Route path="/projects/:projectId/hosts/:hostId" element={<HostDetailPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Container>
    </Box>
  );
}

type AppProps = {
  themeMode: PaletteMode;
  onToggleTheme: () => void;
};

export default function App({ themeMode, onToggleTheme }: AppProps) {
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
      <Route path="/login" element={user ? <Navigate to="/" replace /> : <LoginPage />} />
      <Route path="/*" element={<PrivateLayout themeMode={themeMode} onToggleTheme={onToggleTheme} />} />
    </Routes>
  );
}
