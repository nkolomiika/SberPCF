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
import { Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { listNotifications, unreadCount } from "./api";
import type { Notification } from "./types";
import { useAuthStore } from "./store";
import { LoginPage } from "./pages/LoginPage";
import { HostDetailPage } from "./pages/HostDetailPage";
import { ProjectDetailPage } from "./pages/ProjectDetailPage";
import { ProjectsPage } from "./pages/ProjectsPage";

function PrivateLayout() {
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

  return (
    <Box
      sx={{
        minHeight: "100vh",
        background:
          "radial-gradient(130% 80% at 0% 0%, rgba(110,168,254,0.18) 0%, rgba(11,18,32,1) 55%), radial-gradient(120% 80% at 100% 0%, rgba(126,224,255,0.14) 0%, rgba(11,18,32,0.98) 45%)",
      }}
    >
      <AppBar
        position="sticky"
        elevation={0}
        color="transparent"
        sx={{ borderBottom: "1px solid rgba(126,224,255,0.18)", backdropFilter: "blur(10px)" }}
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
            <Stack spacing={0.2}>
              <Typography variant="h5" fontWeight={700} letterSpacing={0.2}>
                Pentest Collaboration Framework
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Управление проектами и результатами пентеста
              </Typography>
            </Stack>
            <Stack direction="row" spacing={1.5} alignItems="center">
              <IconButton
                color="inherit"
                onClick={openNotifications}
                sx={{
                  border: "1px solid rgba(126,224,255,0.28)",
                  borderRadius: 2,
                  width: 44,
                  height: 44,
                  backgroundColor: "rgba(22,36,58,0.55)",
                  "&:hover": {
                    backgroundColor: "rgba(28,46,72,0.7)",
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
              <Paper sx={{ p: { xs: 2, md: 3 }, borderRadius: 0, backgroundColor: "rgba(18,29,49,0.68)" }}>
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

export default function App() {
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
      <Route path="/*" element={<PrivateLayout />} />
    </Routes>
  );
}
