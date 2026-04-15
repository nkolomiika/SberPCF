import { useEffect, useState } from "react";
import {
  AppBar,
  Avatar,
  Badge,
  Box,
  Button,
  CircularProgress,
  Container,
  IconButton,
  Paper,
  Stack,
  Toolbar,
  Typography,
} from "@mui/material";
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
  const [count, setCount] = useState<number>(0);

  useEffect(() => {
    const load = async () => {
      const unread = await unreadCount();
      setCount(unread);
    };
    void load();
  }, []);

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
          <Container sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
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
                onClick={() => navigate("/")}
                sx={{ border: "1px solid rgba(126,224,255,0.2)", borderRadius: 2 }}
              >
                <Badge color="error" badgeContent={count}>
                  <NotificationsIcon />
                </Badge>
              </IconButton>
              <Stack direction="row" spacing={1} alignItems="center">
                <Avatar sx={{ width: 30, height: 30, bgcolor: "primary.main" }}>{user.username[0]?.toUpperCase()}</Avatar>
                <Typography color="text.secondary">{user.username}</Typography>
              </Stack>
              <Button variant="outlined" onClick={() => void signOut()}>
                Выйти
              </Button>
            </Stack>
          </Container>
        </Toolbar>
      </AppBar>
      <Container sx={{ py: 3 }}>
        <Paper sx={{ p: { xs: 2, md: 3 }, borderRadius: 3, backgroundColor: "rgba(18,29,49,0.68)" }}>
          <Routes>
            <Route path="/" element={<ProjectsPage />} />
            <Route path="/projects/:projectId" element={<ProjectDetailPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Paper>
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
