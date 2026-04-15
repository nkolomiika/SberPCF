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
    <Box sx={{ minHeight: "100vh", background: "linear-gradient(180deg,#0f1726 0%, #101d31 100%)" }}>
      <Box sx={{ borderBottom: "1px solid #23314f", backdropFilter: "blur(6px)" }}>
        <Container sx={{ py: 2 }}>
          <Stack direction="row" justifyContent="space-between" alignItems="center">
            <Typography variant="h5" fontWeight={700}>
              Pentest Collaboration Framework
            </Typography>
            <Stack direction="row" spacing={1} alignItems="center">
              <IconButton color="inherit" onClick={() => navigate("/")}>
                <Badge color="error" badgeContent={count}>
                  <NotificationsIcon />
                </Badge>
              </IconButton>
              <Typography color="text.secondary">{user.username}</Typography>
              <Button variant="outlined" onClick={() => void signOut()}>
                Выйти
              </Button>
            </Stack>
          </Stack>
        </Container>
      </Box>
      <Container sx={{ py: 3 }}>
        <Routes>
          <Route path="/" element={<ProjectsPage />} />
          <Route path="/projects/:projectId" element={<ProjectDetailPage />} />
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
