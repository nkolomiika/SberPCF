import { Alert, Box, Button, Paper, Stack, TextField, Typography } from "@mui/material";
import { type FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuthStore } from "../store";

export function LoginPage() {
  const navigate = useNavigate();
  const signIn = useAuthStore((s) => s.signIn);
  const isLoading = useAuthStore((s) => s.isLoading);
  const error = useAuthStore((s) => s.error);
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("admin");

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    await signIn(username, password);
    navigate("/");
  };

  return (
    <Box
      display="flex"
      minHeight="100vh"
      alignItems="center"
      justifyContent="center"
      sx={{
        p: 2,
        background: "linear-gradient(180deg, #08111F 0%, #0B1220 100%)",
      }}
    >
      <Paper elevation={6} sx={{ width: 460, maxWidth: "100%", p: 4.5, borderRadius: 0 }}>
        <Typography variant="overline" color="primary.main" sx={{ letterSpacing: 1.8, fontWeight: 700 }}>
          Pentest Workspace
        </Typography>
        <Typography variant="h4" fontWeight={700} gutterBottom>
          Вход в PCF
        </Typography>
        <Typography color="text.secondary" sx={{ mb: 3 }}>
          Открой проекты, активы и рабочие заметки команды в едином интерфейсе.
        </Typography>
        <Stack component="form" spacing={2} onSubmit={handleSubmit}>
          {error && <Alert severity="error">{error}</Alert>}
          <TextField label="Логин" value={username} onChange={(e) => setUsername(e.target.value)} required />
          <TextField
            label="Пароль"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            type="password"
          />
          <Button disabled={isLoading} type="submit" variant="contained" size="large">
            {isLoading ? "Вход..." : "Войти"}
          </Button>
        </Stack>
      </Paper>
    </Box>
  );
}
