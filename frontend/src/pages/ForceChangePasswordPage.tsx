import { Alert, Box, Button, Paper, Stack, TextField, Typography } from "@mui/material";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { forceChangePassword } from "../api";
import { useAuthStore } from "../store";

export function ForceChangePasswordPage() {
  const navigate = useNavigate();
  const user = useAuthStore((s) => s.user);
  const setUser = useAuthStore((s) => s.setUser);
  const signOut = useAuthStore((s) => s.signOut);
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  if (!user) {
    return null;
  }

  return (
    <Box display="flex" minHeight="70vh" alignItems="center" justifyContent="center">
      <Paper elevation={0} sx={{ width: 520, maxWidth: "100%", p: 4, borderRadius: 0 }}>
        <Stack spacing={2.5}>
          <Stack spacing={0.5}>
            <Typography variant="h4" fontWeight={700}>
              Смените пароль
            </Typography>
            <Typography color="text.secondary">
              Для пользователя {user.username} выдан временный пароль. Перед началом работы нужно задать новый.
            </Typography>
          </Stack>
          {error && <Alert severity="error">{error}</Alert>}
          <TextField label="Новый пароль" type="password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} fullWidth />
          <TextField
            label="Подтвердите пароль"
            type="password"
            value={confirmPassword}
            onChange={(event) => setConfirmPassword(event.target.value)}
            error={Boolean(confirmPassword && newPassword !== confirmPassword)}
            helperText={confirmPassword && newPassword !== confirmPassword ? "Пароли не совпадают" : " "}
            fullWidth
          />
          <Stack direction="row" spacing={1.5}>
            <Button
              variant="contained"
              disabled={saving || newPassword.length < 8 || newPassword !== confirmPassword}
              onClick={() => {
                setSaving(true);
                setError(null);
                void forceChangePassword(newPassword)
                  .then((updatedUser) => {
                    setUser(updatedUser);
                    navigate("/", { replace: true });
                  })
                  .catch((submitError) => {
                    setError(submitError instanceof Error ? submitError.message : "Не удалось сменить пароль.");
                  })
                  .finally(() => setSaving(false));
              }}
            >
              {saving ? "Сохранение..." : "Сохранить пароль"}
            </Button>
            <Button
              variant="outlined"
              onClick={() => {
                void signOut();
                navigate("/login", { replace: true });
              }}
            >
              Выйти
            </Button>
          </Stack>
        </Stack>
      </Paper>
    </Box>
  );
}
