import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import RadioButtonUncheckedIcon from "@mui/icons-material/RadioButtonUnchecked";
import VisibilityIcon from "@mui/icons-material/Visibility";
import VisibilityOffIcon from "@mui/icons-material/VisibilityOff";
import { Box, Button, IconButton, InputAdornment, Paper, Stack, TextField, Typography } from "@mui/material";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { forceChangePassword, getApiErrorMessage } from "../api";
import { useAuthStore } from "../store";
import { useErrorToast } from "../useErrorToast";

const PASSWORD_MIN_LENGTH = 8;
const PASSWORD_MAX_LENGTH = 128;

type Rule = { id: string; label: string; check: (value: string) => boolean };

const PASSWORD_RULES: Rule[] = [
  {
    id: "length",
    label: `От ${PASSWORD_MIN_LENGTH} до ${PASSWORD_MAX_LENGTH} символов`,
    check: (value) => value.length >= PASSWORD_MIN_LENGTH && value.length <= PASSWORD_MAX_LENGTH,
  },
  {
    id: "letter",
    label: "Содержит букву",
    check: (value) => /[A-Za-zА-Яа-яЁё]/.test(value),
  },
  {
    id: "digit",
    label: "Содержит цифру",
    check: (value) => /\d/.test(value),
  },
];

function PolicyChecklist({ value }: { value: string }) {
  return (
    <Stack spacing={0.4} sx={{ pt: 0.25 }}>
      {PASSWORD_RULES.map((rule) => {
        const passed = rule.check(value);
        return (
          <Stack key={rule.id} direction="row" spacing={0.8} alignItems="center">
            {passed ? (
              <CheckCircleIcon fontSize="small" sx={{ color: "#4ADE80" }} />
            ) : (
              <RadioButtonUncheckedIcon fontSize="small" sx={{ color: "text.disabled" }} />
            )}
            <Typography variant="caption" sx={{ color: passed ? "#4ADE80" : "text.secondary" }}>
              {rule.label}
            </Typography>
          </Stack>
        );
      })}
    </Stack>
  );
}

function renderPasswordToggle(value: string, show: boolean, onToggle: () => void) {
  if (!value) {
    return undefined;
  }
  return (
    <InputAdornment position="end">
      <IconButton
        aria-label={show ? "Скрыть пароль" : "Показать пароль"}
        onClick={onToggle}
        edge="end"
        size="small"
      >
        {show ? <VisibilityOffIcon fontSize="small" /> : <VisibilityIcon fontSize="small" />}
      </IconButton>
    </InputAdornment>
  );
}

export function ForceChangePasswordPage() {
  const navigate = useNavigate();
  const user = useAuthStore((s) => s.user);
  const setUser = useAuthStore((s) => s.setUser);
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useErrorToast(error);

  if (!user) {
    return null;
  }

  const newPasswordTooLong = newPassword.length > PASSWORD_MAX_LENGTH;
  const passwordsMismatch = confirmPassword.length > 0 && newPassword !== confirmPassword;
  const allRulesPassed = PASSWORD_RULES.every((rule) => rule.check(newPassword));

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
          <PolicyChecklist value={newPassword} />
          <TextField
            label="Новый пароль"
            type={showNewPassword ? "text" : "password"}
            value={newPassword}
            onChange={(event) => setNewPassword(event.target.value)}
            error={newPasswordTooLong}
            helperText={newPasswordTooLong ? `Максимум ${PASSWORD_MAX_LENGTH} символов` : " "}
            fullWidth
            slotProps={{
              input: {
                endAdornment: renderPasswordToggle(newPassword, showNewPassword, () =>
                  setShowNewPassword((prev) => !prev)
                ),
              },
            }}
          />
          <TextField
            label="Подтвердите пароль"
            type={showConfirmPassword ? "text" : "password"}
            value={confirmPassword}
            onChange={(event) => setConfirmPassword(event.target.value)}
            error={passwordsMismatch}
            helperText={passwordsMismatch ? "Пароли не совпадают" : " "}
            fullWidth
            slotProps={{
              input: {
                endAdornment: renderPasswordToggle(confirmPassword, showConfirmPassword, () =>
                  setShowConfirmPassword((prev) => !prev)
                ),
              },
            }}
          />
          <Stack direction="row" spacing={1.5}>
            <Button
              variant="contained"
              disabled={saving || !allRulesPassed || newPassword !== confirmPassword}
              onClick={() => {
                setSaving(true);
                setError(null);
                void forceChangePassword(newPassword)
                  .then((updatedUser) => {
                    setUser(updatedUser);
                    navigate("/", { replace: true });
                  })
                  .catch((submitError) => {
                    setError(getApiErrorMessage(submitError, "Не удалось сменить пароль."));
                  })
                  .finally(() => setSaving(false));
              }}
            >
              {saving ? "Сохранение..." : "Сохранить пароль"}
            </Button>
          </Stack>
        </Stack>
      </Paper>
    </Box>
  );
}
