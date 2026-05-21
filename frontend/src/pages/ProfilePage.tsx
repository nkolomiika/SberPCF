import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import PhotoCameraIcon from "@mui/icons-material/PhotoCamera";
import RadioButtonUncheckedIcon from "@mui/icons-material/RadioButtonUnchecked";
import VisibilityIcon from "@mui/icons-material/Visibility";
import VisibilityOffIcon from "@mui/icons-material/VisibilityOff";
import {
  Avatar,
  Box,
  Button,
  Card,
  CardContent,
  IconButton,
  InputAdornment,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { changeMyPassword, getApiErrorMessage, updateMyProfile, uploadMyAvatar } from "../api";
import { useAuthStore } from "../store";
import { useErrorToast, useToastMessage } from "../useErrorToast";

const PASSWORD_MIN_LENGTH = 8;
const PASSWORD_MAX_LENGTH = 128;

type Rule = { id: string; label: string; check: (value: string, current: string) => boolean };

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
  {
    id: "different",
    label: "Отличается от текущего",
    check: (value, current) => value.length > 0 && value !== current,
  },
];

export function ProfilePage() {
  const user = useAuthStore((s) => s.user);
  const setUser = useAuthStore((s) => s.setUser);
  const [searchParams] = useSearchParams();
  const passwordFirst = searchParams.get("tab") === "password";
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const [infoMessage, setInfoMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [fullName, setFullName] = useState("");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showCurrentPassword, setShowCurrentPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [savingProfile, setSavingProfile] = useState(false);
  const [savingPassword, setSavingPassword] = useState(false);
  const [uploadingAvatar, setUploadingAvatar] = useState(false);

  useErrorToast(error);
  useToastMessage(infoMessage, "success");

  useEffect(() => {
    if (!user) {
      return;
    }
    setFullName(user.full_name ?? "");
    setUsername(user.username);
    setEmail(user.email);
  }, [user]);

  if (!user) {
    return null;
  }

  const newPasswordTooLong = newPassword.length > PASSWORD_MAX_LENGTH;
  const passwordsMismatch = confirmPassword.length > 0 && newPassword !== confirmPassword;
  const allRulesPassed = PASSWORD_RULES.every((rule) => rule.check(newPassword, currentPassword));
  const renderPasswordToggle = (value: string, show: boolean, setShow: (next: boolean) => void) => {
    if (!value) {
      return undefined;
    }
    return (
      <InputAdornment position="end">
        <IconButton
          size="small"
          edge="end"
          aria-label={show ? "Скрыть пароль" : "Показать пароль"}
          onClick={() => setShow(!show)}
        >
          {show ? <VisibilityOffIcon fontSize="small" /> : <VisibilityIcon fontSize="small" />}
        </IconButton>
      </InputAdornment>
    );
  };

  const profileSection = (
    <Card sx={{ borderRadius: 0 }}>
      <CardContent sx={{ p: 3 }}>
        <Stack spacing={2.5}>
          <Stack direction={{ xs: "column", md: "row" }} spacing={2} alignItems={{ xs: "flex-start", md: "center" }}>
            <Avatar src={user.avatar_url ?? undefined} sx={{ width: 80, height: 80 }}>
              {(user.full_name || user.username)[0]?.toUpperCase()}
            </Avatar>
            <Stack spacing={1}>
              <Typography variant="h5" fontWeight={700}>
                {user.full_name || user.username}
              </Typography>
              <Typography color="text.secondary">{user.email}</Typography>
              <Box>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept="image/png,image/jpeg,image/webp,image/gif"
                  hidden
                  onChange={(event) => {
                    const file = event.target.files?.[0];
                    if (!file) {
                      return;
                    }
                    setUploadingAvatar(true);
                    setError(null);
                    setInfoMessage(null);
                    void uploadMyAvatar(file)
                      .then((updatedUser) => {
                        setUser(updatedUser);
                        setInfoMessage("Аватар обновлён.");
                      })
                      .catch((uploadError) => {
                        setError(getApiErrorMessage(uploadError, "Не удалось обновить аватар."));
                      })
                      .finally(() => {
                        setUploadingAvatar(false);
                        if (event.target) {
                          event.target.value = "";
                        }
                      });
                  }}
                />
                <Button variant="outlined" startIcon={<PhotoCameraIcon />} onClick={() => fileInputRef.current?.click()} disabled={uploadingAvatar}>
                  {uploadingAvatar ? "Загрузка..." : "Изменить фото"}
                </Button>
              </Box>
            </Stack>
          </Stack>

          <TextField label="Отображаемое имя" value={fullName} onChange={(event) => setFullName(event.target.value)} fullWidth />
          <TextField label="Логин" value={username} onChange={(event) => setUsername(event.target.value)} fullWidth />
          <TextField label="Email" value={email} onChange={(event) => setEmail(event.target.value)} fullWidth />
          <Box>
            <Button
              variant="contained"
              disabled={savingProfile || !username.trim() || !email.trim()}
              onClick={() => {
                setSavingProfile(true);
                setError(null);
                setInfoMessage(null);
                void updateMyProfile({
                  username: username.trim(),
                  email: email.trim(),
                  full_name: fullName.trim() || undefined,
                })
                  .then((updatedUser) => {
                    setUser(updatedUser);
                    setInfoMessage("Профиль обновлён.");
                  })
                  .catch((updateError) => {
                    setError(getApiErrorMessage(updateError, "Не удалось обновить профиль."));
                  })
                  .finally(() => setSavingProfile(false));
              }}
            >
              {savingProfile ? "Сохранение..." : "Сохранить профиль"}
            </Button>
          </Box>
        </Stack>
      </CardContent>
    </Card>
  );

  const passwordSection = (
    <Card sx={{ borderRadius: 0 }}>
      <CardContent sx={{ p: 3 }}>
        <Stack spacing={2.5}>
          <Typography variant="h5" fontWeight={700}>
            Смена пароля
          </Typography>
          <Stack spacing={0.4}>
            {PASSWORD_RULES.map((rule) => {
              const passed = rule.check(newPassword, currentPassword);
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
          <TextField
            label="Текущий пароль"
            type={showCurrentPassword ? "text" : "password"}
            value={currentPassword}
            onChange={(event) => setCurrentPassword(event.target.value)}
            fullWidth
            slotProps={{
              input: { endAdornment: renderPasswordToggle(currentPassword, showCurrentPassword, setShowCurrentPassword) },
            }}
          />
          <TextField
            label="Новый пароль"
            type={showNewPassword ? "text" : "password"}
            value={newPassword}
            onChange={(event) => setNewPassword(event.target.value)}
            error={newPasswordTooLong}
            helperText={newPasswordTooLong ? `Максимум ${PASSWORD_MAX_LENGTH} символов` : " "}
            fullWidth
            slotProps={{
              input: { endAdornment: renderPasswordToggle(newPassword, showNewPassword, setShowNewPassword) },
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
              input: { endAdornment: renderPasswordToggle(confirmPassword, showConfirmPassword, setShowConfirmPassword) },
            }}
          />
          <Box>
            <Button
              variant="contained"
              disabled={
                savingPassword ||
                !currentPassword ||
                !allRulesPassed ||
                newPassword !== confirmPassword
              }
              onClick={() => {
                setSavingPassword(true);
                setError(null);
                setInfoMessage(null);
                void changeMyPassword({ current_password: currentPassword, new_password: newPassword })
                  .then((updatedUser) => {
                    setUser(updatedUser);
                    setCurrentPassword("");
                    setNewPassword("");
                    setConfirmPassword("");
                    setInfoMessage("Пароль изменён.");
                  })
                  .catch((changeError) => {
                    setError(getApiErrorMessage(changeError, "Не удалось сменить пароль."));
                  })
                  .finally(() => setSavingPassword(false));
              }}
            >
              {savingPassword ? "Смена..." : "Сменить пароль"}
            </Button>
          </Box>
        </Stack>
      </CardContent>
    </Card>
  );

  return (
    <Stack spacing={2.5}>
      <Typography variant="h4" fontWeight={700}>
        Профиль
      </Typography>
      {passwordFirst ? (
        <>
          {passwordSection}
          {profileSection}
        </>
      ) : (
        <>
          {profileSection}
          {passwordSection}
        </>
      )}
    </Stack>
  );
}
