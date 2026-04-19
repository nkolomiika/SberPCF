import PhotoCameraIcon from "@mui/icons-material/PhotoCamera";
import { Avatar, Box, Button, Card, CardContent, Chip, Stack, TextField, Typography } from "@mui/material";
import { useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { changeMyPassword, getApiErrorMessage, updateMyProfile, uploadMyAvatar } from "../api";
import { useAuthStore } from "../store";
import { useErrorToast, useToastMessage } from "../useErrorToast";

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
  const [tagsText, setTagsText] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
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
    setTagsText(user.tags.join(", "));
  }, [user]);

  const tagsPreview = useMemo(
    () =>
      tagsText
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean),
    [tagsText]
  );

  if (!user) {
    return null;
  }

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
          <TextField
            label="Теги"
            value={tagsText}
            onChange={(event) => setTagsText(event.target.value)}
            helperText="Укажи теги через запятую, например: teamlead, web, internal"
            fullWidth
          />
          <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
            {tagsPreview.map((tag) => (
              <Chip key={tag} label={tag} size="small" />
            ))}
          </Stack>
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
                  tags: tagsPreview,
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
          <TextField
            label="Текущий пароль"
            type="password"
            value={currentPassword}
            onChange={(event) => setCurrentPassword(event.target.value)}
            fullWidth
          />
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
          <Box>
            <Button
              variant="contained"
              disabled={savingPassword || !currentPassword || newPassword.length < 8 || newPassword !== confirmPassword}
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
      <Stack spacing={0.5}>
        <Typography variant="h4" fontWeight={700}>
          Профиль
        </Typography>
        <Typography color="text.secondary">Личные данные, фото, теги и пароль.</Typography>
      </Stack>
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
