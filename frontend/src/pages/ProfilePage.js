import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
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
    const fileInputRef = useRef(null);
    const [infoMessage, setInfoMessage] = useState(null);
    const [error, setError] = useState(null);
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
    const tagsPreview = useMemo(() => tagsText
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean), [tagsText]);
    if (!user) {
        return null;
    }
    const profileSection = (_jsx(Card, { sx: { borderRadius: 0 }, children: _jsx(CardContent, { sx: { p: 3 }, children: _jsxs(Stack, { spacing: 2.5, children: [_jsxs(Stack, { direction: { xs: "column", md: "row" }, spacing: 2, alignItems: { xs: "flex-start", md: "center" }, children: [_jsx(Avatar, { src: user.avatar_url ?? undefined, sx: { width: 80, height: 80 }, children: (user.full_name || user.username)[0]?.toUpperCase() }), _jsxs(Stack, { spacing: 1, children: [_jsx(Typography, { variant: "h5", fontWeight: 700, children: user.full_name || user.username }), _jsx(Typography, { color: "text.secondary", children: user.email }), _jsxs(Box, { children: [_jsx("input", { ref: fileInputRef, type: "file", accept: "image/png,image/jpeg,image/webp,image/gif", hidden: true, onChange: (event) => {
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
                                                } }), _jsx(Button, { variant: "outlined", startIcon: _jsx(PhotoCameraIcon, {}), onClick: () => fileInputRef.current?.click(), disabled: uploadingAvatar, children: uploadingAvatar ? "Загрузка..." : "Изменить фото" })] })] })] }), _jsx(TextField, { label: "\u041E\u0442\u043E\u0431\u0440\u0430\u0436\u0430\u0435\u043C\u043E\u0435 \u0438\u043C\u044F", value: fullName, onChange: (event) => setFullName(event.target.value), fullWidth: true }), _jsx(TextField, { label: "\u041B\u043E\u0433\u0438\u043D", value: username, onChange: (event) => setUsername(event.target.value), fullWidth: true }), _jsx(TextField, { label: "Email", value: email, onChange: (event) => setEmail(event.target.value), fullWidth: true }), _jsx(TextField, { label: "\u0422\u0435\u0433\u0438", value: tagsText, onChange: (event) => setTagsText(event.target.value), helperText: "\u0423\u043A\u0430\u0436\u0438 \u0442\u0435\u0433\u0438 \u0447\u0435\u0440\u0435\u0437 \u0437\u0430\u043F\u044F\u0442\u0443\u044E, \u043D\u0430\u043F\u0440\u0438\u043C\u0435\u0440: teamlead, web, internal", fullWidth: true }), _jsx(Stack, { direction: "row", spacing: 1, flexWrap: "wrap", useFlexGap: true, children: tagsPreview.map((tag) => (_jsx(Chip, { label: tag, size: "small" }, tag))) }), _jsx(Box, { children: _jsx(Button, { variant: "contained", disabled: savingProfile || !username.trim() || !email.trim(), onClick: () => {
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
                            }, children: savingProfile ? "Сохранение..." : "Сохранить профиль" }) })] }) }) }));
    const passwordSection = (_jsx(Card, { sx: { borderRadius: 0 }, children: _jsx(CardContent, { sx: { p: 3 }, children: _jsxs(Stack, { spacing: 2.5, children: [_jsx(Typography, { variant: "h5", fontWeight: 700, children: "\u0421\u043C\u0435\u043D\u0430 \u043F\u0430\u0440\u043E\u043B\u044F" }), _jsx(TextField, { label: "\u0422\u0435\u043A\u0443\u0449\u0438\u0439 \u043F\u0430\u0440\u043E\u043B\u044C", type: "password", value: currentPassword, onChange: (event) => setCurrentPassword(event.target.value), fullWidth: true }), _jsx(TextField, { label: "\u041D\u043E\u0432\u044B\u0439 \u043F\u0430\u0440\u043E\u043B\u044C", type: "password", value: newPassword, onChange: (event) => setNewPassword(event.target.value), fullWidth: true }), _jsx(TextField, { label: "\u041F\u043E\u0434\u0442\u0432\u0435\u0440\u0434\u0438\u0442\u0435 \u043F\u0430\u0440\u043E\u043B\u044C", type: "password", value: confirmPassword, onChange: (event) => setConfirmPassword(event.target.value), error: Boolean(confirmPassword && newPassword !== confirmPassword), helperText: confirmPassword && newPassword !== confirmPassword ? "Пароли не совпадают" : " ", fullWidth: true }), _jsx(Box, { children: _jsx(Button, { variant: "contained", disabled: savingPassword || !currentPassword || newPassword.length < 8 || newPassword !== confirmPassword, onClick: () => {
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
                            }, children: savingPassword ? "Смена..." : "Сменить пароль" }) })] }) }) }));
    return (_jsxs(Stack, { spacing: 2.5, children: [_jsxs(Stack, { spacing: 0.5, children: [_jsx(Typography, { variant: "h4", fontWeight: 700, children: "\u041F\u0440\u043E\u0444\u0438\u043B\u044C" }), _jsx(Typography, { color: "text.secondary", children: "\u041B\u0438\u0447\u043D\u044B\u0435 \u0434\u0430\u043D\u043D\u044B\u0435, \u0444\u043E\u0442\u043E, \u0442\u0435\u0433\u0438 \u0438 \u043F\u0430\u0440\u043E\u043B\u044C." })] }), passwordFirst ? (_jsxs(_Fragment, { children: [passwordSection, profileSection] })) : (_jsxs(_Fragment, { children: [profileSection, passwordSection] }))] }));
}
