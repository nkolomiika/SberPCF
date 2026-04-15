import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import AddIcon from "@mui/icons-material/Add";
import FolderOpenIcon from "@mui/icons-material/FolderOpen";
import { Alert, Box, Button, Card, CardContent, Dialog, DialogActions, DialogContent, DialogTitle, Grid2 as Grid, Stack, TextField, Typography, } from "@mui/material";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { createProject, getProjects } from "../api";
import { useAuthStore } from "../store";
export function ProjectsPage() {
    const navigate = useNavigate();
    const user = useAuthStore((s) => s.user);
    const [projects, setProjects] = useState([]);
    const [error, setError] = useState(null);
    const [createOpen, setCreateOpen] = useState(false);
    const [name, setName] = useState("");
    const [description, setDescription] = useState("");
    const loadProjects = async () => {
        try {
            const response = await getProjects();
            if (!response || !Array.isArray(response.items)) {
                throw new Error("projects payload shape is invalid");
            }
            setProjects(response.items);
        }
        catch {
            setError("Не удалось загрузить проекты");
        }
    };
    useEffect(() => {
        void loadProjects();
    }, []);
    const handleCreate = async () => {
        await createProject({ name, description });
        setCreateOpen(false);
        setName("");
        setDescription("");
        await loadProjects();
    };
    return (_jsxs(Stack, { spacing: 3, children: [_jsxs(Stack, { direction: "row", justifyContent: "space-between", alignItems: "center", children: [_jsxs(Box, { children: [_jsx(Typography, { variant: "h4", fontWeight: 700, children: "\u041F\u0440\u043E\u0435\u043A\u0442\u044B" }), _jsx(Typography, { color: "text.secondary", children: "\u0423\u043F\u0440\u0430\u0432\u043B\u044F\u0439\u0442\u0435 \u043F\u0435\u043D\u0442\u0435\u0441\u0442-\u043F\u0440\u043E\u0435\u043A\u0442\u0430\u043C\u0438 \u0438 \u0440\u0430\u0431\u043E\u0447\u0438\u043C\u0438 \u043A\u043E\u043C\u0430\u043D\u0434\u0430\u043C\u0438" })] }), user?.role === "admin" && (_jsx(Button, { variant: "contained", startIcon: _jsx(AddIcon, {}), onClick: () => setCreateOpen(true), children: "\u041D\u043E\u0432\u044B\u0439 \u043F\u0440\u043E\u0435\u043A\u0442" }))] }), error && _jsx(Alert, { severity: "error", children: error }), _jsx(Grid, { container: true, spacing: 2, children: projects.map((project) => (_jsx(Grid, { size: { xs: 12, md: 6, lg: 4 }, children: _jsx(Card, { sx: { cursor: "pointer", border: "1px solid #2a3c5f", height: "100%" }, onClick: () => navigate(`/projects/${project.id}`), children: _jsx(CardContent, { children: _jsxs(Stack, { spacing: 1, children: [_jsxs(Stack, { direction: "row", spacing: 1, alignItems: "center", children: [_jsx(FolderOpenIcon, { color: "primary" }), _jsx(Typography, { variant: "h6", children: project.name })] }), _jsx(Typography, { color: "text.secondary", children: project.description || "Без описания" }), _jsxs(Typography, { variant: "body2", color: "text.secondary", children: ["\u0421\u0442\u0430\u0442\u0443\u0441: ", project.status] })] }) }) }) }, project.id))) }), _jsxs(Dialog, { open: createOpen, onClose: () => setCreateOpen(false), fullWidth: true, children: [_jsx(DialogTitle, { children: "\u0421\u043E\u0437\u0434\u0430\u0442\u044C \u043F\u0440\u043E\u0435\u043A\u0442" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [_jsx(TextField, { label: "\u041D\u0430\u0437\u0432\u0430\u043D\u0438\u0435", value: name, onChange: (e) => setName(e.target.value) }), _jsx(TextField, { label: "\u041E\u043F\u0438\u0441\u0430\u043D\u0438\u0435", multiline: true, minRows: 3, value: description, onChange: (e) => setDescription(e.target.value) })] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setCreateOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", onClick: () => void handleCreate(), disabled: !name.trim(), children: "\u0421\u043E\u0437\u0434\u0430\u0442\u044C" })] })] })] }));
}
