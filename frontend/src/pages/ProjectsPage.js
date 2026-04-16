import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import AddIcon from "@mui/icons-material/Add";
import DeleteOutlineIcon from "@mui/icons-material/DeleteOutline";
import FolderOpenIcon from "@mui/icons-material/FolderOpen";
import { Alert, Box, Button, Dialog, DialogActions, DialogContent, DialogTitle, Divider, List, ListItemButton, ListItemIcon, ListItemText, MenuItem, Stack, TextField, Typography, IconButton, Tooltip, } from "@mui/material";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { createProject, deleteProject, getProjects } from "../api";
import { useAuthStore } from "../store";
export function ProjectsPage() {
    const navigate = useNavigate();
    const user = useAuthStore((s) => s.user);
    const [projects, setProjects] = useState([]);
    const [error, setError] = useState(null);
    const [createOpen, setCreateOpen] = useState(false);
    const [name, setName] = useState("");
    const [description, setDescription] = useState("");
    const [startDate, setStartDate] = useState("");
    const [endDate, setEndDate] = useState("");
    const [searchQuery, setSearchQuery] = useState("");
    const [statusFilter, setStatusFilter] = useState("all");
    const [sortBy, setSortBy] = useState("start_date_desc");
    const domNestingLogSentRef = useRef(false);
    const loadProjects = useCallback(async () => {
        try {
            const response = await getProjects(1, 200, statusFilter === "all" ? undefined : statusFilter);
            if (!response || !Array.isArray(response.items)) {
                throw new Error("projects payload shape is invalid");
            }
            setProjects(response.items);
        }
        catch {
            setError("Не удалось загрузить проекты");
        }
    }, [statusFilter]);
    useEffect(() => {
        void loadProjects();
    }, [loadProjects]);
    const visibleProjects = useMemo(() => {
        const normalizedQuery = searchQuery.trim().toLowerCase();
        const filtered = normalizedQuery
            ? projects.filter((project) => {
                const haystack = `${project.name} ${project.description ?? ""}`.toLowerCase();
                return haystack.includes(normalizedQuery);
            })
            : projects;
        const statusWeight = {
            active: 0,
            completed: 1,
            archived: 2,
        };
        return [...filtered].sort((left, right) => {
            if (sortBy === "status_asc") {
                return statusWeight[left.status] - statusWeight[right.status];
            }
            if (sortBy === "status_desc") {
                return statusWeight[right.status] - statusWeight[left.status];
            }
            const leftTs = left.start_date ? Date.parse(left.start_date) : 0;
            const rightTs = right.start_date ? Date.parse(right.start_date) : 0;
            if (sortBy === "start_date_asc") {
                return leftTs - rightTs;
            }
            return rightTs - leftTs;
        });
    }, [projects, searchQuery, sortBy]);
    useEffect(() => {
        if (domNestingLogSentRef.current) {
            return;
        }
        domNestingLogSentRef.current = true;
        // #region agent log
        fetch("http://127.0.0.1:7847/ingest/092a8b93-589d-44d5-a2a5-67f255084dee", {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "a74592" },
            body: JSON.stringify({
                sessionId: "a74592",
                runId: "dom-nesting-pre-fix",
                hypothesisId: "H6",
                location: "ProjectsPage.tsx:ListItemText-secondary",
                message: "ProjectsPage secondary content shape",
                data: {
                    visibleProjectsCount: visibleProjects.length,
                    hasStackInSecondary: true,
                    hasTypographyBody2InSecondary: true,
                    secondaryTypographyPropsConfigured: false,
                },
                timestamp: Date.now(),
            }),
        }).catch(() => { });
        // #endregion
    }, [visibleProjects.length]);
    useEffect(() => {
        // #region agent log
        fetch("http://127.0.0.1:7847/ingest/092a8b93-589d-44d5-a2a5-67f255084dee", {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "a74592" },
            body: JSON.stringify({
                sessionId: "a74592",
                runId: "dom-nesting-post-fix",
                hypothesisId: "H10",
                location: "ProjectsPage.tsx:post-fix-secondaryTypographyProps",
                message: "Post-fix ListItemText secondary typography config",
                data: {
                    secondaryTypographyComponent: "div",
                    warningExpected: false,
                    visibleProjectsCount: visibleProjects.length,
                },
                timestamp: Date.now(),
            }),
        }).catch(() => { });
        // #endregion
    }, [visibleProjects.length]);
    const handleCreate = async () => {
        setError(null);
        if (startDate && endDate && startDate > endDate) {
            setError("Дата окончания проекта не может быть раньше даты начала");
            return;
        }
        try {
            await createProject({
                name: name.trim(),
                description: description.trim() || undefined,
                start_date: startDate || undefined,
                end_date: endDate || undefined,
            });
            setCreateOpen(false);
            setName("");
            setDescription("");
            setStartDate("");
            setEndDate("");
            await loadProjects();
        }
        catch {
            setError("Не удалось создать проект");
        }
    };
    const handleDeleteProject = async (projectId, projectName) => {
        if (!window.confirm(`Удалить проект "${projectName}"?`)) {
            return;
        }
        setError(null);
        try {
            await deleteProject(projectId);
            await loadProjects();
        }
        catch {
            setError("Не удалось удалить проект");
        }
    };
    return (_jsxs(Stack, { spacing: 3, children: [_jsxs(Stack, { direction: "row", justifyContent: "space-between", alignItems: "center", children: [_jsxs(Box, { children: [_jsx(Typography, { variant: "h4", fontWeight: 700, children: "\u041F\u0440\u043E\u0435\u043A\u0442\u044B" }), _jsx(Typography, { color: "text.secondary", children: "\u0423\u043F\u0440\u0430\u0432\u043B\u044F\u0439\u0442\u0435 \u043F\u0435\u043D\u0442\u0435\u0441\u0442-\u043F\u0440\u043E\u0435\u043A\u0442\u0430\u043C\u0438 \u0438 \u0440\u0430\u0431\u043E\u0447\u0438\u043C\u0438 \u043A\u043E\u043C\u0430\u043D\u0434\u0430\u043C\u0438" })] }), user?.role === "admin" && (_jsx(Button, { variant: "contained", startIcon: _jsx(AddIcon, {}), onClick: () => setCreateOpen(true), children: "\u041D\u043E\u0432\u044B\u0439 \u043F\u0440\u043E\u0435\u043A\u0442" }))] }), error && _jsx(Alert, { severity: "error", children: error }), _jsxs(Stack, { direction: { xs: "column", md: "row" }, spacing: 1.5, children: [_jsx(TextField, { label: "\u041F\u043E\u0438\u0441\u043A \u043F\u0440\u043E\u0435\u043A\u0442\u0430", placeholder: "\u041D\u0430\u0437\u0432\u0430\u043D\u0438\u0435 \u0438\u043B\u0438 \u043E\u043F\u0438\u0441\u0430\u043D\u0438\u0435", value: searchQuery, onChange: (event) => setSearchQuery(event.target.value), fullWidth: true }), _jsxs(TextField, { select: true, label: "\u0421\u0442\u0430\u0442\u0443\u0441", value: statusFilter, onChange: (event) => setStatusFilter(event.target.value), sx: { minWidth: 200 }, children: [_jsx(MenuItem, { value: "all", children: "\u0412\u0441\u0435 \u0441\u0442\u0430\u0442\u0443\u0441\u044B" }), _jsx(MenuItem, { value: "active", children: "active" }), _jsx(MenuItem, { value: "completed", children: "completed" }), _jsx(MenuItem, { value: "archived", children: "archived" })] }), _jsxs(TextField, { select: true, label: "\u0421\u043E\u0440\u0442\u0438\u0440\u043E\u0432\u043A\u0430", value: sortBy, onChange: (event) => setSortBy(event.target.value), sx: { minWidth: 260 }, children: [_jsx(MenuItem, { value: "start_date_desc", children: "\u0414\u0430\u0442\u0430 \u043D\u0430\u0447\u0430\u043B\u0430: \u043D\u043E\u0432\u044B\u0435 \u0441\u0432\u0435\u0440\u0445\u0443" }), _jsx(MenuItem, { value: "start_date_asc", children: "\u0414\u0430\u0442\u0430 \u043D\u0430\u0447\u0430\u043B\u0430: \u0441\u0442\u0430\u0440\u044B\u0435 \u0441\u0432\u0435\u0440\u0445\u0443" }), _jsx(MenuItem, { value: "status_asc", children: "\u0421\u0442\u0430\u0442\u0443\u0441: active \u2192 archived" }), _jsx(MenuItem, { value: "status_desc", children: "\u0421\u0442\u0430\u0442\u0443\u0441: archived \u2192 active" })] })] }), _jsx(List, { disablePadding: true, sx: { border: "1px solid rgba(126,224,255,0.18)" }, children: visibleProjects.map((project, index) => (_jsxs(Box, { children: [_jsxs(Stack, { direction: "row", alignItems: "center", justifyContent: "space-between", children: [_jsxs(ListItemButton, { sx: { py: 1.5, flex: 1 }, onClick: () => navigate(`/projects/${project.id}`), children: [_jsx(ListItemIcon, { sx: { minWidth: 36 }, children: _jsx(FolderOpenIcon, { color: "primary" }) }), _jsx(ListItemText, { primary: project.name, secondaryTypographyProps: { component: "div" }, secondary: _jsxs(Stack, { direction: { xs: "column", md: "row" }, spacing: { xs: 0.5, md: 2 }, alignItems: { md: "center" }, children: [_jsx(Typography, { variant: "body2", color: "text.secondary", children: project.description || "Без описания" }), _jsxs(Typography, { variant: "caption", color: "text.secondary", children: ["\u0421\u0442\u0430\u0442\u0443\u0441: ", project.status] }), _jsxs(Typography, { variant: "caption", color: "text.secondary", children: ["\u0421\u0442\u0430\u0440\u0442: ", project.start_date || "не задана"] })] }) })] }), user?.role === "admin" && (_jsx(Tooltip, { title: "\u0423\u0434\u0430\u043B\u0438\u0442\u044C \u043F\u0440\u043E\u0435\u043A\u0442", children: _jsx(IconButton, { color: "error", sx: { mr: 1 }, onClick: (event) => {
                                            event.stopPropagation();
                                            void handleDeleteProject(project.id, project.name);
                                        }, children: _jsx(DeleteOutlineIcon, {}) }) }))] }), index < visibleProjects.length - 1 && _jsx(Divider, {})] }, project.id))) }), _jsxs(Dialog, { open: createOpen, onClose: () => setCreateOpen(false), fullWidth: true, children: [_jsx(DialogTitle, { children: "\u0421\u043E\u0437\u0434\u0430\u0442\u044C \u043F\u0440\u043E\u0435\u043A\u0442" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [_jsx(TextField, { label: "\u041D\u0430\u0437\u0432\u0430\u043D\u0438\u0435", value: name, onChange: (e) => setName(e.target.value) }), _jsx(TextField, { label: "\u041E\u043F\u0438\u0441\u0430\u043D\u0438\u0435", multiline: true, minRows: 3, value: description, onChange: (e) => setDescription(e.target.value) }), _jsx(TextField, { label: "\u0414\u0430\u0442\u0430 \u043D\u0430\u0447\u0430\u043B\u0430", type: "date", value: startDate, onChange: (e) => setStartDate(e.target.value), InputLabelProps: { shrink: true } }), _jsx(TextField, { label: "\u0414\u0430\u0442\u0430 \u043E\u043A\u043E\u043D\u0447\u0430\u043D\u0438\u044F", type: "date", value: endDate, onChange: (e) => setEndDate(e.target.value), InputLabelProps: { shrink: true } })] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => {
                                    setCreateOpen(false);
                                    setName("");
                                    setDescription("");
                                    setStartDate("");
                                    setEndDate("");
                                }, children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", onClick: () => void handleCreate(), disabled: !name.trim(), children: "\u0421\u043E\u0437\u0434\u0430\u0442\u044C" })] })] })] }));
}
