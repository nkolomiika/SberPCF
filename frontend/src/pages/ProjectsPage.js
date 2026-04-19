import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import AddIcon from "@mui/icons-material/Add";
import DeleteOutlineIcon from "@mui/icons-material/DeleteOutline";
import EditIcon from "@mui/icons-material/Edit";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import FolderOpenIcon from "@mui/icons-material/FolderOpen";
import CreateNewFolderIcon from "@mui/icons-material/CreateNewFolder";
import ChevronRightIcon from "@mui/icons-material/ChevronRight";
import DescriptionOutlinedIcon from "@mui/icons-material/DescriptionOutlined";
import MoreVertIcon from "@mui/icons-material/MoreVert";
import { Checkbox, Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogTitle, Divider, List, ListItemButton, ListItemIcon, ListItemText, Menu, MenuItem, Stack, TextField, Typography, IconButton, Tooltip, } from "@mui/material";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { addProjectMember, createProject, createProjectFolder, deleteProject, getApiErrorMessage, getProjectFolders, getProjects, getUsers, moveProjectFolder, updateProject, } from "../api";
import { PROJECT_STATUS_CHIP_SX, PROJECT_STATUS_LABELS, PROJECT_STATUS_ORDER } from "../projectStatus";
import { useAuthStore } from "../store";
import { useErrorToast } from "../useErrorToast";
const DEFAULT_PROJECT_DURATION_DAYS = 14;
const ROOT_FOLDER_LABEL = "Корень";
const ROOT_FOLDER_NODE = { id: null, name: "", path: "", children: [], projects: [] };
const toDateInputValue = (date) => {
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, "0");
    const day = String(date.getDate()).padStart(2, "0");
    return `${year}-${month}-${day}`;
};
const plusDays = (dateString, days) => {
    const base = new Date(`${dateString}T00:00:00`);
    base.setDate(base.getDate() + days);
    return toDateInputValue(base);
};
export function ProjectsPage() {
    const navigate = useNavigate();
    const user = useAuthStore((s) => s.user);
    const [projects, setProjects] = useState([]);
    const [folders, setFolders] = useState([]);
    const [error, setError] = useState(null);
    const [actionsAnchorEl, setActionsAnchorEl] = useState(null);
    const [projectActionsAnchorEl, setProjectActionsAnchorEl] = useState(null);
    const [folderActionsAnchorEl, setFolderActionsAnchorEl] = useState(null);
    const [activeFolderNode, setActiveFolderNode] = useState(null);
    const [activeProject, setActiveProject] = useState(null);
    const [createOpen, setCreateOpen] = useState(false);
    const [editOpen, setEditOpen] = useState(false);
    const [createFolderOpen, setCreateFolderOpen] = useState(false);
    const [folderName, setFolderName] = useState("");
    const [folderParentId, setFolderParentId] = useState("");
    const [name, setName] = useState("");
    const [description, setDescription] = useState("");
    const [startDate, setStartDate] = useState("");
    const [endDate, setEndDate] = useState("");
    const [usersCatalog, setUsersCatalog] = useState([]);
    const [selectedMemberIds, setSelectedMemberIds] = useState([]);
    const [selectedFolder, setSelectedFolder] = useState("");
    const [folderPaths, setFolderPaths] = useState([]);
    const [creatingProject, setCreatingProject] = useState(false);
    const [updatingProject, setUpdatingProject] = useState(false);
    const [creatingFolder, setCreatingFolder] = useState(false);
    const [draggingProjectId, setDraggingProjectId] = useState(null);
    const [draggingFolderId, setDraggingFolderId] = useState(null);
    const [draggingFolderPath, setDraggingFolderPath] = useState(null);
    const [dragOverFolderPath, setDragOverFolderPath] = useState(null);
    const [dropLineTarget, setDropLineTarget] = useState(null);
    const [, setDraggingType] = useState(null);
    const [expandedFolderPaths, setExpandedFolderPaths] = useState([]);
    const [searchQuery, setSearchQuery] = useState("");
    const [statusFilter, setStatusFilter] = useState("all");
    const [editingProjectName, setEditingProjectName] = useState("");
    const [editingProjectId, setEditingProjectId] = useState(null);
    const [editingProjectDescription, setEditingProjectDescription] = useState("");
    const [editingProjectStartDate, setEditingProjectStartDate] = useState("");
    const [editingProjectEndDate, setEditingProjectEndDate] = useState("");
    const [editingProjectStatus, setEditingProjectStatus] = useState("active");
    const [editingProjectFolder, setEditingProjectFolder] = useState("");
    const projectListRef = useRef(null);
    const autoScrollFrameRef = useRef(null);
    const autoScrollVelocityRef = useRef(0);
    const autoExpandTimerRef = useRef(null);
    const autoExpandTargetRef = useRef(null);
    useErrorToast(error);
    const loadProjects = useCallback(async () => {
        try {
            const [projectsResponse, foldersResponse] = await Promise.all([
                getProjects(1, 200, statusFilter === "all" ? undefined : statusFilter),
                getProjectFolders(),
            ]);
            if (!projectsResponse || !Array.isArray(projectsResponse.items)) {
                throw new Error("projects payload shape is invalid");
            }
            setProjects(projectsResponse.items);
            setFolders(Array.isArray(foldersResponse) ? foldersResponse : []);
        }
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось загрузить проекты"));
        }
    }, [statusFilter]);
    useEffect(() => {
        void loadProjects();
    }, [loadProjects]);
    useEffect(() => {
        const wsProtocol = window.location.protocol === "https:" ? "wss" : "ws";
        const ws = new WebSocket(`${wsProtocol}://${window.location.host}/ws/projects-index`);
        ws.onmessage = () => {
            void loadProjects();
        };
        return () => ws.close();
    }, [loadProjects]);
    useEffect(() => {
        const values = [
            ...folders.map((item) => item.path),
            ...projects.map((item) => item.folder),
        ]
            .map((item) => (item || "").trim())
            .filter(Boolean);
        setFolderPaths(Array.from(new Set(values)).sort((a, b) => a.localeCompare(b)));
    }, [folders, projects]);
    const visibleProjects = useMemo(() => {
        const normalizedQuery = searchQuery.trim().toLowerCase();
        return normalizedQuery
            ? projects.filter((project) => {
                const haystack = `${project.name} ${project.description ?? ""}`.toLowerCase();
                return haystack.includes(normalizedQuery);
            })
            : projects;
    }, [projects, searchQuery]);
    const groupedProjects = useMemo(() => {
        const folderByPath = new Map(folders.map((item) => [item.path, item]));
        const root = { id: null, name: "", path: "", children: [], projects: [] };
        const nodeMap = new Map([["", root]]);
        const ensurePath = (pathValue) => {
            const normalizedPath = (pathValue || "").trim();
            if (!normalizedPath) {
                return root;
            }
            const segments = normalizedPath.split("/").filter(Boolean);
            let currentPath = "";
            let parent = root;
            for (const segment of segments) {
                currentPath = currentPath ? `${currentPath}/${segment}` : segment;
                let node = nodeMap.get(currentPath);
                if (!node) {
                    node = { id: folderByPath.get(currentPath)?.id ?? null, name: segment, path: currentPath, children: [], projects: [] };
                    nodeMap.set(currentPath, node);
                    parent.children.push(node);
                }
                else if (!node.id && folderByPath.get(currentPath)?.id) {
                    node.id = folderByPath.get(currentPath).id;
                }
                parent = node;
            }
            return nodeMap.get(normalizedPath) ?? root;
        };
        for (const pathValue of folderPaths) {
            ensurePath(pathValue);
        }
        for (const project of visibleProjects) {
            const target = ensurePath(project.folder);
            target.projects.push(project);
        }
        const sortTree = (node) => {
            node.children.sort((left, right) => left.name.localeCompare(right.name));
            node.projects.sort((left, right) => left.name.localeCompare(right.name));
            node.children.forEach(sortTree);
        };
        sortTree(root);
        return root.children;
    }, [folderPaths, folders, visibleProjects]);
    const folderPathById = useMemo(() => {
        return new Map(folders.map((folder) => [folder.id, folder.path]));
    }, [folders]);
    const treeStats = useMemo(() => {
        const totalProjects = visibleProjects.length;
        const totalFolders = folders.length;
        const nestedFolders = folders.filter((folder) => folder.parent_id).length;
        return { totalProjects, totalFolders, nestedFolders };
    }, [folders, visibleProjects]);
    useEffect(() => {
        if (!createOpen || user?.role !== "admin") {
            return;
        }
        const loadUsers = async () => {
            try {
                const response = await getUsers(1, 200);
                setUsersCatalog(response.items);
            }
            catch (error) {
                setError(getApiErrorMessage(error, "Не удалось загрузить список пользователей"));
            }
        };
        void loadUsers();
    }, [createOpen, user?.role]);
    const handleCreate = async () => {
        setError(null);
        const today = toDateInputValue(new Date());
        const effectiveStartDate = startDate || today;
        const effectiveEndDate = endDate || plusDays(effectiveStartDate, DEFAULT_PROJECT_DURATION_DAYS);
        if (effectiveStartDate > effectiveEndDate) {
            setError("Дата окончания проекта не может быть раньше даты начала");
            return;
        }
        setCreatingProject(true);
        try {
            const createdProject = await createProject({
                name: name.trim(),
                folder: selectedFolder || "",
                description: description.trim() || undefined,
                start_date: effectiveStartDate,
                end_date: effectiveEndDate,
            });
            if (selectedMemberIds.length > 0) {
                await Promise.all(selectedMemberIds.map((userId) => addProjectMember(createdProject.id, userId)));
            }
            setCreateOpen(false);
            setName("");
            setDescription("");
            setStartDate("");
            setEndDate("");
            setSelectedMemberIds([]);
            setSelectedFolder("");
            await loadProjects();
        }
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось создать проект"));
        }
        finally {
            setCreatingProject(false);
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
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось удалить проект"));
        }
    };
    const openActionsMenu = (event) => {
        setActionsAnchorEl(event.currentTarget);
    };
    const closeActionsMenu = () => {
        setActionsAnchorEl(null);
    };
    const openCreateProjectDialog = (folderPath = "") => {
        closeActionsMenu();
        closeFolderActions();
        const today = toDateInputValue(new Date());
        setStartDate(today);
        setEndDate(plusDays(today, DEFAULT_PROJECT_DURATION_DAYS));
        setSelectedMemberIds([]);
        setSelectedFolder((folderPath || "").trim());
        setCreateOpen(true);
    };
    const openCreateFolderDialog = (parentId = "", seedName = "") => {
        closeActionsMenu();
        setFolderName(seedName);
        setFolderParentId(parentId);
        setCreateFolderOpen(true);
    };
    const submitCreateFolder = async () => {
        setError(null);
        setCreatingFolder(true);
        try {
            const created = await createProjectFolder({
                name: folderName.trim(),
                parent_id: folderParentId || null,
            });
            setSelectedFolder(created.path);
            setCreateFolderOpen(false);
            await loadProjects();
        }
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось создать папку проекта"));
        }
        finally {
            setCreatingFolder(false);
        }
    };
    const openProjectActions = (event, project) => {
        event.stopPropagation();
        setProjectActionsAnchorEl(event.currentTarget);
        setActiveProject(project);
    };
    const closeProjectActions = () => {
        setProjectActionsAnchorEl(null);
        setActiveProject(null);
    };
    const openFolderActions = (event, node) => {
        event.stopPropagation();
        setFolderActionsAnchorEl(event.currentTarget);
        setActiveFolderNode(node);
    };
    const closeFolderActions = () => {
        setFolderActionsAnchorEl(null);
        setActiveFolderNode(null);
    };
    const openEditProjectDialog = (project) => {
        setEditingProjectId(project.id);
        setEditingProjectName(project.name);
        setEditingProjectDescription(project.description ?? "");
        setEditingProjectStartDate(project.start_date ?? "");
        setEditingProjectEndDate(project.end_date ?? "");
        setEditingProjectStatus(project.status);
        setEditingProjectFolder((project.folder || "").trim());
        setEditOpen(true);
    };
    const submitProjectEdit = async () => {
        if (!editingProjectId) {
            return;
        }
        const normalizedStart = editingProjectStartDate || undefined;
        const normalizedEnd = editingProjectEndDate || undefined;
        if (normalizedStart && normalizedEnd && normalizedStart > normalizedEnd) {
            setError("Дата окончания проекта не может быть раньше даты начала");
            return;
        }
        setError(null);
        setUpdatingProject(true);
        try {
            await updateProject(editingProjectId, {
                name: editingProjectName.trim() || undefined,
                description: editingProjectDescription.trim() || undefined,
                start_date: normalizedStart,
                end_date: normalizedEnd,
                status: editingProjectStatus,
                folder: editingProjectFolder || "",
            });
            setEditOpen(false);
            setEditingProjectId(null);
            await loadProjects();
        }
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось обновить проект"));
        }
        finally {
            setUpdatingProject(false);
        }
    };
    const moveProjectToFolder = async (projectId, folderPath) => {
        const normalizedFolder = (folderPath || "").trim();
        setError(null);
        try {
            await updateProject(projectId, { folder: normalizedFolder });
            await loadProjects();
        }
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось перенести проект в папку"));
        }
        finally {
            setDraggingProjectId(null);
            setDragOverFolderPath(null);
            stopAutoScroll();
        }
    };
    const moveFolderToFolder = async (folderId, targetNode) => {
        const explicitTargetFolder = folders.find((item) => item.path === targetNode.path);
        const targetParentId = targetNode.path === "" ? null : explicitTargetFolder?.id ?? targetNode.id;
        if (targetNode.path !== "" && !targetParentId) {
            setError("Целевая папка не найдена");
            return;
        }
        setError(null);
        try {
            await moveProjectFolder(folderId, { parent_id: targetParentId });
            await loadProjects();
        }
        catch (error) {
            setError(getApiErrorMessage(error, "Не удалось переместить папку"));
        }
        finally {
            setDraggingFolderId(null);
            setDraggingFolderPath(null);
            setDragOverFolderPath(null);
            stopAutoScroll();
        }
    };
    const toggleFolderCollapsed = (folderPath) => {
        setExpandedFolderPaths((prev) => (prev.includes(folderPath) ? prev.filter((item) => item !== folderPath) : [...prev, folderPath]));
    };
    const prepareDragPayload = (event, type, id) => {
        setDraggingType(type);
        event.dataTransfer.effectAllowed = "move";
        event.dataTransfer.setData("text/plain", `${type}:${id}`);
        // Use a tiny transparent drag preview to avoid large ghost artifacts.
        const img = new Image();
        img.src =
            "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==";
        event.dataTransfer.setDragImage(img, 0, 0);
    };
    const parseDragPayload = (event) => {
        const raw = event.dataTransfer.getData("text/plain") || "";
        const [type, id] = raw.split(":");
        if ((type === "project" || type === "folder") && id) {
            return { type, id };
        }
        if (draggingProjectId) {
            return { type: "project", id: draggingProjectId };
        }
        if (draggingFolderId) {
            return { type: "folder", id: draggingFolderId };
        }
        return null;
    };
    const getFolderSourcePath = useCallback((folderId) => {
        return folderId === draggingFolderId ? draggingFolderPath : folderPathById.get(folderId) ?? null;
    }, [draggingFolderId, draggingFolderPath, folderPathById]);
    const stopAutoScroll = useCallback(() => {
        autoScrollVelocityRef.current = 0;
        if (autoScrollFrameRef.current !== null) {
            window.cancelAnimationFrame(autoScrollFrameRef.current);
            autoScrollFrameRef.current = null;
        }
    }, []);
    const startAutoScroll = useCallback((velocity) => {
        autoScrollVelocityRef.current = velocity;
        if (autoScrollFrameRef.current !== null) {
            return;
        }
        const step = () => {
            const delta = autoScrollVelocityRef.current;
            if (!delta) {
                autoScrollFrameRef.current = null;
                return;
            }
            projectListRef.current?.scrollBy({ top: delta });
            window.scrollBy({ top: delta });
            autoScrollFrameRef.current = window.requestAnimationFrame(step);
        };
        autoScrollFrameRef.current = window.requestAnimationFrame(step);
    }, []);
    const updateAutoScrollFromPointer = useCallback((clientY) => {
        const listRect = projectListRef.current?.getBoundingClientRect();
        const viewportHeight = window.innerHeight;
        const topBoundary = listRect ? Math.max(listRect.top, 0) : 0;
        const bottomBoundary = listRect ? Math.min(listRect.bottom, viewportHeight) : viewportHeight;
        const threshold = 72;
        if (clientY <= topBoundary + threshold) {
            startAutoScroll(-14);
            return;
        }
        if (clientY >= bottomBoundary - threshold) {
            startAutoScroll(14);
            return;
        }
        stopAutoScroll();
    }, [startAutoScroll, stopAutoScroll]);
    const stopAutoExpand = useCallback(() => {
        if (autoExpandTimerRef.current !== null) {
            window.clearTimeout(autoExpandTimerRef.current);
            autoExpandTimerRef.current = null;
        }
        autoExpandTargetRef.current = null;
    }, []);
    const scheduleAutoExpand = useCallback((folderPath, canExpand) => {
        if (!canExpand || expandedFolderPaths.includes(folderPath)) {
            stopAutoExpand();
            return;
        }
        if (autoExpandTargetRef.current === folderPath) {
            return;
        }
        stopAutoExpand();
        autoExpandTargetRef.current = folderPath;
        autoExpandTimerRef.current = window.setTimeout(() => {
            setExpandedFolderPaths((prev) => (prev.includes(folderPath) ? prev : [...prev, folderPath]));
            autoExpandTimerRef.current = null;
        }, 500);
    }, [expandedFolderPaths, stopAutoExpand]);
    const canDropOnNode = (dragging, targetNode) => {
        if (dragging.type === "project") {
            return true;
        }
        const sourcePath = getFolderSourcePath(dragging.id);
        if (!sourcePath) {
            return false;
        }
        if (targetNode.path === sourcePath || targetNode.path.startsWith(`${sourcePath}/`)) {
            return false;
        }
        if (!targetNode.id && targetNode.path !== "") {
            return false;
        }
        return true;
    };
    useEffect(() => {
        return () => {
            stopAutoScroll();
            stopAutoExpand();
        };
    }, [stopAutoExpand, stopAutoScroll]);
    const isDraggingSomething = Boolean(draggingProjectId || draggingFolderId);
    const renderDropLine = (targetNode, lineKey, depth) => (_jsx(Box, { onDragOver: (event) => {
            const dragging = parseDragPayload(event);
            if (!dragging || !canDropOnNode(dragging, targetNode)) {
                return;
            }
            event.preventDefault();
            event.stopPropagation();
            event.dataTransfer.dropEffect = "move";
            setDragOverFolderPath(null);
            setDropLineTarget(lineKey);
            stopAutoExpand();
            updateAutoScrollFromPointer(event.clientY);
        }, onDragLeave: () => {
            if (dropLineTarget === lineKey) {
                setDropLineTarget(null);
            }
        }, onDrop: (event) => {
            const dragging = parseDragPayload(event);
            stopAutoScroll();
            stopAutoExpand();
            if (!dragging || !canDropOnNode(dragging, targetNode)) {
                setDropLineTarget(null);
                return;
            }
            event.preventDefault();
            event.stopPropagation();
            setDropLineTarget(null);
            if (dragging.type === "project") {
                void moveProjectToFolder(dragging.id, targetNode.path);
                return;
            }
            void moveFolderToFolder(dragging.id, targetNode);
        }, sx: {
            height: 10,
            mx: 1.2,
            ml: 1.2 + depth * 2.1,
            position: "relative",
            opacity: isDraggingSomething ? 1 : 0,
            transition: "opacity 0.15s ease-in-out",
            "&::before": {
                content: '""',
                position: "absolute",
                left: 0,
                right: 0,
                top: "50%",
                transform: "translateY(-50%)",
                borderTop: dropLineTarget === lineKey ? "2px solid rgba(126,224,255,0.9)" : "1px dashed rgba(126,224,255,0.16)",
            },
        } }, lineKey));
    const getNestedProjectsCount = (node) => {
        return node.projects.length + node.children.reduce((total, child) => total + getNestedProjectsCount(child), 0);
    };
    const renderFolderNode = (node, depth = 0, parentNode = ROOT_FOLDER_NODE) => (_jsxs(Box, { children: [renderDropLine(parentNode, `before-folder:${node.path}`, depth), (() => {
                const hasNestedContent = node.children.length > 0 || node.projects.length > 0;
                const isExpanded = expandedFolderPaths.includes(node.path);
                const isFolderDropActive = dragOverFolderPath === node.path;
                return (_jsxs(Stack, { direction: "row", alignItems: "center", justifyContent: "space-between", draggable: Boolean(user?.role === "admin" && node.id && node.path !== ""), onDragStart: (event) => {
                        if (!(user?.role === "admin" && node.id && node.path !== "")) {
                            return;
                        }
                        setDraggingProjectId(null);
                        setDraggingFolderId(node.id);
                        setDraggingFolderPath(node.path);
                        prepareDragPayload(event, "folder", node.id);
                    }, onDragEnd: () => {
                        setDraggingFolderId(null);
                        setDraggingFolderPath(null);
                        setDragOverFolderPath(null);
                        setDropLineTarget(null);
                        setDraggingType(null);
                        stopAutoScroll();
                        stopAutoExpand();
                    }, onDragOver: (event) => {
                        const dragging = parseDragPayload(event);
                        if (!dragging) {
                            stopAutoScroll();
                            return;
                        }
                        const canDrop = canDropOnNode(dragging, node);
                        if (!canDrop) {
                            stopAutoScroll();
                            return;
                        }
                        event.preventDefault();
                        event.stopPropagation();
                        event.dataTransfer.dropEffect = "move";
                        setDragOverFolderPath(node.path);
                        setDropLineTarget(null);
                        scheduleAutoExpand(node.path, hasNestedContent);
                        updateAutoScrollFromPointer(event.clientY);
                    }, onDragLeave: () => {
                        if (dragOverFolderPath === node.path) {
                            setDragOverFolderPath(null);
                        }
                        stopAutoExpand();
                    }, onDrop: (event) => {
                        const dragging = parseDragPayload(event);
                        if (!dragging) {
                            stopAutoScroll();
                            return;
                        }
                        event.preventDefault();
                        event.stopPropagation();
                        const canDrop = canDropOnNode(dragging, node);
                        if (!canDrop) {
                            setDragOverFolderPath(null);
                            stopAutoScroll();
                            stopAutoExpand();
                            return;
                        }
                        if (dragging.type === "project") {
                            void moveProjectToFolder(dragging.id, node.path);
                            return;
                        }
                        void moveFolderToFolder(dragging.id, node);
                        setDragOverFolderPath(null);
                        setDropLineTarget(null);
                        setDraggingFolderId(null);
                        setDraggingFolderPath(null);
                        setDraggingType(null);
                        stopAutoScroll();
                        stopAutoExpand();
                    }, sx: {
                        px: 1.2,
                        py: 0.75,
                        pl: 1.2 + depth * 2.1,
                        backgroundColor: isFolderDropActive
                            ? "rgba(126,224,255,0.14)"
                            : depth === 0
                                ? "rgba(126,224,255,0.06)"
                                : "transparent",
                        borderRadius: 0,
                        "& .folder-actions": {
                            opacity: 0,
                            pointerEvents: "none",
                            transition: "opacity 0.15s ease-in-out",
                        },
                        "&:hover .folder-actions": {
                            opacity: 1,
                            pointerEvents: "auto",
                        },
                        outline: isFolderDropActive ? "1px solid rgba(126,224,255,0.55)" : "none",
                        boxShadow: isFolderDropActive ? "inset 0 0 0 1px rgba(126,224,255,0.22)" : "none",
                    }, children: [_jsxs(Stack, { direction: "row", spacing: 0.8, alignItems: "center", sx: { flex: 1, minWidth: 0, cursor: hasNestedContent ? "pointer" : "default" }, onClick: () => {
                                if (hasNestedContent) {
                                    toggleFolderCollapsed(node.path);
                                }
                            }, children: [hasNestedContent ? (isExpanded ? (_jsx(ExpandMoreIcon, { fontSize: "small", sx: { color: "text.secondary" } })) : (_jsx(ChevronRightIcon, { fontSize: "small", sx: { color: "text.secondary" } }))) : (_jsx(Box, { sx: { width: 20, height: 20 } })), _jsx(FolderOpenIcon, { fontSize: "small" }), _jsx(Typography, { fontWeight: depth === 0 ? 700 : 500, noWrap: true, children: node.name }), _jsx(Typography, { variant: "caption", color: "text.secondary", children: getNestedProjectsCount(node) > 0 ? `${getNestedProjectsCount(node)} пр.` : "" })] }), user?.role === "admin" && node.id && (_jsxs(Stack, { direction: "row", className: "folder-actions", children: [isFolderDropActive && (_jsx(Typography, { variant: "caption", color: "primary.main", sx: { alignSelf: "center", mr: 0.5, whiteSpace: "nowrap" }, children: "\u0412\u043B\u043E\u0436\u0438\u0442\u044C \u0432 \u043F\u0430\u043F\u043A\u0443" })), _jsx(Tooltip, { title: "\u0414\u0435\u0439\u0441\u0442\u0432\u0438\u044F \u043F\u0430\u043F\u043A\u0438", children: _jsx(IconButton, { size: "small", onClick: (event) => openFolderActions(event, node), sx: { width: 28, height: 28 }, children: _jsx(MoreVertIcon, { fontSize: "small" }) }) })] }))] }));
            })(), expandedFolderPaths.includes(node.path) && (_jsxs(_Fragment, { children: [node.projects.map((project) => (_jsxs(Box, { children: [renderDropLine(node, `before-project:${project.id}`, depth + 1), _jsxs(Stack, { direction: "row", alignItems: "center", justifyContent: "space-between", draggable: user?.role === "admin", onDragStart: (event) => {
                                    setDraggingFolderId(null);
                                    setDraggingFolderPath(null);
                                    setDraggingProjectId(project.id);
                                    prepareDragPayload(event, "project", project.id);
                                }, onDragEnd: () => {
                                    setDraggingProjectId(null);
                                    setDragOverFolderPath(null);
                                    setDropLineTarget(null);
                                    setDraggingType(null);
                                    stopAutoScroll();
                                    stopAutoExpand();
                                }, sx: {
                                    "& .project-actions": {
                                        opacity: 0,
                                        pointerEvents: "none",
                                        transition: "opacity 0.15s ease-in-out",
                                    },
                                    "&:hover .project-actions": {
                                        opacity: 1,
                                        pointerEvents: "auto",
                                    },
                                    borderRadius: 0,
                                    "&:hover": {
                                        backgroundColor: "rgba(126,224,255,0.06)",
                                    },
                                }, children: [_jsxs(ListItemButton, { sx: { py: 1, pl: 4 + depth * 2, borderRadius: 0 }, onClick: () => navigate(`/projects/${project.id}`), children: [_jsx(ListItemIcon, { sx: { minWidth: 32 }, children: _jsx(DescriptionOutlinedIcon, { fontSize: "small", color: "action" }) }), _jsx(ListItemText, { primary: project.name, secondaryTypographyProps: { component: "div" }, secondary: _jsxs(Stack, { direction: { xs: "column", md: "row" }, spacing: { xs: 0.5, md: 1.5 }, alignItems: { md: "center" }, children: [_jsx(Chip, { size: "small", label: PROJECT_STATUS_LABELS[project.status], sx: PROJECT_STATUS_CHIP_SX[project.status] }), _jsx(Typography, { variant: "caption", color: "text.secondary", children: project.start_date || "дата не задана" })] }) })] }), user?.role === "admin" && (_jsx(Stack, { direction: "row", alignItems: "center", className: "project-actions", sx: { pr: 0.5 }, children: _jsx(Tooltip, { title: "\u0414\u0435\u0439\u0441\u0442\u0432\u0438\u044F", children: _jsx(IconButton, { size: "small", onClick: (event) => openProjectActions(event, project), sx: { width: 28, height: 28 }, children: _jsx(MoreVertIcon, { fontSize: "small" }) }) }) }))] })] }, project.id))), node.children.map((child) => (_jsx(Box, { sx: { pl: 0.8 }, children: renderFolderNode(child, depth + 1, node) }, child.path))), renderDropLine(node, `after-folder-content:${node.path}`, depth + 1)] })), depth === 0 && _jsx(Divider, {})] }, node.path));
    return (_jsxs(Stack, { spacing: 3, children: [_jsxs(Stack, { direction: "row", justifyContent: "space-between", alignItems: "flex-start", gap: 2, children: [_jsx(Box, { children: _jsx(Typography, { variant: "h4", fontWeight: 700, children: "\u041F\u0440\u043E\u0435\u043A\u0442\u044B" }) }), user?.role === "admin" && (_jsx(IconButton, { onClick: openActionsMenu, sx: {
                            border: "1px solid rgba(126,224,255,0.24)",
                            width: 40,
                            height: 40,
                            backgroundColor: "rgba(15,27,45,0.74)",
                        }, children: _jsx(MoreVertIcon, {}) }))] }), _jsxs(Menu, { anchorEl: actionsAnchorEl, open: Boolean(actionsAnchorEl), onClose: closeActionsMenu, anchorOrigin: { vertical: "bottom", horizontal: "right" }, transformOrigin: { vertical: "top", horizontal: "right" }, children: [_jsxs(MenuItem, { onClick: () => openCreateProjectDialog(), children: [_jsx(ListItemIcon, { children: _jsx(AddIcon, { fontSize: "small" }) }), "\u0421\u043E\u0437\u0434\u0430\u0442\u044C \u043F\u0440\u043E\u0435\u043A\u0442"] }), _jsxs(MenuItem, { onClick: () => openCreateFolderDialog(), children: [_jsx(ListItemIcon, { children: _jsx(CreateNewFolderIcon, { fontSize: "small" }) }), "\u0421\u043E\u0437\u0434\u0430\u0442\u044C \u043F\u0430\u043F\u043A\u0443"] })] }), _jsxs(Menu, { anchorEl: projectActionsAnchorEl, open: Boolean(projectActionsAnchorEl), onClose: closeProjectActions, anchorOrigin: { vertical: "bottom", horizontal: "right" }, transformOrigin: { vertical: "top", horizontal: "right" }, children: [_jsxs(MenuItem, { onClick: () => {
                            if (activeProject) {
                                openEditProjectDialog(activeProject);
                            }
                            closeProjectActions();
                        }, children: [_jsx(ListItemIcon, { children: _jsx(EditIcon, { fontSize: "small" }) }), "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C"] }), _jsxs(MenuItem, { onClick: () => {
                            if (activeProject) {
                                void handleDeleteProject(activeProject.id, activeProject.name);
                            }
                            closeProjectActions();
                        }, children: [_jsx(ListItemIcon, { children: _jsx(DeleteOutlineIcon, { fontSize: "small" }) }), "\u0423\u0434\u0430\u043B\u0438\u0442\u044C"] })] }), _jsxs(Menu, { anchorEl: folderActionsAnchorEl, open: Boolean(folderActionsAnchorEl), onClose: closeFolderActions, anchorOrigin: { vertical: "bottom", horizontal: "right" }, transformOrigin: { vertical: "top", horizontal: "right" }, children: [_jsxs(MenuItem, { onClick: () => {
                            if (activeFolderNode?.path) {
                                openCreateProjectDialog(activeFolderNode.path);
                            }
                            closeFolderActions();
                        }, children: [_jsx(ListItemIcon, { children: _jsx(AddIcon, { fontSize: "small" }) }), "\u0421\u043E\u0437\u0434\u0430\u0442\u044C \u043F\u0440\u043E\u0435\u043A\u0442 \u0432\u043D\u0443\u0442\u0440\u0438"] }), _jsxs(MenuItem, { onClick: () => {
                            if (activeFolderNode?.id) {
                                openCreateFolderDialog(activeFolderNode.id);
                            }
                            closeFolderActions();
                        }, children: [_jsx(ListItemIcon, { children: _jsx(CreateNewFolderIcon, { fontSize: "small" }) }), "\u0421\u043E\u0437\u0434\u0430\u0442\u044C \u043F\u0430\u043F\u043A\u0443 \u0432\u043D\u0443\u0442\u0440\u0438"] })] }), _jsx(Box, { sx: {
                    border: "1px solid rgba(126,224,255,0.12)",
                    borderRadius: 0,
                    p: 2,
                    backgroundColor: "rgba(15,27,45,0.56)",
                }, children: _jsxs(Stack, { spacing: 2, children: [_jsx(Stack, { direction: { xs: "column", lg: "row" }, spacing: 1.5, alignItems: { lg: "center" }, justifyContent: "space-between", children: _jsxs(Stack, { direction: "row", spacing: 1, flexWrap: "wrap", children: [_jsx(Chip, { label: `Проектов: ${treeStats.totalProjects}`, variant: "outlined" }), _jsx(Chip, { label: `Папок: ${treeStats.totalFolders}`, variant: "outlined" }), _jsx(Chip, { label: `Вложенных папок: ${treeStats.nestedFolders}`, variant: "outlined" })] }) }), _jsxs(Stack, { direction: { xs: "column", md: "row" }, spacing: 1.5, children: [_jsx(TextField, { label: "\u041F\u043E\u0438\u0441\u043A \u043F\u0440\u043E\u0435\u043A\u0442\u0430", placeholder: "\u041D\u0430\u0437\u0432\u0430\u043D\u0438\u0435 \u0438\u043B\u0438 \u043E\u043F\u0438\u0441\u0430\u043D\u0438\u0435", value: searchQuery, onChange: (event) => setSearchQuery(event.target.value), fullWidth: true }), _jsxs(TextField, { select: true, label: "\u0421\u0442\u0430\u0442\u0443\u0441", value: statusFilter, onChange: (event) => setStatusFilter(event.target.value), sx: { minWidth: 220 }, children: [_jsx(MenuItem, { value: "all", children: "\u0412\u0441\u0435 \u0441\u0442\u0430\u0442\u0443\u0441\u044B" }), PROJECT_STATUS_ORDER.map((status) => (_jsx(MenuItem, { value: status, children: PROJECT_STATUS_LABELS[status] }, status)))] })] })] }) }), _jsxs(List, { ref: projectListRef, disablePadding: true, onDragOver: (event) => {
                    const dragging = parseDragPayload(event);
                    if (!dragging) {
                        stopAutoScroll();
                        return;
                    }
                    event.preventDefault();
                    updateAutoScrollFromPointer(event.clientY);
                }, onDragLeave: (event) => {
                    if (!event.currentTarget.contains(event.relatedTarget)) {
                        stopAutoScroll();
                        stopAutoExpand();
                        setDragOverFolderPath(null);
                        setDropLineTarget(null);
                    }
                }, onDrop: (event) => {
                    const dragging = parseDragPayload(event);
                    stopAutoScroll();
                    stopAutoExpand();
                    if (!dragging) {
                        return;
                    }
                    event.preventDefault();
                    setDropLineTarget(null);
                    setDragOverFolderPath(null);
                    if (dragging.type === "project") {
                        void moveProjectToFolder(dragging.id, "");
                        return;
                    }
                    void moveFolderToFolder(dragging.id, ROOT_FOLDER_NODE);
                }, sx: {
                    border: "1px solid rgba(126,224,255,0.14)",
                    borderRadius: 0,
                    backgroundColor: "rgba(15,27,45,0.58)",
                    maxHeight: "calc(100vh - 300px)",
                    overflowY: "auto",
                    p: 1,
                }, children: [renderDropLine(ROOT_FOLDER_NODE, "root-drop-line", 0), groupedProjects.map((node) => renderFolderNode(node)), renderDropLine(ROOT_FOLDER_NODE, "root-drop-line-end", 0), groupedProjects.length === 0 && (_jsx(Box, { sx: { px: 2, py: 2 }, children: _jsx(Typography, { color: "text.secondary", children: "\u041F\u0440\u043E\u0435\u043A\u0442\u044B \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D\u044B." }) }))] }), _jsxs(Dialog, { open: createOpen, onClose: () => setCreateOpen(false), fullWidth: true, maxWidth: "sm", children: [_jsx(DialogTitle, { children: "\u0421\u043E\u0437\u0434\u0430\u0442\u044C \u043F\u0440\u043E\u0435\u043A\u0442" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [_jsx(TextField, { label: "\u041D\u0430\u0437\u0432\u0430\u043D\u0438\u0435", value: name, onChange: (e) => setName(e.target.value) }), _jsx(TextField, { label: "\u041E\u043F\u0438\u0441\u0430\u043D\u0438\u0435", multiline: true, minRows: 3, value: description, onChange: (e) => setDescription(e.target.value) }), _jsx(TextField, { label: "\u0414\u0430\u0442\u0430 \u043D\u0430\u0447\u0430\u043B\u0430", type: "date", value: startDate, onChange: (e) => setStartDate(e.target.value), InputLabelProps: { shrink: true } }), _jsx(TextField, { label: "\u0414\u0430\u0442\u0430 \u043E\u043A\u043E\u043D\u0447\u0430\u043D\u0438\u044F", type: "date", value: endDate, onChange: (e) => setEndDate(e.target.value), InputLabelProps: { shrink: true } }), _jsxs(TextField, { select: true, label: "\u041F\u0430\u043F\u043A\u0430 \u043F\u0440\u043E\u0435\u043A\u0442\u0430", value: selectedFolder, onChange: (event) => setSelectedFolder(event.target.value), children: [_jsx(MenuItem, { value: "", children: ROOT_FOLDER_LABEL }), folderPaths.map((folder) => (_jsx(MenuItem, { value: folder, children: folder }, folder)))] }), _jsx(TextField, { select: true, label: "\u0423\u0447\u0430\u0441\u0442\u043D\u0438\u043A\u0438 \u043F\u0440\u043E\u0435\u043A\u0442\u0430", value: selectedMemberIds, onChange: (event) => {
                                        const value = event.target.value;
                                        setSelectedMemberIds(typeof value === "string" ? value.split(",") : value);
                                    }, SelectProps: {
                                        multiple: true,
                                        renderValue: (selected) => selected
                                            .map((id) => usersCatalog.find((item) => item.id === id)?.username ?? id)
                                            .join(", "),
                                    }, children: usersCatalog.map((candidate) => (_jsxs(MenuItem, { value: candidate.id, children: [_jsx(Checkbox, { size: "small", checked: selectedMemberIds.includes(candidate.id) }), _jsx(ListItemText, { primary: `${candidate.username} (${candidate.role})`, secondary: candidate.email })] }, candidate.id))) })] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => {
                                    setCreateOpen(false);
                                    setName("");
                                    setDescription("");
                                    setStartDate("");
                                    setEndDate("");
                                    setSelectedMemberIds([]);
                                    setSelectedFolder("");
                                }, children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", onClick: () => void handleCreate(), disabled: !name.trim() || creatingProject, children: "\u0421\u043E\u0437\u0434\u0430\u0442\u044C" })] })] }), _jsxs(Dialog, { open: createFolderOpen, onClose: () => setCreateFolderOpen(false), fullWidth: true, maxWidth: "sm", children: [_jsx(DialogTitle, { children: "\u0421\u043E\u0437\u0434\u0430\u0442\u044C \u043F\u0430\u043F\u043A\u0443 \u043F\u0440\u043E\u0435\u043A\u0442\u0430" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [_jsx(TextField, { label: "\u041D\u0430\u0437\u0432\u0430\u043D\u0438\u0435 \u043F\u0430\u043F\u043A\u0438", placeholder: "\u041D\u0430\u043F\u0440\u0438\u043C\u0435\u0440: \u041A\u043B\u0438\u0435\u043D\u0442\u044B", value: folderName, onChange: (event) => setFolderName(event.target.value) }), _jsxs(TextField, { select: true, label: "\u0420\u043E\u0434\u0438\u0442\u0435\u043B\u044C\u0441\u043A\u0430\u044F \u043F\u0430\u043F\u043A\u0430", value: folderParentId, onChange: (event) => setFolderParentId(event.target.value), children: [_jsx(MenuItem, { value: "", children: "\u041A\u043E\u0440\u0435\u043D\u044C" }), folders.map((folder) => (_jsx(MenuItem, { value: folder.id, children: folder.path }, folder.id)))] })] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => setCreateFolderOpen(false), children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", onClick: () => void submitCreateFolder(), disabled: !folderName.trim() || creatingFolder, children: "\u0421\u043E\u0437\u0434\u0430\u0442\u044C" })] })] }), _jsxs(Dialog, { open: editOpen, onClose: () => setEditOpen(false), fullWidth: true, maxWidth: "sm", children: [_jsx(DialogTitle, { children: "\u0420\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u043F\u0440\u043E\u0435\u043A\u0442" }), _jsx(DialogContent, { children: _jsxs(Stack, { spacing: 2, sx: { mt: 1 }, children: [_jsx(TextField, { label: "\u041D\u0430\u0437\u0432\u0430\u043D\u0438\u0435", value: editingProjectName, onChange: (event) => setEditingProjectName(event.target.value) }), _jsx(TextField, { label: "\u041E\u043F\u0438\u0441\u0430\u043D\u0438\u0435", multiline: true, minRows: 3, value: editingProjectDescription, onChange: (event) => setEditingProjectDescription(event.target.value) }), _jsx(TextField, { label: "\u0414\u0430\u0442\u0430 \u043D\u0430\u0447\u0430\u043B\u0430", type: "date", value: editingProjectStartDate, onChange: (event) => setEditingProjectStartDate(event.target.value), InputLabelProps: { shrink: true } }), _jsx(TextField, { label: "\u0414\u0430\u0442\u0430 \u043E\u043A\u043E\u043D\u0447\u0430\u043D\u0438\u044F", type: "date", value: editingProjectEndDate, onChange: (event) => setEditingProjectEndDate(event.target.value), InputLabelProps: { shrink: true } }), _jsx(TextField, { select: true, label: "\u0421\u0442\u0430\u0442\u0443\u0441", value: editingProjectStatus, onChange: (event) => setEditingProjectStatus(event.target.value), children: PROJECT_STATUS_ORDER.map((status) => (_jsx(MenuItem, { value: status, children: PROJECT_STATUS_LABELS[status] }, status))) }), _jsxs(TextField, { select: true, label: "\u041F\u0430\u043F\u043A\u0430 \u043F\u0440\u043E\u0435\u043A\u0442\u0430", value: editingProjectFolder, onChange: (event) => setEditingProjectFolder(event.target.value), children: [_jsx(MenuItem, { value: "", children: ROOT_FOLDER_LABEL }), folderPaths.map((folder) => (_jsx(MenuItem, { value: folder, children: folder }, folder)))] })] }) }), _jsxs(DialogActions, { children: [_jsx(Button, { onClick: () => {
                                    setEditOpen(false);
                                    setEditingProjectId(null);
                                }, children: "\u041E\u0442\u043C\u0435\u043D\u0430" }), _jsx(Button, { variant: "contained", onClick: () => void submitProjectEdit(), disabled: !editingProjectName.trim() || updatingProject, children: "\u0421\u043E\u0445\u0440\u0430\u043D\u0438\u0442\u044C" })] })] })] }));
}
