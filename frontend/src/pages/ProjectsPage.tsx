import AddIcon from "@mui/icons-material/Add";
import DeleteOutlineIcon from "@mui/icons-material/DeleteOutline";
import EditIcon from "@mui/icons-material/Edit";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import FolderOpenIcon from "@mui/icons-material/FolderOpen";
import CreateNewFolderIcon from "@mui/icons-material/CreateNewFolder";
import ChevronRightIcon from "@mui/icons-material/ChevronRight";
import DescriptionOutlinedIcon from "@mui/icons-material/DescriptionOutlined";
import MoreVertIcon from "@mui/icons-material/MoreVert";
import {
  Checkbox,
  Alert,
  Box,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Menu,
  MenuItem,
  Stack,
  TextField,
  Typography,
  IconButton,
  Tooltip,
} from "@mui/material";
import { type DragEvent, type MouseEvent, useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  addProjectMember,
  createProject,
  createProjectFolder,
  deleteProject,
  getProjectFolders,
  getProjects,
  getUsers,
  moveProjectFolder,
  updateProject,
} from "../api";
import { useAuthStore } from "../store";
import type { Project, ProjectFolder, User } from "../types";

const DEFAULT_PROJECT_DURATION_DAYS = 14;
const DEFAULT_FOLDER_NAME = "Без папки";

type FolderTreeNode = {
  id: string | null;
  name: string;
  path: string;
  children: FolderTreeNode[];
  projects: Project[];
};

const toDateInputValue = (date: Date) => {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
};

const plusDays = (dateString: string, days: number) => {
  const base = new Date(`${dateString}T00:00:00`);
  base.setDate(base.getDate() + days);
  return toDateInputValue(base);
};

export function ProjectsPage() {
  const navigate = useNavigate();
  const user = useAuthStore((s) => s.user);
  const [projects, setProjects] = useState<Project[]>([]);
  const [folders, setFolders] = useState<ProjectFolder[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [actionsAnchorEl, setActionsAnchorEl] = useState<null | HTMLElement>(null);
  const [projectActionsAnchorEl, setProjectActionsAnchorEl] = useState<null | HTMLElement>(null);
  const [folderActionsAnchorEl, setFolderActionsAnchorEl] = useState<null | HTMLElement>(null);
  const [activeFolderNode, setActiveFolderNode] = useState<FolderTreeNode | null>(null);
  const [activeProject, setActiveProject] = useState<Project | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [editOpen, setEditOpen] = useState(false);
  const [createFolderOpen, setCreateFolderOpen] = useState(false);
  const [folderName, setFolderName] = useState("");
  const [folderParentId, setFolderParentId] = useState<string>("");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [usersCatalog, setUsersCatalog] = useState<User[]>([]);
  const [selectedMemberIds, setSelectedMemberIds] = useState<string[]>([]);
  const [selectedFolder, setSelectedFolder] = useState(DEFAULT_FOLDER_NAME);
  const [folderPaths, setFolderPaths] = useState<string[]>([DEFAULT_FOLDER_NAME]);
  const [creatingProject, setCreatingProject] = useState(false);
  const [updatingProject, setUpdatingProject] = useState(false);
  const [creatingFolder, setCreatingFolder] = useState(false);
  const [draggingProjectId, setDraggingProjectId] = useState<string | null>(null);
  const [draggingFolderId, setDraggingFolderId] = useState<string | null>(null);
  const [draggingFolderPath, setDraggingFolderPath] = useState<string | null>(null);
  const [dragOverFolderPath, setDragOverFolderPath] = useState<string | null>(null);
  const [, setDraggingType] = useState<"project" | "folder" | null>(null);
  const [expandedFolderPaths, setExpandedFolderPaths] = useState<string[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | Project["status"]>("all");
  const [editingProjectName, setEditingProjectName] = useState("");
  const [editingProjectId, setEditingProjectId] = useState<string | null>(null);
  const [editingProjectDescription, setEditingProjectDescription] = useState("");
  const [editingProjectStartDate, setEditingProjectStartDate] = useState("");
  const [editingProjectEndDate, setEditingProjectEndDate] = useState("");
  const [editingProjectStatus, setEditingProjectStatus] = useState<Project["status"]>("active");
  const [editingProjectFolder, setEditingProjectFolder] = useState(DEFAULT_FOLDER_NAME);

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
    } catch {
      setError("Не удалось загрузить проекты");
    }
  }, [statusFilter]);

  useEffect(() => {
    void loadProjects();
  }, [loadProjects]);

  useEffect(() => {
    const values = [
      DEFAULT_FOLDER_NAME,
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
    const folderByPath = new Map(folders.map((item) => [item.path, item] as const));
    const root: FolderTreeNode = { id: null, name: "", path: "", children: [], projects: [] };
    const nodeMap = new Map<string, FolderTreeNode>([["", root]]);

    const ensurePath = (pathValue: string) => {
      const normalizedPath = (pathValue || DEFAULT_FOLDER_NAME).trim() || DEFAULT_FOLDER_NAME;
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
        } else if (!node.id && folderByPath.get(currentPath)?.id) {
          node.id = folderByPath.get(currentPath)!.id;
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

    const sortTree = (node: FolderTreeNode) => {
      node.children.sort((left, right) => left.name.localeCompare(right.name));
      node.projects.sort((left, right) => left.name.localeCompare(right.name));
      node.children.forEach(sortTree);
    };
    sortTree(root);
    return root.children;
  }, [folderPaths, folders, visibleProjects]);

  useEffect(() => {
    if (!createOpen || user?.role !== "admin") {
      return;
    }
    const loadUsers = async () => {
      try {
        const response = await getUsers(1, 200);
        setUsersCatalog(response.items);
      } catch {
        setError("Не удалось загрузить список пользователей");
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
        folder: selectedFolder || DEFAULT_FOLDER_NAME,
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
      setSelectedFolder(DEFAULT_FOLDER_NAME);
      await loadProjects();
    } catch {
      setError("Не удалось создать проект");
    } finally {
      setCreatingProject(false);
    }
  };

  const handleDeleteProject = async (projectId: string, projectName: string) => {
    if (!window.confirm(`Удалить проект "${projectName}"?`)) {
      return;
    }
    setError(null);
    try {
      await deleteProject(projectId);
      await loadProjects();
    } catch {
      setError("Не удалось удалить проект");
    }
  };

  const openActionsMenu = (event: MouseEvent<HTMLElement>) => {
    setActionsAnchorEl(event.currentTarget);
  };

  const closeActionsMenu = () => {
    setActionsAnchorEl(null);
  };

  const openCreateProjectDialog = (folderPath = DEFAULT_FOLDER_NAME) => {
    closeActionsMenu();
    closeFolderActions();
    const today = toDateInputValue(new Date());
    setStartDate(today);
    setEndDate(plusDays(today, DEFAULT_PROJECT_DURATION_DAYS));
    setSelectedMemberIds([]);
    setSelectedFolder((folderPath || DEFAULT_FOLDER_NAME).trim() || DEFAULT_FOLDER_NAME);
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
    } catch {
      setError("Не удалось создать папку проекта");
    } finally {
      setCreatingFolder(false);
    }
  };

  const openProjectActions = (event: MouseEvent<HTMLElement>, project: Project) => {
    event.stopPropagation();
    setProjectActionsAnchorEl(event.currentTarget);
    setActiveProject(project);
  };

  const closeProjectActions = () => {
    setProjectActionsAnchorEl(null);
    setActiveProject(null);
  };

  const openFolderActions = (event: MouseEvent<HTMLElement>, node: FolderTreeNode) => {
    event.stopPropagation();
    setFolderActionsAnchorEl(event.currentTarget);
    setActiveFolderNode(node);
  };

  const closeFolderActions = () => {
    setFolderActionsAnchorEl(null);
    setActiveFolderNode(null);
  };

  const openEditProjectDialog = (project: Project) => {
    setEditingProjectId(project.id);
    setEditingProjectName(project.name);
    setEditingProjectDescription(project.description ?? "");
    setEditingProjectStartDate(project.start_date ?? "");
    setEditingProjectEndDate(project.end_date ?? "");
    setEditingProjectStatus(project.status);
    setEditingProjectFolder((project.folder || DEFAULT_FOLDER_NAME).trim() || DEFAULT_FOLDER_NAME);
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
        folder: editingProjectFolder || DEFAULT_FOLDER_NAME,
      });
      setEditOpen(false);
      setEditingProjectId(null);
      await loadProjects();
    } catch {
      setError("Не удалось обновить проект");
    } finally {
      setUpdatingProject(false);
    }
  };

  const moveProjectToFolder = async (projectId: string, folderPath: string) => {
    const normalizedFolder = (folderPath || DEFAULT_FOLDER_NAME).trim() || DEFAULT_FOLDER_NAME;
    setError(null);
    try {
      await updateProject(projectId, { folder: normalizedFolder });
      await loadProjects();
    } catch {
      setError("Не удалось перенести проект в папку");
    } finally {
      setDraggingProjectId(null);
      setDragOverFolderPath(null);
    }
  };

  const moveFolderToFolder = async (folderId: string, targetNode: FolderTreeNode) => {
    const explicitTargetFolder = folders.find((item) => item.path === targetNode.path);
    const targetParentId = targetNode.path === DEFAULT_FOLDER_NAME ? null : explicitTargetFolder?.id ?? targetNode.id;
    if (targetNode.path !== DEFAULT_FOLDER_NAME && !targetParentId) {
      setError("Целевая папка не найдена");
      return;
    }
    setError(null);
    try {
      await moveProjectFolder(folderId, { parent_id: targetParentId });
      await loadProjects();
    } catch {
      setError("Не удалось переместить папку");
    } finally {
      setDraggingFolderId(null);
      setDraggingFolderPath(null);
      setDragOverFolderPath(null);
    }
  };

  const toggleFolderCollapsed = (folderPath: string) => {
    setExpandedFolderPaths((prev) => (prev.includes(folderPath) ? prev.filter((item) => item !== folderPath) : [...prev, folderPath]));
  };

  const prepareDragPayload = (event: DragEvent, type: "project" | "folder", id: string) => {
    setDraggingType(type);
    event.dataTransfer.effectAllowed = "move";
    event.dataTransfer.setData("text/plain", `${type}:${id}`);
    // Use a tiny transparent drag preview to avoid large ghost artifacts.
    const img = new Image();
    img.src =
      "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==";
    event.dataTransfer.setDragImage(img, 0, 0);
  };

  const renderFolderNode = (node: FolderTreeNode, depth = 0): JSX.Element => (
    <Box key={node.path}>
      {(() => {
        const hasNestedContent = node.children.length > 0 || node.projects.length > 0;
        const isExpanded = expandedFolderPaths.includes(node.path);
        return (
      <Stack
        direction="row"
        alignItems="center"
        justifyContent="space-between"
        draggable={Boolean(user?.role === "admin" && node.id && node.path !== DEFAULT_FOLDER_NAME)}
        onDragStart={(event) => {
          if (!(user?.role === "admin" && node.id && node.path !== DEFAULT_FOLDER_NAME)) {
            return;
          }
          setDraggingProjectId(null);
          setDraggingFolderId(node.id);
          setDraggingFolderPath(node.path);
          prepareDragPayload(event, "folder", node.id);
        }}
        onDragEnd={() => {
          setDraggingFolderId(null);
          setDraggingFolderPath(null);
          setDragOverFolderPath(null);
          setDraggingType(null);
        }}
        onDragOver={(event) => {
          if (!draggingProjectId && !draggingFolderId) {
            return;
          }
          if (draggingFolderId && draggingFolderPath && (node.path === draggingFolderPath || node.path.startsWith(`${draggingFolderPath}/`))) {
            return;
          }
          if (draggingFolderId && !node.id && node.path !== DEFAULT_FOLDER_NAME) {
            return;
          }
          event.preventDefault();
          setDragOverFolderPath(node.path);
        }}
        onDragLeave={() => {
          if (dragOverFolderPath === node.path) {
            setDragOverFolderPath(null);
          }
        }}
        onDrop={(event) => {
          event.preventDefault();
          if (draggingProjectId) {
            void moveProjectToFolder(draggingProjectId, node.path);
            return;
          }
          if (draggingFolderId && draggingFolderPath && !(node.path === draggingFolderPath || node.path.startsWith(`${draggingFolderPath}/`))) {
            void moveFolderToFolder(draggingFolderId, node);
            return;
          }
          setDragOverFolderPath(null);
          setDraggingFolderId(null);
          setDraggingFolderPath(null);
          setDraggingType(null);
        }}
        sx={{
          px: 1.2,
          py: 0.65,
          pl: 1.2 + depth * 2.1,
          backgroundColor:
            dragOverFolderPath === node.path
              ? "rgba(126,224,255,0.16)"
              : depth === 0
                ? "rgba(126,224,255,0.06)"
                : "transparent",
          "& .folder-actions": {
            opacity: 0,
            pointerEvents: "none",
            transition: "opacity 0.15s ease-in-out",
          },
          "&:hover .folder-actions": {
            opacity: 1,
            pointerEvents: "auto",
          },
          outline: dragOverFolderPath === node.path ? "1px solid rgba(126,224,255,0.45)" : "none",
        }}
      >
        <Stack
          direction="row"
          spacing={0.8}
          alignItems="center"
          sx={{ flex: 1, minWidth: 0, cursor: hasNestedContent ? "pointer" : "default" }}
          onClick={() => {
            if (hasNestedContent) {
              toggleFolderCollapsed(node.path);
            }
          }}
        >
          {hasNestedContent ? (
            isExpanded ? (
              <ExpandMoreIcon fontSize="small" sx={{ color: "text.secondary" }} />
            ) : (
              <ChevronRightIcon fontSize="small" sx={{ color: "text.secondary" }} />
            )
          ) : (
            <Box sx={{ width: 20, height: 20 }} />
          )}
          <FolderOpenIcon fontSize="small" />
          <Typography fontWeight={depth === 0 ? 700 : 500} noWrap>
            {node.name}
          </Typography>
          <Typography variant="caption" color="text.secondary">
            {node.projects.length + node.children.length > 0 ? `${node.projects.length} пр.` : ""}
          </Typography>
        </Stack>
        {user?.role === "admin" && node.id && (
          <Stack direction="row" className="folder-actions">
            <Tooltip title="Действия папки">
              <IconButton
                size="small"
                onClick={(event) => openFolderActions(event, node)}
                sx={{ width: 28, height: 28 }}
              >
                <MoreVertIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          </Stack>
        )}
      </Stack>
        );
      })()}
      {expandedFolderPaths.includes(node.path) && (
        <>
      {node.projects.map((project) => (
        <Stack
          key={project.id}
          direction="row"
          alignItems="center"
          justifyContent="space-between"
          draggable={user?.role === "admin"}
          onDragStart={(event) => {
            setDraggingFolderId(null);
            setDraggingFolderPath(null);
            setDraggingProjectId(project.id);
            prepareDragPayload(event, "project", project.id);
          }}
          onDragEnd={() => {
            setDraggingProjectId(null);
            setDragOverFolderPath(null);
            setDraggingType(null);
          }}
          sx={{
            "& .project-actions": {
              opacity: 0,
              pointerEvents: "none",
              transition: "opacity 0.15s ease-in-out",
            },
            "&:hover .project-actions": {
              opacity: 1,
              pointerEvents: "auto",
            },
          }}
        >
          <ListItemButton sx={{ py: 1, pl: 4 + depth * 2 }} onClick={() => navigate(`/projects/${project.id}`)}>
            <ListItemIcon sx={{ minWidth: 32 }}>
              <DescriptionOutlinedIcon fontSize="small" color="action" />
            </ListItemIcon>
            <ListItemText
              primary={project.name}
              secondaryTypographyProps={{ component: "div" }}
              secondary={
                <Stack direction={{ xs: "column", md: "row" }} spacing={{ xs: 0.5, md: 1.5 }} alignItems={{ md: "center" }}>
                  <Typography variant="caption" color="text.secondary">
                    {project.status}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {project.start_date || "дата не задана"}
                  </Typography>
                </Stack>
              }
            />
          </ListItemButton>
          {user?.role === "admin" && (
            <Stack direction="row" alignItems="center" className="project-actions" sx={{ pr: 0.5 }}>
              <Tooltip title="Действия">
                <IconButton
                  size="small"
                  onClick={(event) => openProjectActions(event, project)}
                  sx={{ width: 28, height: 28 }}
                >
                  <MoreVertIcon fontSize="small" />
                </IconButton>
              </Tooltip>
            </Stack>
          )}
        </Stack>
      ))}
      {node.children.map((child) => (
        <Box key={child.path} sx={{ pl: 0.8 }}>
          {renderFolderNode(child, depth + 1)}
        </Box>
      ))}
        </>
      )}
      {depth === 0 && <Divider />}
    </Box>
  );

  return (
    <Stack spacing={3}>
      <Stack direction="row" justifyContent="space-between" alignItems="center">
        <Box>
          <Typography variant="h4" fontWeight={700}>
            Проекты
          </Typography>
        </Box>
        {user?.role === "admin" && (
          <IconButton
            onClick={openActionsMenu}
            sx={{
              border: "1px solid rgba(126,224,255,0.24)",
              borderRadius: 0,
              width: 36,
              height: 36,
            }}
          >
            <MoreVertIcon />
          </IconButton>
        )}
      </Stack>

      <Menu
        anchorEl={actionsAnchorEl}
        open={Boolean(actionsAnchorEl)}
        onClose={closeActionsMenu}
        anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
        transformOrigin={{ vertical: "top", horizontal: "right" }}
      >
        <MenuItem onClick={() => openCreateProjectDialog()}>
          <ListItemIcon>
            <AddIcon fontSize="small" />
          </ListItemIcon>
          Создать проект
        </MenuItem>
        <MenuItem onClick={() => openCreateFolderDialog()}>
          <ListItemIcon>
            <CreateNewFolderIcon fontSize="small" />
          </ListItemIcon>
          Создать папку
        </MenuItem>
      </Menu>

      <Menu
        anchorEl={projectActionsAnchorEl}
        open={Boolean(projectActionsAnchorEl)}
        onClose={closeProjectActions}
        anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
        transformOrigin={{ vertical: "top", horizontal: "right" }}
      >
        <MenuItem
          onClick={() => {
            if (activeProject) {
              openEditProjectDialog(activeProject);
            }
            closeProjectActions();
          }}
        >
          <ListItemIcon>
            <EditIcon fontSize="small" />
          </ListItemIcon>
          Редактировать
        </MenuItem>
        <MenuItem
          onClick={() => {
            if (activeProject) {
              void handleDeleteProject(activeProject.id, activeProject.name);
            }
            closeProjectActions();
          }}
        >
          <ListItemIcon>
            <DeleteOutlineIcon fontSize="small" />
          </ListItemIcon>
          Удалить
        </MenuItem>
      </Menu>

      <Menu
        anchorEl={folderActionsAnchorEl}
        open={Boolean(folderActionsAnchorEl)}
        onClose={closeFolderActions}
        anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
        transformOrigin={{ vertical: "top", horizontal: "right" }}
      >
        <MenuItem
          onClick={() => {
            if (activeFolderNode?.path) {
              openCreateProjectDialog(activeFolderNode.path);
            }
            closeFolderActions();
          }}
        >
          <ListItemIcon>
            <AddIcon fontSize="small" />
          </ListItemIcon>
          Создать проект внутри
        </MenuItem>
        <MenuItem
          onClick={() => {
            if (activeFolderNode?.id) {
              openCreateFolderDialog(activeFolderNode.id);
            }
            closeFolderActions();
          }}
        >
          <ListItemIcon>
            <CreateNewFolderIcon fontSize="small" />
          </ListItemIcon>
          Создать папку внутри
        </MenuItem>
      </Menu>

      {error && <Alert severity="error">{error}</Alert>}

      <Stack direction={{ xs: "column", md: "row" }} spacing={1.5}>
        <TextField
          label="Поиск проекта"
          placeholder="Название или описание"
          value={searchQuery}
          onChange={(event) => setSearchQuery(event.target.value)}
          fullWidth
        />
        <TextField select label="Статус" value={statusFilter} onChange={(event) => setStatusFilter(event.target.value as "all" | Project["status"])} sx={{ minWidth: 200 }}>
          <MenuItem value="all">Все статусы</MenuItem>
          <MenuItem value="active">active</MenuItem>
          <MenuItem value="completed">completed</MenuItem>
          <MenuItem value="archived">archived</MenuItem>
        </TextField>
      </Stack>

      <List disablePadding sx={{ border: "1px solid rgba(126,224,255,0.18)" }}>
        {groupedProjects.map((node) => renderFolderNode(node))}
        {groupedProjects.length === 0 && (
          <Box sx={{ px: 2, py: 2 }}>
            <Typography color="text.secondary">Проекты не найдены.</Typography>
          </Box>
        )}
      </List>

      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} fullWidth>
        <DialogTitle>Создать проект</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField label="Название" value={name} onChange={(e) => setName(e.target.value)} />
            <TextField
              label="Описание"
              multiline
              minRows={3}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
            <TextField
              label="Дата начала"
              type="date"
              value={startDate}
              onChange={(e) => setStartDate(e.target.value)}
              InputLabelProps={{ shrink: true }}
            />
            <TextField
              label="Дата окончания"
              type="date"
              value={endDate}
              onChange={(e) => setEndDate(e.target.value)}
              InputLabelProps={{ shrink: true }}
            />
            <TextField select label="Папка проекта" value={selectedFolder} onChange={(event) => setSelectedFolder(event.target.value)}>
              {folderPaths.map((folder) => (
                <MenuItem key={folder} value={folder}>
                  {folder}
                </MenuItem>
              ))}
            </TextField>
            <TextField
              select
              label="Участники проекта"
              value={selectedMemberIds}
              onChange={(event) => {
                const value = event.target.value;
                setSelectedMemberIds(typeof value === "string" ? value.split(",") : value);
              }}
              SelectProps={{
                multiple: true,
                renderValue: (selected) =>
                  (selected as string[])
                    .map((id) => usersCatalog.find((item) => item.id === id)?.username ?? id)
                    .join(", "),
              }}
            >
              {usersCatalog.map((candidate) => (
                <MenuItem key={candidate.id} value={candidate.id}>
                  <Checkbox size="small" checked={selectedMemberIds.includes(candidate.id)} />
                  <ListItemText primary={`${candidate.username} (${candidate.role})`} secondary={candidate.email} />
                </MenuItem>
              ))}
            </TextField>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => {
              setCreateOpen(false);
              setName("");
              setDescription("");
              setStartDate("");
              setEndDate("");
              setSelectedMemberIds([]);
              setSelectedFolder(DEFAULT_FOLDER_NAME);
            }}
          >
            Отмена
          </Button>
          <Button variant="contained" onClick={() => void handleCreate()} disabled={!name.trim() || creatingProject}>
            Создать
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={createFolderOpen} onClose={() => setCreateFolderOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>Создать папку проекта</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField
              label="Название папки"
              placeholder="Например: Клиенты"
              value={folderName}
              onChange={(event) => setFolderName(event.target.value)}
            />
            <TextField
              select
              label="Родительская папка"
              value={folderParentId}
              onChange={(event) => setFolderParentId(event.target.value)}
            >
              <MenuItem value="">Корень</MenuItem>
              {folders.map((folder) => (
                <MenuItem key={folder.id} value={folder.id}>
                  {folder.path}
                </MenuItem>
              ))}
            </TextField>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateFolderOpen(false)}>Отмена</Button>
          <Button variant="contained" onClick={() => void submitCreateFolder()} disabled={!folderName.trim() || creatingFolder}>
            Создать
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={editOpen} onClose={() => setEditOpen(false)} fullWidth>
        <DialogTitle>Редактировать проект</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField label="Название" value={editingProjectName} onChange={(event) => setEditingProjectName(event.target.value)} />
            <TextField
              label="Описание"
              multiline
              minRows={3}
              value={editingProjectDescription}
              onChange={(event) => setEditingProjectDescription(event.target.value)}
            />
            <TextField
              label="Дата начала"
              type="date"
              value={editingProjectStartDate}
              onChange={(event) => setEditingProjectStartDate(event.target.value)}
              InputLabelProps={{ shrink: true }}
            />
            <TextField
              label="Дата окончания"
              type="date"
              value={editingProjectEndDate}
              onChange={(event) => setEditingProjectEndDate(event.target.value)}
              InputLabelProps={{ shrink: true }}
            />
            <TextField
              select
              label="Статус"
              value={editingProjectStatus}
              onChange={(event) => setEditingProjectStatus(event.target.value as Project["status"])}
            >
              <MenuItem value="active">active</MenuItem>
              <MenuItem value="completed">completed</MenuItem>
              <MenuItem value="archived">archived</MenuItem>
            </TextField>
            <TextField
              select
              label="Папка проекта"
              value={editingProjectFolder}
              onChange={(event) => setEditingProjectFolder(event.target.value)}
            >
              {folderPaths.map((folder) => (
                <MenuItem key={folder} value={folder}>
                  {folder}
                </MenuItem>
              ))}
            </TextField>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => {
              setEditOpen(false);
              setEditingProjectId(null);
            }}
          >
            Отмена
          </Button>
          <Button variant="contained" onClick={() => void submitProjectEdit()} disabled={!editingProjectName.trim() || updatingProject}>
            Сохранить
          </Button>
        </DialogActions>
      </Dialog>
    </Stack>
  );
}
