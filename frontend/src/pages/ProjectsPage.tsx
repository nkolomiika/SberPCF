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
  Box,
  Button,
  Chip,
  Collapse,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  List,
  ListItemIcon,
  ListItemText,
  Menu,
  MenuItem,
  Stack,
  TextField,
  Typography,
  IconButton,
} from "@mui/material";
import { Fragment, type DragEvent, type MouseEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  addProjectMember,
  createProject,
  createProjectFolder,
  deleteProject,
  deleteProjectFolder,
  getApiErrorMessage,
  getProjectFolders,
  getProjects,
  getUsers,
  moveProjectFolder,
  updateProject,
} from "../api";
import { MarkdownEditor } from "../components/MarkdownEditor";
import { PROJECT_STATUS_CHIP_SX, PROJECT_STATUS_LABELS, PROJECT_STATUS_ORDER } from "../projectStatus";
import { useAuthStore } from "../store";
import type { Project, ProjectFolder, ProjectStatus, User } from "../types";
import { useErrorToast } from "../useErrorToast";

const DEFAULT_PROJECT_DURATION_DAYS = 14;
const ROOT_FOLDER_LABEL = "Корень";
const ROOT_FOLDER_NODE: FolderTreeNode = { id: null, name: "", path: "", children: [], projects: [] };

type FolderTreeNode = {
  id: number | null;
  name: string;
  path: string;
  children: FolderTreeNode[];
  projects: Project[];
};

type DragPayload = {
  type: "project" | "folder";
  id: number;
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
  const [deleteFolderTarget, setDeleteFolderTarget] = useState<FolderTreeNode | null>(null);
  const [deleteFolderBusy, setDeleteFolderBusy] = useState<boolean>(false);
  const [activeProject, setActiveProject] = useState<Project | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [editOpen, setEditOpen] = useState(false);
  const [createFolderOpen, setCreateFolderOpen] = useState(false);
  const [folderName, setFolderName] = useState("");
  const [folderParentId, setFolderParentId] = useState<number | "">("");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [usersCatalog, setUsersCatalog] = useState<User[]>([]);
  const [selectedMemberIds, setSelectedMemberIds] = useState<number[]>([]);
  const [selectedFolder, setSelectedFolder] = useState("");
  const [folderPaths, setFolderPaths] = useState<string[]>([]);
  const [creatingProject, setCreatingProject] = useState(false);
  const [updatingProject, setUpdatingProject] = useState(false);
  const [creatingFolder, setCreatingFolder] = useState(false);
  const [draggingProjectId, setDraggingProjectId] = useState<number | null>(null);
  const [draggingFolderId, setDraggingFolderId] = useState<number | null>(null);
  const [draggingFolderPath, setDraggingFolderPath] = useState<string | null>(null);
  const [dragOverFolderPath, setDragOverFolderPath] = useState<string | null>(null);
  const [dropLineTarget, setDropLineTarget] = useState<string | null>(null);
  const [, setDraggingType] = useState<"project" | "folder" | null>(null);
  const [expandedFolderPaths, setExpandedFolderPaths] = useState<string[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | ProjectStatus>("all");
  const [editingProjectName, setEditingProjectName] = useState("");
  const [editingProjectId, setEditingProjectId] = useState<number | null>(null);
  const [editingProjectDescription, setEditingProjectDescription] = useState("");
  const [editingProjectStartDate, setEditingProjectStartDate] = useState("");
  const [editingProjectEndDate, setEditingProjectEndDate] = useState("");
  const [editingProjectStatus, setEditingProjectStatus] = useState<ProjectStatus>("active");
  const [editingProjectFolder, setEditingProjectFolder] = useState("");
  const projectListRef = useRef<HTMLUListElement | null>(null);
  const autoScrollFrameRef = useRef<number | null>(null);
  const autoScrollVelocityRef = useRef(0);
  const autoExpandTimerRef = useRef<number | null>(null);
  const autoExpandTargetRef = useRef<string | null>(null);

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
    } catch (error) {
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
    const folderByPath = new Map(folders.map((item) => [item.path, item] as const));
    const root: FolderTreeNode = { id: null, name: "", path: "", children: [], projects: [] };
    const nodeMap = new Map<string, FolderTreeNode>([["", root]]);

    const ensurePath = (pathValue: string) => {
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
    return { rootProjects: root.projects, topFolders: root.children };
  }, [folderPaths, folders, visibleProjects]);

  const folderPathById = useMemo(() => {
    return new Map(folders.map((folder) => [folder.id, folder.path] as const));
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
      } catch (error) {
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
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось создать проект"));
    } finally {
      setCreatingProject(false);
    }
  };

  const handleDeleteProject = async (projectId: number, projectName: string) => {
    if (!window.confirm(`Удалить проект "${projectName}"?`)) {
      return;
    }
    setError(null);
    try {
      await deleteProject(projectId);
      await loadProjects();
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось удалить проект"));
    }
  };

  const openActionsMenu = (event: MouseEvent<HTMLElement>) => {
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

  const openCreateFolderDialog = (parentId: number | "" = "", seedName = "") => {
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
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось создать папку проекта"));
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

  const countFolderDescendants = (node: FolderTreeNode): { folders: number; projects: number } => {
    if (!node.path) return { folders: 0, projects: 0 };
    const prefix = `${node.path}/`;
    const subFolders = folders.filter((f) => f.path === node.path || f.path.startsWith(prefix)).length;
    const subProjects = projects.filter((p) => (p.folder ?? "") === node.path || (p.folder ?? "").startsWith(prefix)).length;
    return { folders: Math.max(0, subFolders - 1), projects: subProjects };
  };

  const handleConfirmDeleteFolder = async () => {
    const target = deleteFolderTarget;
    if (!target?.id) return;
    setDeleteFolderBusy(true);
    try {
      await deleteProjectFolder(target.id);
      setDeleteFolderTarget(null);
      await loadProjects();
    } catch (caught) {
      setError(getApiErrorMessage(caught, "Не удалось удалить папку"));
    } finally {
      setDeleteFolderBusy(false);
    }
  };

  const openEditProjectDialog = (project: Project) => {
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
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось обновить проект"));
    } finally {
      setUpdatingProject(false);
    }
  };

  const moveProjectToFolder = async (projectId: number, folderPath: string) => {
    const normalizedFolder = (folderPath || "").trim();
    setError(null);
    try {
      await updateProject(projectId, { folder: normalizedFolder });
      await loadProjects();
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось перенести проект в папку"));
    } finally {
      setDraggingProjectId(null);
      setDragOverFolderPath(null);
      stopAutoScroll();
    }
  };

  const moveFolderToFolder = async (folderId: number, targetNode: FolderTreeNode) => {
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
    } catch (error) {
      setError(getApiErrorMessage(error, "Не удалось переместить папку"));
    } finally {
      setDraggingFolderId(null);
      setDraggingFolderPath(null);
      setDragOverFolderPath(null);
      stopAutoScroll();
    }
  };

  const toggleFolderCollapsed = (folderPath: string) => {
    setExpandedFolderPaths((prev) => (prev.includes(folderPath) ? prev.filter((item) => item !== folderPath) : [...prev, folderPath]));
  };

  const prepareDragPayload = (event: DragEvent, type: "project" | "folder", id: number) => {
    setDraggingType(type);
    event.dataTransfer.effectAllowed = "move";
    event.dataTransfer.setData("text/plain", `${type}:${id}`);
    // Use a tiny transparent drag preview to avoid large ghost artifacts.
    const img = new Image();
    img.src =
      "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==";
    event.dataTransfer.setDragImage(img, 0, 0);
  };

  const parseDragPayload = (event: DragEvent): DragPayload | null => {
    const raw = event.dataTransfer.getData("text/plain") || "";
    const [type, id] = raw.split(":");
    if ((type === "project" || type === "folder") && id) {
      return { type, id: Number(id) };
    }
    if (draggingProjectId) {
      return { type: "project", id: draggingProjectId };
    }
    if (draggingFolderId) {
      return { type: "folder", id: draggingFolderId };
    }
    return null;
  };

  const getFolderSourcePath = useCallback(
    (folderId: number) => {
      return folderId === draggingFolderId ? draggingFolderPath : folderPathById.get(folderId) ?? null;
    },
    [draggingFolderId, draggingFolderPath, folderPathById]
  );

  const stopAutoScroll = useCallback(() => {
    autoScrollVelocityRef.current = 0;
    if (autoScrollFrameRef.current !== null) {
      window.cancelAnimationFrame(autoScrollFrameRef.current);
      autoScrollFrameRef.current = null;
    }
  }, []);

  const startAutoScroll = useCallback((velocity: number) => {
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

  const updateAutoScrollFromPointer = useCallback(
    (clientY: number) => {
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
    },
    [startAutoScroll, stopAutoScroll]
  );

  const stopAutoExpand = useCallback(() => {
    if (autoExpandTimerRef.current !== null) {
      window.clearTimeout(autoExpandTimerRef.current);
      autoExpandTimerRef.current = null;
    }
    autoExpandTargetRef.current = null;
  }, []);

  const scheduleAutoExpand = useCallback(
    (folderPath: string, canExpand: boolean) => {
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
    },
    [expandedFolderPaths, stopAutoExpand]
  );

  const canDropOnNode = (dragging: DragPayload, targetNode: FolderTreeNode) => {
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

  const renderDropLine = (targetNode: FolderTreeNode, lineKey: string, depth: number) => (
    <Box
      key={lineKey}
      onDragOver={(event) => {
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
      }}
      onDragLeave={() => {
        if (dropLineTarget === lineKey) {
          setDropLineTarget(null);
        }
      }}
      onDrop={(event) => {
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
      }}
      sx={{
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
      }}
    />
  );

  const getNestedProjectsCount = (node: FolderTreeNode): number => {
    return node.projects.length + node.children.reduce((total, child) => total + getNestedProjectsCount(child), 0);
  };

  const renderProjectRow = (project: Project, depth: number, parentNode: FolderTreeNode): JSX.Element => (
    <Fragment key={project.id}>
      {renderDropLine(parentNode, `before-project:${project.id}`, depth)}
      <Stack
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
          setDropLineTarget(null);
          setDraggingType(null);
          stopAutoScroll();
          stopAutoExpand();
        }}
        onClick={() => navigate(`/projects/${project.id}`)}
        sx={{
          px: 1.2,
          py: 0.75,
          pl: 1.2 + depth * 2.1,
          cursor: "pointer",
          borderRadius: 0,
          "& .project-actions": {
            opacity: 0,
            pointerEvents: "none",
            transition: "opacity 0.15s ease-in-out",
          },
          "&:hover": {
            backgroundColor: "rgba(126,224,255,0.06)",
          },
          "&:hover .project-actions": {
            opacity: 1,
            pointerEvents: "auto",
          },
        }}
      >
        <Stack direction="row" spacing={0.8} alignItems="center" sx={{ minWidth: 0, flex: 1 }}>
          <DescriptionOutlinedIcon fontSize="small" sx={{ color: "text.secondary" }} />
          <Typography fontWeight={500} noWrap>
            {project.name}
          </Typography>
          <Chip size="small" label={PROJECT_STATUS_LABELS[project.status]} sx={PROJECT_STATUS_CHIP_SX[project.status]} />
          <Typography variant="caption" color="text.secondary" noWrap>
            {project.start_date || "дата не задана"}
          </Typography>
        </Stack>
        {user?.role === "admin" && (
          <Stack direction="row" alignItems="center" className="project-actions">
            <IconButton
              size="small"
              aria-label="Действия проекта"
              onClick={(event) => {
                event.stopPropagation();
                openProjectActions(event, project);
              }}
              sx={{ width: 28, height: 28, "&:hover": { backgroundColor: "transparent" } }}
            >
              <MoreVertIcon fontSize="small" />
            </IconButton>
          </Stack>
        )}
      </Stack>
    </Fragment>
  );

  const renderFolderNode = (node: FolderTreeNode, depth = 0, parentNode: FolderTreeNode = ROOT_FOLDER_NODE): JSX.Element => (
    <Box key={node.path}>
      {renderDropLine(parentNode, `before-folder:${node.path}`, depth)}
      {(() => {
        const hasNestedContent = node.children.length > 0 || node.projects.length > 0;
        const isExpanded = expandedFolderPaths.includes(node.path);
        const isFolderDropActive = dragOverFolderPath === node.path;
        return (
      <Stack
        direction="row"
        alignItems="center"
        justifyContent="space-between"
        draggable={Boolean(user?.role === "admin" && node.id && node.path !== "")}
        onDragStart={(event) => {
          if (!(user?.role === "admin" && node.id && node.path !== "")) {
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
          setDropLineTarget(null);
          setDraggingType(null);
          stopAutoScroll();
          stopAutoExpand();
        }}
        onDragOver={(event) => {
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
        }}
        onDragLeave={() => {
          if (dragOverFolderPath === node.path) {
            setDragOverFolderPath(null);
          }
          stopAutoExpand();
        }}
        onDrop={(event) => {
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
        }}
        sx={{
          px: 1.2,
          py: 0.75,
          pl: 1.2 + depth * 2.1,
          backgroundColor: isFolderDropActive ? "rgba(126,224,255,0.14)" : "transparent",
          borderRadius: 0,
          "& .folder-actions": {
            opacity: 0,
            pointerEvents: "none",
            transition: "opacity 0.15s ease-in-out",
          },
          "&:hover": {
            backgroundColor: isFolderDropActive ? "rgba(126,224,255,0.14)" : "rgba(126,224,255,0.06)",
          },
          "&:hover .folder-actions": {
            opacity: 1,
            pointerEvents: "auto",
          },
          outline: isFolderDropActive ? "1px solid rgba(126,224,255,0.55)" : "none",
          boxShadow: isFolderDropActive ? "inset 0 0 0 1px rgba(126,224,255,0.22)" : "none",
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
            // Один и тот же ExpandMoreIcon: открыто = 0deg, закрыто = −90deg.
            // Плавная transition на rotate синхронизирует поворот с анимацией Collapse.
            <ExpandMoreIcon
              fontSize="small"
              sx={{
                color: "text.secondary",
                transform: isExpanded ? "rotate(0deg)" : "rotate(-90deg)",
                transition: "transform .22s ease",
              }}
            />
          ) : (
            <Box sx={{ width: 20, height: 20 }} />
          )}
          <FolderOpenIcon fontSize="small" />
          <Typography fontWeight={depth === 0 ? 700 : 500} noWrap>
            {node.name}
          </Typography>
          <Typography variant="caption" color="text.secondary">
            {getNestedProjectsCount(node) > 0 ? `${getNestedProjectsCount(node)} пр.` : ""}
          </Typography>
        </Stack>
        {user?.role === "admin" && node.id && (
          <Stack direction="row" className="folder-actions">
            {isFolderDropActive && (
              <Typography variant="caption" color="primary.main" sx={{ alignSelf: "center", mr: 0.5, whiteSpace: "nowrap" }}>
                Вложить в папку
              </Typography>
            )}
            <IconButton
              size="small"
              aria-label="Действия папки"
              onClick={(event) => openFolderActions(event, node)}
              sx={{ width: 28, height: 28, "&:hover": { backgroundColor: "transparent" } }}
            >
              <MoreVertIcon fontSize="small" />
            </IconButton>
          </Stack>
        )}
      </Stack>
        );
      })()}
      {/*
        Плавное раскрытие/сворачивание содержимого папки. mountOnEnter,
        чтобы скрытые папки не рендерились до первого раскрытия (важно для
        крупных проектных деревьев).
      */}
      <Collapse in={expandedFolderPaths.includes(node.path)} timeout={240} mountOnEnter>
        <Box>
      {node.projects.map((project) => renderProjectRow(project, depth + 1, node))}
      {node.children.map((child) => (
        <Box key={child.path} sx={{ pl: 0.8 }}>
          {renderFolderNode(child, depth + 1, node)}
        </Box>
      ))}
      {renderDropLine(node, `after-folder-content:${node.path}`, depth + 1)}
        </Box>
      </Collapse>
    </Box>
  );

  return (
    <Stack spacing={3}>
      <Stack direction="row" justifyContent="space-between" alignItems="flex-start" gap={2}>
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
              width: 40,
              height: 40,
              backgroundColor: "rgba(15,27,45,0.74)",
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
        <MenuItem
          onClick={() => {
            const target = activeFolderNode;
            closeFolderActions();
            if (target?.id) {
              setDeleteFolderTarget(target);
            }
          }}
          sx={{ color: "#ff8a80" }}
        >
          <ListItemIcon>
            <DeleteOutlineIcon fontSize="small" sx={{ color: "#ff8a80" }} />
          </ListItemIcon>
          Удалить папку
        </MenuItem>
      </Menu>

      <Dialog open={Boolean(deleteFolderTarget)} onClose={() => !deleteFolderBusy && setDeleteFolderTarget(null)}>
        <DialogTitle>Удалить папку «{deleteFolderTarget?.name}»?</DialogTitle>
        <DialogContent>
          {(() => {
            if (!deleteFolderTarget) return null;
            const stats = countFolderDescendants(deleteFolderTarget);
            return (
              <Stack spacing={1}>
                <Typography variant="body2">
                  Будут безвозвратно удалены вложенные сущности:
                </Typography>
                <Typography variant="body2" sx={{ pl: 1 }}>
                  • Подпапок: <strong>{stats.folders}</strong>
                </Typography>
                <Typography variant="body2" sx={{ pl: 1 }}>
                  • Проектов (со всеми данными): <strong>{stats.projects}</strong>
                </Typography>
                <Typography variant="body2" color="warning.main">
                  Эта операция необратима.
                </Typography>
              </Stack>
            );
          })()}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteFolderTarget(null)} disabled={deleteFolderBusy}>
            Отмена
          </Button>
          <Button color="error" onClick={handleConfirmDeleteFolder} disabled={deleteFolderBusy}>
            {deleteFolderBusy ? "Удаление…" : "Удалить"}
          </Button>
        </DialogActions>
      </Dialog>

      <Box
        sx={{
          border: "1px solid rgba(126,224,255,0.12)",
          borderRadius: 0,
          p: 2,
          backgroundColor: "rgba(15,27,45,0.56)",
        }}
      >
        <Stack spacing={2}>
          <Stack direction={{ xs: "column", lg: "row" }} spacing={1.5} alignItems={{ lg: "center" }} justifyContent="space-between">
            <Stack direction="row" spacing={1} flexWrap="wrap">
              <Chip label={`Проектов: ${treeStats.totalProjects}`} variant="outlined" />
              <Chip label={`Папок: ${treeStats.totalFolders}`} variant="outlined" />
              <Chip label={`Вложенных папок: ${treeStats.nestedFolders}`} variant="outlined" />
            </Stack>
          </Stack>
          <Stack direction={{ xs: "column", md: "row" }} spacing={1.5}>
            <TextField
              label="Поиск проекта"
              value={searchQuery}
              onChange={(event) => setSearchQuery(event.target.value)}
              fullWidth
            />
            <TextField
              select
              label="Статус"
              value={statusFilter}
              onChange={(event) => setStatusFilter(event.target.value as "all" | ProjectStatus)}
              sx={{ minWidth: 220 }}
            >
              <MenuItem value="all">Все статусы</MenuItem>
              {PROJECT_STATUS_ORDER.map((status) => (
                <MenuItem key={status} value={status}>
                  {PROJECT_STATUS_LABELS[status]}
                </MenuItem>
              ))}
            </TextField>
          </Stack>
        </Stack>
      </Box>

      <List
        ref={projectListRef}
        disablePadding
        onDragOver={(event) => {
          const dragging = parseDragPayload(event);
          if (!dragging) {
            stopAutoScroll();
            return;
          }
          event.preventDefault();
          updateAutoScrollFromPointer(event.clientY);
        }}
        onDragLeave={(event) => {
          if (!event.currentTarget.contains(event.relatedTarget as Node | null)) {
            stopAutoScroll();
            stopAutoExpand();
            setDragOverFolderPath(null);
            setDropLineTarget(null);
          }
        }}
        onDrop={(event) => {
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
        }}
        sx={{
          border: "1px solid rgba(126,224,255,0.14)",
          borderRadius: 0,
          backgroundColor: "rgba(15,27,45,0.58)",
          maxHeight: "calc(100vh - 300px)",
          overflowY: "auto",
          p: 1,
        }}
      >
        {renderDropLine(ROOT_FOLDER_NODE, "root-drop-line", 0)}
        {groupedProjects.rootProjects.map((project) => renderProjectRow(project, 0, ROOT_FOLDER_NODE))}
        {groupedProjects.topFolders.map((node) => renderFolderNode(node))}
        {renderDropLine(ROOT_FOLDER_NODE, "root-drop-line-end", 0)}
        {groupedProjects.rootProjects.length === 0 && groupedProjects.topFolders.length === 0 && (
          <Box sx={{ px: 2, py: 2 }}>
            <Typography color="text.secondary">Проекты не найдены.</Typography>
          </Box>
        )}
      </List>

      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>Создать проект</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField label="Название" value={name} onChange={(e) => setName(e.target.value)} />
            <MarkdownEditor
              label="Описание"
              minRows={3}
              value={description}
              onChange={(next) => setDescription(next || "")}
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
              <MenuItem value="">{ROOT_FOLDER_LABEL}</MenuItem>
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
                setSelectedMemberIds(typeof value === "string" ? value.split(",").map(Number) : value);
              }}
              SelectProps={{
                multiple: true,
                renderValue: (selected) =>
                  (selected as number[])
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
              setSelectedFolder("");
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
              value={folderName}
              onChange={(event) => setFolderName(event.target.value)}
            />
            <TextField
              select
              label="Родительская папка"
              value={folderParentId}
              onChange={(event) => setFolderParentId(event.target.value === "" ? "" : Number(event.target.value))}
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

      <Dialog open={editOpen} onClose={() => setEditOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>Редактировать проект</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField label="Название" value={editingProjectName} onChange={(event) => setEditingProjectName(event.target.value)} />
            <MarkdownEditor
              label="Описание"
              minRows={3}
              value={editingProjectDescription}
              onChange={(next) => setEditingProjectDescription(next || "")}
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
              onChange={(event) => setEditingProjectStatus(event.target.value as ProjectStatus)}
            >
              {PROJECT_STATUS_ORDER.map((status) => (
                <MenuItem key={status} value={status}>
                  {PROJECT_STATUS_LABELS[status]}
                </MenuItem>
              ))}
            </TextField>
            <TextField
              select
              label="Папка проекта"
              value={editingProjectFolder}
              onChange={(event) => setEditingProjectFolder(event.target.value)}
            >
              <MenuItem value="">{ROOT_FOLDER_LABEL}</MenuItem>
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
