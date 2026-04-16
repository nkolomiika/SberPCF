import AddIcon from "@mui/icons-material/Add";
import DeleteOutlineIcon from "@mui/icons-material/DeleteOutline";
import FolderOpenIcon from "@mui/icons-material/FolderOpen";
import {
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
  MenuItem,
  Stack,
  TextField,
  Typography,
  IconButton,
  Tooltip,
} from "@mui/material";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { createProject, deleteProject, getProjects } from "../api";
import { useAuthStore } from "../store";
import type { Project } from "../types";

export function ProjectsPage() {
  const navigate = useNavigate();
  const user = useAuthStore((s) => s.user);
  const [projects, setProjects] = useState<Project[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | Project["status"]>("all");
  const [sortBy, setSortBy] = useState<"start_date_desc" | "start_date_asc" | "status_asc" | "status_desc">("start_date_desc");

  const loadProjects = useCallback(async () => {
    try {
      const response = await getProjects(1, 200, statusFilter === "all" ? undefined : statusFilter);
      if (!response || !Array.isArray(response.items)) {
        throw new Error("projects payload shape is invalid");
      }
      setProjects(response.items);
    } catch {
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

    const statusWeight: Record<Project["status"], number> = {
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

  const handleCreate = async () => {
    await createProject({ name, description });
    setCreateOpen(false);
    setName("");
    setDescription("");
    await loadProjects();
  };

  const handleDeleteProject = async (projectId: string, projectName: string) => {
    if (!window.confirm(`Удалить проект "${projectName}"?`)) {
      return;
    }
    await deleteProject(projectId);
    await loadProjects();
  };

  return (
    <Stack spacing={3}>
      <Stack direction="row" justifyContent="space-between" alignItems="center">
        <Box>
          <Typography variant="h4" fontWeight={700}>
            Проекты
          </Typography>
          <Typography color="text.secondary">Управляйте пентест-проектами и рабочими командами</Typography>
        </Box>
        {user?.role === "admin" && (
          <Button variant="contained" startIcon={<AddIcon />} onClick={() => setCreateOpen(true)}>
            Новый проект
          </Button>
        )}
      </Stack>

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
        <TextField
          select
          label="Сортировка"
          value={sortBy}
          onChange={(event) => setSortBy(event.target.value as "start_date_desc" | "start_date_asc" | "status_asc" | "status_desc")}
          sx={{ minWidth: 260 }}
        >
          <MenuItem value="start_date_desc">Дата начала: новые сверху</MenuItem>
          <MenuItem value="start_date_asc">Дата начала: старые сверху</MenuItem>
          <MenuItem value="status_asc">Статус: active → archived</MenuItem>
          <MenuItem value="status_desc">Статус: archived → active</MenuItem>
        </TextField>
      </Stack>

      <List disablePadding sx={{ border: "1px solid rgba(126,224,255,0.18)" }}>
        {visibleProjects.map((project, index) => (
          <Box key={project.id}>
            <Stack direction="row" alignItems="center" justifyContent="space-between">
              <ListItemButton sx={{ py: 1.5, flex: 1 }} onClick={() => navigate(`/projects/${project.id}`)}>
                <ListItemIcon sx={{ minWidth: 36 }}>
                  <FolderOpenIcon color="primary" />
                </ListItemIcon>
                <ListItemText
                  primary={project.name}
                  secondary={
                    <Stack direction={{ xs: "column", md: "row" }} spacing={{ xs: 0.5, md: 2 }} alignItems={{ md: "center" }}>
                      <Typography variant="body2" color="text.secondary">
                        {project.description || "Без описания"}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        Статус: {project.status}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        Старт: {project.start_date || "не задана"}
                      </Typography>
                    </Stack>
                  }
                />
              </ListItemButton>
              {user?.role === "admin" && (
                <Tooltip title="Удалить проект">
                  <IconButton
                    color="error"
                    sx={{ mr: 1 }}
                    onClick={(event) => {
                      event.stopPropagation();
                      void handleDeleteProject(project.id, project.name);
                    }}
                  >
                    <DeleteOutlineIcon />
                  </IconButton>
                </Tooltip>
              )}
            </Stack>
            {index < visibleProjects.length - 1 && <Divider />}
          </Box>
        ))}
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
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateOpen(false)}>Отмена</Button>
          <Button variant="contained" onClick={() => void handleCreate()} disabled={!name.trim()}>
            Создать
          </Button>
        </DialogActions>
      </Dialog>
    </Stack>
  );
}
