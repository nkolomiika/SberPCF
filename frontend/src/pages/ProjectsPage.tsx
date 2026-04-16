import AddIcon from "@mui/icons-material/Add";
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
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { createProject, getProjects } from "../api";
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

  const loadProjects = async () => {
    try {
      const response = await getProjects();
      if (!response || !Array.isArray(response.items)) {
        throw new Error("projects payload shape is invalid");
      }
      setProjects(response.items);
    } catch {
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

      <List disablePadding sx={{ border: "1px solid rgba(126,224,255,0.18)" }}>
        {projects.map((project, index) => (
          <Box key={project.id}>
            <ListItemButton sx={{ py: 1.5 }} onClick={() => navigate(`/projects/${project.id}`)}>
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
                  </Stack>
                }
              />
            </ListItemButton>
            {index < projects.length - 1 && <Divider />}
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
