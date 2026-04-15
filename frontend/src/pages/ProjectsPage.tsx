import AddIcon from "@mui/icons-material/Add";
import FolderOpenIcon from "@mui/icons-material/FolderOpen";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Grid2 as Grid,
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

      <Grid container spacing={2}>
        {projects.map((project) => (
          <Grid size={{ xs: 12, md: 6, lg: 4 }} key={project.id}>
            <Card
              sx={{ cursor: "pointer", border: "1px solid #2a3c5f", height: "100%" }}
              onClick={() => navigate(`/projects/${project.id}`)}
            >
              <CardContent>
                <Stack spacing={1}>
                  <Stack direction="row" spacing={1} alignItems="center">
                    <FolderOpenIcon color="primary" />
                    <Typography variant="h6">{project.name}</Typography>
                  </Stack>
                  <Typography color="text.secondary">{project.description || "Без описания"}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Статус: {project.status}
                  </Typography>
                </Stack>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

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
