import type { SxProps, Theme } from "@mui/material/styles";

import type { ProjectStatus } from "./types";

export const PROJECT_STATUS_ORDER: ProjectStatus[] = [
  "active",
  "freeze",
  "handover_to_development",
  "vulnerability_recheck",
  "completed",
  "archived",
];

export const PROJECT_STATUS_LABELS: Record<ProjectStatus, string> = {
  active: "Активен",
  freeze: "Заморожен",
  handover_to_development: "Передано команде разработки",
  vulnerability_recheck: "На перепроверке уязвимостей",
  completed: "Завершён",
  archived: "Архив",
};

export const PROJECT_STATUS_CHIP_SX: Record<ProjectStatus, SxProps<Theme>> = {
  active: {
    bgcolor: "rgba(76,175,80,0.16)",
    color: "#a5d6a7",
    border: "1px solid rgba(76,175,80,0.38)",
  },
  freeze: {
    bgcolor: "rgba(0,188,212,0.18)",
    color: "#80deea",
    border: "1px solid rgba(0,188,212,0.4)",
  },
  handover_to_development: {
    bgcolor: "rgba(156,39,176,0.16)",
    color: "#ce93d8",
    border: "1px solid rgba(156,39,176,0.36)",
  },
  vulnerability_recheck: {
    bgcolor: "rgba(33,150,243,0.18)",
    color: "#90caf9",
    border: "1px solid rgba(33,150,243,0.38)",
  },
  completed: {
    bgcolor: "rgba(255,152,0,0.18)",
    color: "#ffcc80",
    border: "1px solid rgba(255,152,0,0.4)",
  },
  archived: {
    bgcolor: "rgba(96,125,139,0.2)",
    color: "#b0bec5",
    border: "1px solid rgba(96,125,139,0.38)",
  },
};
