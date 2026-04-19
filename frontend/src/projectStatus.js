export const PROJECT_STATUS_ORDER = [
    "active",
    "handover_to_development",
    "vulnerability_recheck",
    "completed",
    "archived",
];
export const PROJECT_STATUS_LABELS = {
    active: "Активен",
    handover_to_development: "Передано команде разработки",
    vulnerability_recheck: "На перепроверке уязвимостей",
    completed: "Завершён",
    archived: "Архив",
};
export const PROJECT_STATUS_CHIP_SX = {
    active: {
        bgcolor: "rgba(76,175,80,0.16)",
        color: "#a5d6a7",
        border: "1px solid rgba(76,175,80,0.38)",
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
