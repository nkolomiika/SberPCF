import DnsIcon from "@mui/icons-material/Dns";
import { Box, Divider, List, ListItemButton, ListItemText, Popover, Stack, Typography } from "@mui/material";

import type { Host } from "../types";

type Props = {
  open: boolean;
  anchorEl: Element | null;
  hosts: Host[];
  onClose: () => void;
  onSelectHost: (hostId: string) => void;
};

export function ProjectHostsTreePopover({ open, anchorEl, hosts, onClose, onSelectHost }: Props) {
  return (
    <Popover
      open={open}
      anchorEl={anchorEl}
      onClose={onClose}
      anchorOrigin={{ vertical: "top", horizontal: "right" }}
      transformOrigin={{ vertical: "top", horizontal: "left" }}
      PaperProps={{
        sx: {
          width: 320,
          maxHeight: "70vh",
          backgroundColor: "rgba(8,17,31,0.97)",
          border: "1px solid rgba(126,224,255,0.25)",
          color: "#ffffff",
          backdropFilter: "blur(8px)",
        },
      }}
    >
      <Stack sx={{ px: 1.25, py: 1, borderBottom: "1px solid rgba(126,224,255,0.18)" }}>
        <Typography variant="subtitle2" fontWeight={700}>
          Хосты проекта
        </Typography>
      </Stack>
      <Divider />
      <Box sx={{ overflowY: "auto", maxHeight: "calc(70vh - 48px)", py: 0.5 }}>
        {hosts.length === 0 ? (
          <Box sx={{ px: 1.5, py: 2 }}>
            <Typography variant="body2" color="text.secondary">
              Хосты не добавлены.
            </Typography>
          </Box>
        ) : (
          <List dense disablePadding>
            {hosts.map((host) => (
              <ListItemButton
                key={host.id}
                onClick={() => {
                  onSelectHost(host.id);
                  onClose();
                }}
                sx={{ py: 0.65 }}
              >
                <DnsIcon fontSize="small" sx={{ color: "rgba(126,224,255,0.55)", mr: 1 }} />
                <ListItemText
                  primary={host.hostname || host.ip_address || "unknown-host"}
                  secondary={host.hostname ? host.ip_address || undefined : undefined}
                  primaryTypographyProps={{ noWrap: true, fontSize: "0.85rem" }}
                  secondaryTypographyProps={{ noWrap: true, fontSize: "0.72rem" }}
                />
              </ListItemButton>
            ))}
          </List>
        )}
      </Box>
    </Popover>
  );
}
