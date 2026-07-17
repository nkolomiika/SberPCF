import { TextField, Stack, MenuItem } from "sberpcf-design-kit";

/** The default outlined text field (the theme defaults to outlined + fullWidth). */
export function Basic() {
  return (
    <Stack spacing={2} sx={{ maxWidth: 360 }}>
      <TextField label="Project name" defaultValue="Acme Corp — External Pentest" />
      <TextField label="Host / IP" placeholder="10.0.14.7" />
    </Stack>
  );
}

/** Validation and helper text. */
export function States() {
  return (
    <Stack spacing={2} sx={{ maxWidth: 360 }}>
      <TextField label="CVSS score" defaultValue="8.6" helperText="0.0 – 10.0" />
      <TextField
        label="CVSS score"
        defaultValue="14"
        error
        helperText="Must be between 0 and 10"
      />
      <TextField label="Imported field" defaultValue="read-only" disabled />
    </Stack>
  );
}

/** A select rendered through TextField (`select` prop). */
export function Select() {
  return (
    <Stack spacing={2} sx={{ maxWidth: 360 }}>
      <TextField select label="Severity" defaultValue="high">
        <MenuItem value="critical">Critical</MenuItem>
        <MenuItem value="high">High</MenuItem>
        <MenuItem value="medium">Medium</MenuItem>
        <MenuItem value="low">Low</MenuItem>
      </TextField>
    </Stack>
  );
}

/** Multiline input for descriptions and notes. */
export function Multiline() {
  return (
    <Stack spacing={2} sx={{ maxWidth: 360 }}>
      <TextField
        label="Description"
        multiline
        minRows={3}
        defaultValue={"Steps to reproduce:\n1. Send a crafted filter parameter\n2. Observe the SQL error in the response"}
      />
    </Stack>
  );
}

/** Sizes — `small` is used in dense toolbars and filters. */
export function Sizes() {
  return (
    <Stack spacing={2} sx={{ maxWidth: 360 }}>
      <TextField label="Small" size="small" defaultValue="dense filter" />
      <TextField label="Medium" size="medium" defaultValue="default" />
    </Stack>
  );
}
