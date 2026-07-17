import { Button, Stack } from "sberpcf-design-kit";

const PlusIcon = (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M12 5v14M5 12h14" strokeLinecap="square" />
  </svg>
);

/** The three button variants used across SberPCF. */
export function Variants() {
  return (
    <Stack direction="row" spacing={2} alignItems="center">
      <Button variant="contained">New project</Button>
      <Button variant="outlined">Export report</Button>
      <Button variant="text">Cancel</Button>
    </Stack>
  );
}

/** Semantic colors — used to signal intent (destructive, success, etc.). */
export function Colors() {
  return (
    <Stack direction="row" spacing={2} alignItems="center" flexWrap="wrap">
      <Button variant="contained" color="primary">Primary</Button>
      <Button variant="contained" color="secondary">Secondary</Button>
      <Button variant="contained" color="error">Delete host</Button>
      <Button variant="contained" color="success">Mark fixed</Button>
      <Button variant="contained" color="warning">Reopen</Button>
    </Stack>
  );
}

/** Sizes — `large` is used for primary form submits, `small` for inline actions. */
export function Sizes() {
  return (
    <Stack direction="row" spacing={2} alignItems="center">
      <Button variant="contained" size="small">Small</Button>
      <Button variant="contained" size="medium">Medium</Button>
      <Button variant="contained" size="large">Large</Button>
    </Stack>
  );
}

/** Leading and trailing icon slots accept any node. */
export function WithIcon() {
  return (
    <Stack direction="row" spacing={2} alignItems="center">
      <Button variant="contained" startIcon={PlusIcon}>Add vulnerability</Button>
      <Button variant="outlined" startIcon={PlusIcon}>Add host</Button>
    </Stack>
  );
}

/** Disabled and loading states. */
export function States() {
  return (
    <Stack direction="row" spacing={2} alignItems="center">
      <Button variant="contained" disabled>Disabled</Button>
      <Button variant="outlined" disabled>Unavailable</Button>
      <Button variant="contained" loading loadingPosition="start">Saving</Button>
    </Stack>
  );
}
