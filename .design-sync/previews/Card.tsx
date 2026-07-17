import {
  Card,
  CardContent,
  Typography,
  Stack,
  Chip,
  Divider,
  Button,
  Box,
} from "sberpcf-design-kit";

/** A vulnerability summary card — the primary surface in SberPCF. */
export function VulnerabilityCard() {
  return (
    <Card sx={{ maxWidth: 420 }}>
      <CardContent>
        <Stack direction="row" justifyContent="space-between" alignItems="flex-start" spacing={2}>
          <Typography variant="h6">SQL Injection in /api/v2/hosts</Typography>
          <Chip label="High" color="error" size="small" />
        </Stack>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
          User-supplied <code>filter</code> parameter is concatenated into a raw SQL
          query, allowing extraction of arbitrary table contents.
        </Typography>
        <Divider sx={{ my: 2 }} />
        <Stack direction="row" spacing={1} flexWrap="wrap">
          <Chip label="CVSS 8.6" size="small" variant="outlined" />
          <Chip label="CWE-89" size="small" variant="outlined" />
          <Chip label="10.0.14.7" size="small" variant="outlined" />
        </Stack>
      </CardContent>
    </Card>
  );
}

/** A project card with a footer action row. */
export function ProjectCard() {
  return (
    <Card sx={{ maxWidth: 420 }}>
      <CardContent>
        <Typography variant="subtitle1">Acme Corp — External Pentest</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
          12 hosts · 38 findings · ends 2026-07-15
        </Typography>
        <Stack direction="row" spacing={1} sx={{ mt: 2 }}>
          <Chip label="Critical: 2" color="error" size="small" />
          <Chip label="High: 9" color="warning" size="small" />
          <Chip label="Medium: 14" size="small" variant="outlined" />
        </Stack>
        <Box sx={{ display: "flex", justifyContent: "flex-end", gap: 1, mt: 2 }}>
          <Button size="small" variant="text">Archive</Button>
          <Button size="small" variant="contained">Open</Button>
        </Box>
      </CardContent>
    </Card>
  );
}

/** A plain content card — the base surface for forms and detail panels. */
export function Basic() {
  return (
    <Card sx={{ maxWidth: 420 }}>
      <CardContent>
        <Typography variant="h6">Scan settings</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
          Cards use a flat, zero-radius surface with a faint cyan border and no
          shadow — the defining geometry of the SberPCF theme.
        </Typography>
      </CardContent>
    </Card>
  );
}
