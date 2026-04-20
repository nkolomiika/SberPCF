import { Box, FormControl, InputLabel, OutlinedInput, Typography } from "@mui/material";
import { forwardRef, type HTMLAttributes, type ReactNode } from "react";
import ReactMarkdown from "react-markdown";

const MarkdownOutlinedDiv = forwardRef<HTMLDivElement, HTMLAttributes<HTMLDivElement>>(function MarkdownOutlinedDiv(
  { children, className, ...other },
  ref,
) {
  return (
    <div ref={ref} className={className} {...other}>
      {children}
    </div>
  );
});

export type MarkdownOutlinedReadonlyFieldProps = {
  label: string;
  inputId: string;
  value: string | null | undefined;
  emptyText: string;
};

export function MarkdownOutlinedReadonlyField({ label, inputId, value, emptyText }: MarkdownOutlinedReadonlyFieldProps): ReactNode {
  return (
    <FormControl variant="outlined" fullWidth>
      <InputLabel htmlFor={inputId} shrink>
        {label}
      </InputLabel>
      <OutlinedInput
        id={inputId}
        label={label}
        notched
        multiline
        readOnly
        inputComponent={MarkdownOutlinedDiv}
        inputProps={{
          children: value?.trim() ? (
            <Box
              sx={{
                width: "100%",
                py: 0.25,
                "& p": { m: 0, fontWeight: 400, color: "text.primary" },
                "& p + p": { mt: 1 },
                "& ul, & ol": { m: 0, pl: 2.5, fontWeight: 400 },
                "& li": { mt: 0.25 },
              }}
            >
              <ReactMarkdown>{value}</ReactMarkdown>
            </Box>
          ) : (
            <Typography color="text.secondary" sx={{ py: 0.25 }}>
              {emptyText}
            </Typography>
          ),
        }}
        sx={{ alignItems: "flex-start", cursor: "default" }}
      />
    </FormControl>
  );
}
