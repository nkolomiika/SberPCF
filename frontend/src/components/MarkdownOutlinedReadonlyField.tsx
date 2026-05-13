import { Box, FormControl, InputLabel, OutlinedInput, Typography } from "@mui/material";
import type { SxProps, Theme } from "@mui/material/styles";
import { forwardRef, type HTMLAttributes, type ReactNode } from "react";
import ReactMarkdown from "react-markdown";
import { markdownUrlTransform, normalizeMarkdownForRender } from "../markdownUrlTransform";
import { MarkdownImage } from "./MarkdownImage";

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
  /** Подпись для поля; при hideLabel используется только для a11y (aria-label на input) */
  label: string;
  inputId: string;
  value: string | null | undefined;
  emptyText: string;
  /** Скрыть плавающую подпись MUI (если заголовок секции уже показан выше) */
  hideLabel?: boolean;
  /** Дополнительные стили для блока с Markdown (например, цвет текста на тёмном фоне) */
  markdownSx?: SxProps<Theme>;
  /** Дополнительные стили для плейсхолдера при пустом значении */
  emptyTextSx?: SxProps<Theme>;
};

export function MarkdownOutlinedReadonlyField({
  label,
  inputId,
  value,
  emptyText,
  hideLabel = false,
  markdownSx,
  emptyTextSx,
}: MarkdownOutlinedReadonlyFieldProps): ReactNode {
  const defaultMarkdownStyles = {
    width: "100%",
    py: 0.25,
    "& p": { m: 0, fontWeight: 400, color: "#ffffff" },
    "& p + p": { mt: 1 },
    "& ul, & ol": { m: 0, pl: 2.5, fontWeight: 400, color: "#ffffff" },
    "& li": { mt: 0.25 },
    "& strong, & em": { color: "#ffffff" },
    "& a": { color: "rgba(255,255,255,0.92)" },
    "& code": { color: "#ffffff", backgroundColor: "rgba(0,0,0,0.25)" },
    "& pre": { color: "#ffffff", backgroundColor: "rgba(0,0,0,0.25)" },
    "& h1, & h2, & h3, & h4, & h5, & h6": { color: "#ffffff" },
    "& blockquote": { color: "rgba(255,255,255,0.9)", borderLeftColor: "rgba(255,255,255,0.35)" },
    "& hr": { borderColor: "rgba(255,255,255,0.25)" },
    "& img": { display: "block", maxWidth: "100%", height: "auto", my: 1 },
  };

  return (
    <FormControl variant="outlined" fullWidth>
      {!hideLabel ? (
        <InputLabel htmlFor={inputId} shrink>
          {label}
        </InputLabel>
      ) : null}
      <OutlinedInput
        id={inputId}
        label={hideLabel ? undefined : label}
        notched={!hideLabel}
        multiline
        readOnly
        inputComponent={MarkdownOutlinedDiv}
        inputProps={{
          "aria-label": hideLabel ? label : undefined,
          children: value?.trim() ? (
            <Box sx={[defaultMarkdownStyles, ...(markdownSx ? [markdownSx] : [])]}>
              <ReactMarkdown urlTransform={markdownUrlTransform} components={{ img: MarkdownImage }}>{normalizeMarkdownForRender(value)}</ReactMarkdown>
            </Box>
          ) : (
            <Typography
              sx={[{ py: 0.25, color: "rgba(255,255,255,0.6)" }, ...(emptyTextSx ? [emptyTextSx] : [])]}
            >
              {emptyText}
            </Typography>
          ),
        }}
        sx={{
          alignItems: "flex-start",
          cursor: "default",
          "& .MuiOutlinedInput-input": { color: "#ffffff" },
        }}
      />
    </FormControl>
  );
}
