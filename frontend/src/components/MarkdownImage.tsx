import { Box } from "@mui/material";
import type { ComponentPropsWithoutRef } from "react";

const WIDTH_TITLE_RE = /(?:^|\s)w=(\d+)(?=\s|$)/i;

const parseWidthFromTitle = (title: string | undefined | null): number | null => {
  if (!title) {
    return null;
  }
  const matched = title.match(WIDTH_TITLE_RE);
  if (!matched) {
    return null;
  }
  const parsed = Number.parseInt(matched[1] || "", 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return null;
  }
  return parsed;
};

/**
 * Кастомный рендерер `<img>` для ReactMarkdown.
 *
 * Поддерживает «авторскую» ширину картинки, которую редактор описания
 * сохраняет в title-атрибуте markdown-ссылки в формате `w=<пиксели>`
 * (например `![alt](src "w=520")`). Это позволяет пользователю явно
 * масштабировать картинку и сохранять её размер при просмотре.
 */
export function MarkdownImage({
  src,
  alt,
  title,
  ...rest
}: ComponentPropsWithoutRef<"img">) {
  const explicitWidth = parseWidthFromTitle(typeof title === "string" ? title : null);
  return (
    <Box
      component="img"
      src={src || ""}
      alt={alt ?? ""}
      title={typeof title === "string" ? title : undefined}
      {...rest}
      sx={{
        display: "block",
        maxWidth: "100%",
        height: "auto",
        my: 1,
        ...(explicitWidth ? { width: `${explicitWidth}px` } : {}),
      }}
    />
  );
}
