import { Box, Typography } from "@mui/material";
import { useCallback, useEffect, useId, useMemo, useRef } from "react";
import { EditorContent, useEditor } from "@tiptap/react";
import StarterKit from "@tiptap/starter-kit";
import Image from "@tiptap/extension-image";
import Link from "@tiptap/extension-link";
import Placeholder from "@tiptap/extension-placeholder";
import { Markdown } from "tiptap-markdown";

const MAX_IMAGE_BYTES = 1_500_000;

type Props = {
  label: string;
  /** Если false — не показывать подпись над полем (когда заголовок уже есть на странице) */
  showLabel?: boolean;
  value: string | null;
  onChange: (value: string | null) => void;
  disabled?: boolean;
  minRows?: number;
  helperText?: string;
  onImageTooLarge?: () => void;
  /**
   * Опциональный загрузчик: получает вставленный/перетащенный файл и должен вернуть
   * либо markdown-картинку `![alt](url)`, либо просто URL. При отсутствии — картинки
   * вставляются как data URL, при превышении ~1.5 МБ вызывается onImageTooLarge.
   */
  onUploadImage?: (file: File) => Promise<string | null>;
};

const extractSrcFromMarkdownOrUrl = (value: string): { src: string; alt: string } => {
  const trimmed = value.trim();
  const match = trimmed.match(/!\[([^\]]*)\]\(([^)\s]+)(?:\s+"[^"]*")?\)/);
  if (match) {
    return { alt: match[1] || "image", src: match[2] || "" };
  }
  return { alt: "image", src: trimmed };
};

const readFileAsDataUrl = (file: File): Promise<string> =>
  new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(typeof reader.result === "string" ? reader.result : "");
    reader.onerror = () => reject(new Error("read error"));
    reader.readAsDataURL(file);
  });

/**
 * WYSIWYG-редактор на TipTap с live markdown-shortcuts (### space → h3, - space → bullet,
 * **bold**, > quote, ``` ```, --- горизонтальная линия и т.д.). Сохраняет/загружает
 * данные в виде markdown-строки, чтобы оставаться совместимым с текущим форматом БД.
 */
export function MarkdownEditor({
  label,
  showLabel = true,
  value,
  onChange,
  disabled,
  minRows = 2,
  helperText,
  onImageTooLarge,
  onUploadImage,
}: Props) {
  const reactId = useId();
  const fieldId = `${reactId}-md-editor`;
  // Последний эмитированный/применённый markdown — нужен для разрыва циклической
  // синхронизации между внутренним состоянием TipTap и внешним value.
  const lastSyncedRef = useRef<string>(value || "");
  const lastImagePasteRef = useRef<{ key: string; at: number } | null>(null);
  const onUploadImageRef = useRef(onUploadImage);
  const onImageTooLargeRef = useRef(onImageTooLarge);
  onUploadImageRef.current = onUploadImage;
  onImageTooLargeRef.current = onImageTooLarge;

  const insertImageFromFile = useCallback(
    async (file: File, view: { dispatch: (tr: unknown) => void; state: unknown }) => {
      try {
        let src: string;
        let alt = (file.name.replace(/[^\w.-]/g, "_") || "image").slice(0, 120);
        if (onUploadImageRef.current) {
          const result = await onUploadImageRef.current(file);
          if (!result) {
            return;
          }
          const parsed = extractSrcFromMarkdownOrUrl(result);
          src = parsed.src;
          alt = parsed.alt || alt;
        } else {
          if (file.size > MAX_IMAGE_BYTES) {
            onImageTooLargeRef.current?.();
            return;
          }
          src = await readFileAsDataUrl(file);
        }
        if (!src) {
          return;
        }
        editorRef.current?.chain().focus().setImage({ src, alt }).run();
      } catch {
        /* noop */
      }
    },
    []
  );

  const shouldHandlePastedImageFile = useCallback((file: File): boolean => {
    const now = Date.now();
    const key = `${file.name}:${file.type}:${file.size}:${file.lastModified}`;
    const last = lastImagePasteRef.current;
    if (last?.key === key && now - last.at < 1500) {
      return false;
    }
    lastImagePasteRef.current = { key, at: now };
    return true;
  }, []);

  const editor = useEditor({
    extensions: useMemo(
      () => [
        StarterKit.configure({
          // markdown-shortcuts уже встроены в StarterKit (Heading, BulletList,
          // OrderedList, Bold, Italic, Strike, Code, CodeBlock, Blockquote,
          // HorizontalRule). Дополнительно настраивать не нужно.
          heading: { levels: [1, 2, 3, 4, 5, 6] },
          codeBlock: {},
        }),
        Image.configure({ inline: false, allowBase64: true }),
        Link.configure({
          openOnClick: false,
          autolink: true,
          HTMLAttributes: { rel: "noopener noreferrer", target: "_blank" },
        }),
        Placeholder.configure({
          placeholder: () => "",
        }),
        Markdown.configure({
          html: false,
          tightLists: true,
          bulletListMarker: "-",
          linkify: true,
          breaks: true,
          transformPastedText: true,
          transformCopiedText: true,
        }),
      ],
      []
    ),
    content: value || "",
    editable: !disabled,
    editorProps: {
      attributes: {
        id: fieldId,
        "aria-label": showLabel ? "" : label,
        spellcheck: "true",
      },
      handlePaste: (view, event) => {
        if (disabled) {
          return false;
        }
        const items = Array.from((event as ClipboardEvent).clipboardData?.items || []);
        const fileItem = items.find((item) => item.kind === "file" && item.type.startsWith("image/"));
        if (fileItem) {
          const file = fileItem.getAsFile();
          if (file) {
            event.preventDefault?.();
            if (shouldHandlePastedImageFile(file)) {
              void insertImageFromFile(file, view as never);
            }
            return true;
          }
        }
        const filesArr = Array.from((event as ClipboardEvent).clipboardData?.files || []).filter((f) =>
          f.type.startsWith("image/")
        );
        if (filesArr.length > 0) {
          event.preventDefault?.();
          if (shouldHandlePastedImageFile(filesArr[0]!)) {
            void insertImageFromFile(filesArr[0]!, view as never);
          }
          return true;
        }
        return false;
      },
      handleDrop: (view, event) => {
        if (disabled) {
          return false;
        }
        const dragEvent = event as DragEvent;
        const file = Array.from(dragEvent.dataTransfer?.files || []).find((f) => f.type.startsWith("image/"));
        if (file) {
          dragEvent.preventDefault?.();
          void insertImageFromFile(file, view as never);
          return true;
        }
        return false;
      },
    },
    onUpdate: ({ editor: ed }) => {
      // tiptap-markdown добавляет storage с методом getMarkdown
      const storage = (ed.storage as { markdown?: { getMarkdown: () => string } }).markdown;
      const md = storage ? storage.getMarkdown() : "";
      lastSyncedRef.current = md;
      onChange(md ? md : null);
    },
  });

  const editorRef = useRef<typeof editor>(editor);
  editorRef.current = editor;

  // Синхронизация: внешнее value изменилось (например, загрузили данные с сервера)
  useEffect(() => {
    if (!editor) {
      return;
    }
    const incoming = value || "";
    if (incoming === lastSyncedRef.current) {
      return;
    }
    lastSyncedRef.current = incoming;
    editor.commands.setContent(incoming, false);
  }, [value, editor]);

  useEffect(() => {
    if (!editor) {
      return;
    }
    editor.setEditable(!disabled);
  }, [disabled, editor]);

  const minHeight = `calc(${minRows} * 1.5em + 16px)`;

  return (
    <Box>
      {showLabel ? (
        <Typography
          component="label"
          htmlFor={fieldId}
          variant="body2"
          color="text.secondary"
          sx={{ display: "block", mb: 0.5 }}
        >
          {label}
        </Typography>
      ) : null}
      <Box
        sx={{
          border: "1px solid rgba(126,224,255,0.2)",
          borderRadius: 1,
          backgroundColor: "rgba(8,17,31,0.2)",
          p: 1.5,
          minHeight,
          color: "#ffffff",
          "& .ProseMirror": {
            outline: "none",
            minHeight,
            color: "#ffffff",
            fontFamily:
              "-apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, Helvetica, Arial, sans-serif",
            fontSize: "0.95rem",
            lineHeight: 1.55,
            "& p": { my: 0.5 },
            "& h1": { fontSize: "1.5rem", fontWeight: 700, mt: 1.5, mb: 0.75 },
            "& h2": { fontSize: "1.3rem", fontWeight: 700, mt: 1.5, mb: 0.5 },
            "& h3": { fontSize: "1.15rem", fontWeight: 700, mt: 1, mb: 0.5 },
            "& h4, & h5, & h6": { fontWeight: 700, mt: 0.75, mb: 0.25 },
            "& ul, & ol": { pl: 3, my: 0.5 },
            "& blockquote": {
              borderLeft: "3px solid rgba(126,224,255,0.4)",
              pl: 1.25,
              ml: 0,
              color: "rgba(255,255,255,0.85)",
            },
            "& code": {
              backgroundColor: "rgba(126,224,255,0.12)",
              px: 0.5,
              borderRadius: 0.5,
              fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
              fontSize: "0.85em",
            },
            "& pre": {
              backgroundColor: "rgba(8,17,31,0.65)",
              border: "1px solid rgba(126,224,255,0.16)",
              p: 1,
              borderRadius: 1,
              overflowX: "auto",
              fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
            },
            "& img": {
              maxWidth: "100%",
              height: "auto",
              borderRadius: 1,
              my: 0.5,
            },
            "& a": {
              color: "#7ee0ff",
              textDecoration: "underline",
            },
            "& hr": {
              border: "none",
              borderTop: "1px solid rgba(126,224,255,0.25)",
              my: 1,
            },
            "& p.is-editor-empty:first-of-type::before": {
              content: "attr(data-placeholder)",
              color: "rgba(255,255,255,0.45)",
              float: "left",
              height: 0,
              pointerEvents: "none",
            },
          },
        }}
      >
        <EditorContent editor={editor} />
      </Box>
    </Box>
  );
}

export default MarkdownEditor;
