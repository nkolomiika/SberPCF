import React, { useMemo } from "react";
import ReactDOM from "react-dom/client";
import { CssBaseline, ThemeProvider, createTheme, type PaletteMode } from "@mui/material";
import { BrowserRouter } from "react-router-dom";
import App from "./App";

function createAppTheme(mode: PaletteMode) {
  const theme = createTheme({
    palette: {
      mode,
      primary: { main: "#78A9FF" },
      secondary: { main: "#7EE0FF" },
      success: { main: "#4ADE80" },
      warning: { main: "#FBBF24" },
      error: { main: "#FB7185" },
      background: { default: "#08111F", paper: "#0F1B2D" },
      text: {
        primary: "#E2E8F0",
        secondary: "#94A3B8",
      },
      divider: "rgba(148,163,184,0.12)",
    },
    shape: {
      borderRadius: 0,
    },
    typography: {
      fontFamily: '"Inter", "SF Pro Text", "Segoe UI", "Roboto", sans-serif',
      h4: { fontSize: "1.85rem", fontWeight: 700, letterSpacing: -0.02 },
      h5: { fontSize: "1.35rem", fontWeight: 700, letterSpacing: -0.02 },
      h6: { fontSize: "1rem", fontWeight: 700, letterSpacing: -0.01 },
      subtitle1: { fontSize: "0.95rem", fontWeight: 600 },
      subtitle2: { fontSize: "0.85rem", fontWeight: 600, letterSpacing: 0.1 },
      button: { fontWeight: 600 },
    },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          html: {
            colorScheme: "dark",
            scrollbarWidth: "thin",
            scrollbarColor: "rgba(126,224,255,0.32) rgba(255,255,255,0.02)",
          },
          body: {
            backgroundImage: "linear-gradient(180deg, #08111F 0%, #0B1220 100%)",
          },
          "*": {
            scrollbarWidth: "thin",
            scrollbarColor: "rgba(126,224,255,0.32) rgba(255,255,255,0.02)",
          },
          "*::-webkit-scrollbar": {
            width: 8,
            height: 8,
            backgroundColor: "transparent",
          },
          "*::-webkit-scrollbar-button": {
            display: "none",
            width: 0,
            height: 0,
          },
          "*::-webkit-scrollbar-track": {
            backgroundColor: "rgba(255,255,255,0.03)",
            borderRadius: 999,
          },
          "*::-webkit-scrollbar-thumb": {
            backgroundColor: "rgba(126,224,255,0.28)",
            borderRadius: 999,
            border: "2px solid transparent",
            backgroundClip: "padding-box",
          },
          "*::-webkit-scrollbar-thumb:hover": {
            backgroundColor: "rgba(126,224,255,0.42)",
          },
          "*::-webkit-scrollbar-thumb:active": {
            backgroundColor: "rgba(126,224,255,0.5)",
          },
          "*::-webkit-scrollbar-corner": {
            backgroundColor: "transparent",
          },
          "::selection": {
            backgroundColor: "rgba(120,169,255,0.35)",
          },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: {
            backdropFilter: "none",
            backgroundImage: "none",
            border: "1px solid rgba(126, 224, 255, 0.10)",
            boxShadow: "none",
          },
        },
      },
      MuiCard: {
        styleOverrides: {
          root: {
            borderRadius: 0,
            border: "1px solid rgba(126, 224, 255, 0.10)",
            backgroundColor: "rgba(15, 27, 45, 0.88)",
            boxShadow: "none",
          },
        },
      },
      MuiCardContent: {
        styleOverrides: {
          root: {
            padding: 20,
            "&:last-child": {
              paddingBottom: 20,
            },
          },
        },
      },
      MuiButton: {
        styleOverrides: {
          root: {
            textTransform: "none",
            fontWeight: 600,
            borderRadius: 0,
            minHeight: 38,
            paddingInline: 14,
          },
          contained: {
            boxShadow: "none",
          },
          outlined: {
            borderColor: "rgba(126,224,255,0.18)",
            backgroundColor: "rgba(15,27,45,0.42)",
          },
        },
      },
      MuiIconButton: {
        styleOverrides: {
          root: {
            borderRadius: 0,
          },
        },
      },
      MuiChip: {
        styleOverrides: {
          root: {
            borderRadius: 0,
            fontWeight: 600,
          },
        },
      },
      MuiTextField: {
        defaultProps: {
          variant: "outlined",
          fullWidth: true,
        },
      },
      MuiOutlinedInput: {
        styleOverrides: {
          root: {
            borderRadius: 0,
            backgroundColor: "rgba(8,17,31,0.55)",
            transition: "box-shadow 0.18s ease, border-color 0.18s ease, background-color 0.18s ease",
            "&:hover": {
              backgroundColor: "rgba(8,17,31,0.72)",
            },
            "&.Mui-focused": {
              boxShadow: "0 0 0 4px rgba(120,169,255,0.12)",
            },
          },
          notchedOutline: {
            borderColor: "rgba(148,163,184,0.16)",
          },
        },
      },
      MuiMenu: {
        styleOverrides: {
          paper: {
            borderRadius: 0,
          },
        },
      },
      MuiDialog: {
        styleOverrides: {
          paper: {
            borderRadius: 0,
            backgroundColor: "rgba(15,27,45,0.96)",
          },
        },
      },
      MuiListItemButton: {
        styleOverrides: {
          root: {
            borderRadius: 0,
          },
        },
      },
    },
  });

  return theme;
}

function Root() {
  const themeMode: PaletteMode = "dark";
  const theme = useMemo(() => createAppTheme(themeMode), [themeMode]);

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <BrowserRouter>
        <App themeMode={themeMode} />
      </BrowserRouter>
    </ThemeProvider>
  );
}

const rootElement = document.getElementById("root");

ReactDOM.createRoot(rootElement!).render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>
);
