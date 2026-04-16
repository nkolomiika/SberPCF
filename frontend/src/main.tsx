import React, { useEffect, useMemo, useState } from "react";
import ReactDOM from "react-dom/client";
import { CssBaseline, ThemeProvider, createTheme, type PaletteMode } from "@mui/material";
import { BrowserRouter } from "react-router-dom";
import App from "./App";

const THEME_MODE_STORAGE_KEY = "pcf-theme-mode";

function createAppTheme(mode: PaletteMode) {
  return createTheme({
    palette: {
      mode,
      primary: { main: "#6EA8FE" },
      secondary: { main: "#7EE0FF" },
      background:
        mode === "dark"
          ? { default: "#0B1220", paper: "#121D31" }
          : { default: "#F3F6FB", paper: "#FFFFFF" },
      text:
        mode === "dark"
          ? undefined
          : {
              primary: "#0F172A",
              secondary: "#475569",
            },
    },
    shape: {
      borderRadius: 0,
    },
    typography: {
      fontFamily: '"Inter", "SF Pro Text", "Segoe UI", "Roboto", sans-serif',
    },
    components: {
      MuiPaper: {
        styleOverrides: {
          root: {
            backdropFilter: "blur(12px)",
            backgroundImage: "none",
            border: mode === "dark" ? "1px solid rgba(126, 224, 255, 0.14)" : "1px solid rgba(148, 163, 184, 0.24)",
            boxShadow: mode === "dark" ? undefined : "0 6px 24px rgba(15, 23, 42, 0.06)",
          },
        },
      },
      MuiButton: {
        styleOverrides: {
          root: {
            textTransform: "none",
            fontWeight: 600,
          },
        },
      },
    },
  });
}

function Root() {
  const [themeMode, setThemeMode] = useState<PaletteMode>(() => {
    const stored = window.localStorage.getItem(THEME_MODE_STORAGE_KEY);
    return stored === "light" || stored === "dark" ? stored : "dark";
  });

  const theme = useMemo(() => createAppTheme(themeMode), [themeMode]);

  useEffect(() => {
    window.localStorage.setItem(THEME_MODE_STORAGE_KEY, themeMode);
  }, [themeMode]);

  const toggleThemeMode = () => {
    setThemeMode((current) => (current === "dark" ? "light" : "dark"));
  };

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <BrowserRouter>
        <App themeMode={themeMode} onToggleTheme={toggleThemeMode} />
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
