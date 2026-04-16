import React, { useMemo } from "react";
import ReactDOM from "react-dom/client";
import { CssBaseline, ThemeProvider, createTheme, type PaletteMode } from "@mui/material";
import { BrowserRouter } from "react-router-dom";
import App from "./App";

function createAppTheme(mode: PaletteMode) {
  const theme = createTheme({
    palette: {
      mode,
      primary: { main: "#6EA8FE" },
      secondary: { main: "#7EE0FF" },
      background: { default: "#0B1220", paper: "#121D31" },
      text: {
        primary: "#E2E8F0",
        secondary: "#94A3B8",
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
            border: "1px solid rgba(126, 224, 255, 0.14)",
            boxShadow: undefined,
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
