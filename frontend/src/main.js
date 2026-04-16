import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import React, { useEffect, useMemo, useState } from "react";
import ReactDOM from "react-dom/client";
import { CssBaseline, ThemeProvider, createTheme } from "@mui/material";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
const THEME_MODE_STORAGE_KEY = "pcf-theme-mode";
const DEBUG_BUILD_MARKER = "theme-fix-v2-main-tsx";
function createAppTheme(mode) {
    // #region agent log
    fetch("http://127.0.0.1:7847/ingest/092a8b93-589d-44d5-a2a5-67f255084dee", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "a74592" },
        body: JSON.stringify({
            sessionId: "a74592",
            runId: "post-fix",
            hypothesisId: "H1",
            location: "main.tsx:createAppTheme:entry",
            message: "createAppTheme called",
            data: { mode, buildMarker: DEBUG_BUILD_MARKER },
            timestamp: Date.now(),
        }),
    }).catch(() => { });
    // #endregion
    const theme = createTheme({
        palette: {
            mode,
            primary: { main: "#6EA8FE" },
            secondary: { main: "#7EE0FF" },
            background: mode === "dark"
                ? { default: "#0B1220", paper: "#121D31" }
                : { default: "#F3F6FB", paper: "#FFFFFF" },
            text: mode === "dark"
                ? {
                    primary: "#E2E8F0",
                    secondary: "#94A3B8",
                }
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
    // #region agent log
    fetch("http://127.0.0.1:7847/ingest/092a8b93-589d-44d5-a2a5-67f255084dee", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "a74592" },
        body: JSON.stringify({
            sessionId: "a74592",
            runId: "post-fix",
            hypothesisId: "H2",
            location: "main.tsx:createAppTheme:afterCreateTheme",
            message: "theme palette snapshot",
            data: {
                buildMarker: DEBUG_BUILD_MARKER,
                hasPalette: Boolean(theme.palette),
                hasPrimary: Boolean(theme.palette?.primary),
                primaryMain: theme.palette?.primary?.main ?? null,
                hasText: Boolean(theme.palette?.text),
                textPrimary: theme.palette?.text?.primary ?? null,
            },
            timestamp: Date.now(),
        }),
    }).catch(() => { });
    // #endregion
    return theme;
}
function Root() {
    const [themeMode, setThemeMode] = useState(() => {
        const stored = window.localStorage.getItem(THEME_MODE_STORAGE_KEY);
        const resolvedMode = stored === "light" || stored === "dark" ? stored : "dark";
        // #region agent log
        fetch("http://127.0.0.1:7847/ingest/092a8b93-589d-44d5-a2a5-67f255084dee", {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "a74592" },
            body: JSON.stringify({
                sessionId: "a74592",
                runId: "post-fix",
                hypothesisId: "H1",
                location: "main.tsx:Root:initThemeMode",
                message: "theme mode resolved from storage",
                data: { storedValue: stored, resolvedMode, buildMarker: DEBUG_BUILD_MARKER },
                timestamp: Date.now(),
            }),
        }).catch(() => { });
        // #endregion
        return resolvedMode;
    });
    const theme = useMemo(() => createAppTheme(themeMode), [themeMode]);
    // #region agent log
    fetch("http://127.0.0.1:7847/ingest/092a8b93-589d-44d5-a2a5-67f255084dee", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "a74592" },
        body: JSON.stringify({
            sessionId: "a74592",
            runId: "post-fix",
            hypothesisId: "H5",
            location: "main.tsx:Root:beforeRender",
            message: "ThemeProvider render snapshot",
            data: {
                buildMarker: DEBUG_BUILD_MARKER,
                themeMode,
                hasPrimary: Boolean(theme.palette?.primary),
                hasText: Boolean(theme.palette?.text),
                textPrimary: theme.palette?.text?.primary ?? null,
            },
            timestamp: Date.now(),
        }),
    }).catch(() => { });
    // #endregion
    useEffect(() => {
        window.localStorage.setItem(THEME_MODE_STORAGE_KEY, themeMode);
    }, [themeMode]);
    const toggleThemeMode = () => {
        setThemeMode((current) => (current === "dark" ? "light" : "dark"));
    };
    return (_jsxs(ThemeProvider, { theme: theme, children: [_jsx(CssBaseline, {}), _jsx(BrowserRouter, { children: _jsx(App, { themeMode: themeMode, onToggleTheme: toggleThemeMode }) })] }));
}
const rootElement = document.getElementById("root");
ReactDOM.createRoot(rootElement).render(_jsx(React.StrictMode, { children: _jsx(Root, {}) }));
