import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import React, { useEffect, useMemo, useState } from "react";
import ReactDOM from "react-dom/client";
import { CssBaseline, ThemeProvider, createTheme } from "@mui/material";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
const THEME_MODE_STORAGE_KEY = "pcf-theme-mode";
function createAppTheme(mode) {
    return createTheme({
        palette: {
            mode,
            primary: { main: "#6EA8FE" },
            secondary: { main: "#7EE0FF" },
            background: mode === "dark"
                ? { default: "#0B1220", paper: "#121D31" }
                : { default: "#F4F8FF", paper: "#FFFFFF" },
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
                        border: mode === "dark" ? "1px solid rgba(126, 224, 255, 0.14)" : "1px solid rgba(51, 65, 85, 0.12)",
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
    const [themeMode, setThemeMode] = useState(() => {
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
    return (_jsxs(ThemeProvider, { theme: theme, children: [_jsx(CssBaseline, {}), _jsx(BrowserRouter, { children: _jsx(App, { themeMode: themeMode, onToggleTheme: toggleThemeMode }) })] }));
}
const rootElement = document.getElementById("root");
ReactDOM.createRoot(rootElement).render(_jsx(React.StrictMode, { children: _jsx(Root, {}) }));
