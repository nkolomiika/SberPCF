import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import React from "react";
import ReactDOM from "react-dom/client";
import { CssBaseline, ThemeProvider, createTheme } from "@mui/material";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
const theme = createTheme({
    palette: {
        mode: "dark",
        primary: { main: "#4f8cff" },
        secondary: { main: "#65c4ff" },
        background: { default: "#0f1726", paper: "#182237" },
    },
    shape: {
        borderRadius: 12,
    },
});
ReactDOM.createRoot(document.getElementById("root")).render(_jsx(React.StrictMode, { children: _jsxs(ThemeProvider, { theme: theme, children: [_jsx(CssBaseline, {}), _jsx(BrowserRouter, { children: _jsx(App, {}) })] }) }));
