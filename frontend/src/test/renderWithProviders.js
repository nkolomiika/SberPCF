import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { CssBaseline, ThemeProvider, createTheme } from "@mui/material";
import { MemoryRouter } from "react-router-dom";
import { render } from "@testing-library/react";
function Wrapper({ children, route = "/" }) {
    return (_jsxs(ThemeProvider, { theme: createTheme(), children: [_jsx(CssBaseline, {}), _jsx(MemoryRouter, { initialEntries: [route], children: children })] }));
}
export function renderWithProviders(ui, route = "/") {
    return render(ui, {
        wrapper: ({ children }) => _jsx(Wrapper, { route: route, children: children }),
    });
}
