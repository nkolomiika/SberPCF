import { CssBaseline, ThemeProvider, createTheme } from "@mui/material";
import type { ReactElement, ReactNode } from "react";
import { MemoryRouter } from "react-router-dom";
import { render } from "@testing-library/react";

type Props = {
  children: ReactNode;
  route?: string;
};

function Wrapper({ children, route = "/" }: Props) {
  return (
    <ThemeProvider theme={createTheme()}>
      <CssBaseline />
      <MemoryRouter initialEntries={[route]}>{children}</MemoryRouter>
    </ThemeProvider>
  );
}

export function renderWithProviders(ui: ReactElement, route = "/") {
  return render(ui, {
    wrapper: ({ children }) => <Wrapper route={route}>{children}</Wrapper>,
  });
}
