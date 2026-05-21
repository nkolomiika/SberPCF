import { screen } from "@testing-library/react";
import App from "./App";
import { renderWithProviders } from "./test/renderWithProviders";
import type { User } from "./types";
import { unreadCount } from "./api";

const initialize = vi.fn();
const signOut = vi.fn();
const pushToast = vi.fn();
const dismissToast = vi.fn();
const authState: {
  user: User | null;
  isInitialized: boolean;
  initialize: typeof initialize;
  signOut: typeof signOut;
} = {
  user: null,
  isInitialized: true,
  initialize,
  signOut,
};

const toastState = {
  toasts: [] as Array<{ id: string; message: string; severity: "success" | "error" | "info" | "warning" }>,
  pushToast,
  dismissToast,
};

vi.mock("./store", () => ({
  useAuthStore: (selector: (state: typeof authState) => unknown) => selector(authState),
  useToastStore: (selector: (state: typeof toastState) => unknown) => selector(toastState),
}));

vi.mock("./api", () => ({
  listNotifications: vi.fn().mockResolvedValue({ items: [] }),
  unreadCount: vi.fn().mockResolvedValue(0),
}));

vi.mock("./pages/LoginPage", () => ({
  LoginPage: () => <div>Login page</div>,
}));

vi.mock("./pages/ForceChangePasswordPage", () => ({
  ForceChangePasswordPage: () => <div>Force change password page</div>,
}));

vi.mock("./pages/ProjectsPage", () => ({
  ProjectsPage: () => <div>Projects page</div>,
}));

vi.mock("./pages/ProfilePage", () => ({
  ProfilePage: () => <div>Profile page</div>,
}));

vi.mock("./pages/ProjectDetailPage", () => ({
  ProjectDetailPage: () => <div>Project detail page</div>,
}));

vi.mock("./pages/HostDetailPage", () => ({
  HostDetailPage: () => <div>Host detail page</div>,
}));

vi.mock("./pages/AuditLogsPage", () => ({
  AuditLogsPage: () => <div>Audit logs page</div>,
}));

vi.mock("./pages/AiAgentIntegrationPage", () => ({
  AiAgentIntegrationPage: () => <div>AI agent integration page</div>,
}));

vi.mock("./pages/UsersAdminPage", () => ({
  UsersAdminPage: () => <div>Users admin page</div>,
}));

class WebSocketMock {
  close() {}
}

describe("App routing", () => {
  beforeEach(() => {
    authState.user = null;
    authState.isInitialized = true;
    initialize.mockReset();
    signOut.mockReset();
    pushToast.mockReset();
    dismissToast.mockReset();
    toastState.toasts = [];
    vi.stubGlobal("WebSocket", WebSocketMock);
  });

  it("shows loading spinner until auth is initialized", () => {
    authState.isInitialized = false;

    renderWithProviders(<App themeMode="dark" />, "/login");

    expect(screen.getByRole("progressbar")).toBeInTheDocument();
    expect(initialize).toHaveBeenCalled();
  });

  it("renders login page for anonymous user", () => {
    renderWithProviders(<App themeMode="dark" />, "/login");

    expect(screen.getByText("Login page")).toBeInTheDocument();
  });

  it("does not request unread notifications for anonymous user", () => {
    renderWithProviders(<App themeMode="dark" />, "/login");

    expect(unreadCount).not.toHaveBeenCalled();
  });

  it("redirects user with must_change_password to forced password page", async () => {
    authState.user = {
      id: "u-1",
      username: "alice",
      email: "alice@example.com",
      full_name: null,
      avatar_url: null,
      role: "pentester",
      is_active: true,
      must_change_password: true,
      password_changed_at: null,
      created_at: new Date().toISOString(),
    };

    renderWithProviders(<App themeMode="dark" />, "/login");

    expect(await screen.findByText("Force change password page")).toBeInTheDocument();
  });

  it("redirects non-admin away from admin route", async () => {
    authState.user = {
      id: "u-2",
      username: "bob",
      email: "bob@example.com",
      full_name: null,
      avatar_url: null,
      role: "pentester",
      is_active: true,
      must_change_password: false,
      password_changed_at: null,
      created_at: new Date().toISOString(),
    };

    renderWithProviders(<App themeMode="dark" />, "/users");

    expect(await screen.findByText("Projects page")).toBeInTheDocument();
    expect(screen.queryByText("Users admin page")).not.toBeInTheDocument();
  });
});
