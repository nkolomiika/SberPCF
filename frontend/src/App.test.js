import { jsx as _jsx } from "react/jsx-runtime";
import { screen } from "@testing-library/react";
import App from "./App";
import { renderWithProviders } from "./test/renderWithProviders";
import { unreadCount } from "./api";
const initialize = vi.fn();
const signOut = vi.fn();
const authState = {
    user: null,
    isInitialized: true,
    initialize,
    signOut,
};
vi.mock("./store", () => ({
    useAuthStore: (selector) => selector(authState),
}));
vi.mock("./api", () => ({
    listNotifications: vi.fn().mockResolvedValue({ items: [] }),
    unreadCount: vi.fn().mockResolvedValue(0),
}));
vi.mock("./pages/LoginPage", () => ({
    LoginPage: () => _jsx("div", { children: "Login page" }),
}));
vi.mock("./pages/ForceChangePasswordPage", () => ({
    ForceChangePasswordPage: () => _jsx("div", { children: "Force change password page" }),
}));
vi.mock("./pages/ProjectsPage", () => ({
    ProjectsPage: () => _jsx("div", { children: "Projects page" }),
}));
vi.mock("./pages/ProfilePage", () => ({
    ProfilePage: () => _jsx("div", { children: "Profile page" }),
}));
vi.mock("./pages/ProjectDetailPage", () => ({
    ProjectDetailPage: () => _jsx("div", { children: "Project detail page" }),
}));
vi.mock("./pages/HostDetailPage", () => ({
    HostDetailPage: () => _jsx("div", { children: "Host detail page" }),
}));
vi.mock("./pages/AuditLogsPage", () => ({
    AuditLogsPage: () => _jsx("div", { children: "Audit logs page" }),
}));
vi.mock("./pages/UsersAdminPage", () => ({
    UsersAdminPage: () => _jsx("div", { children: "Users admin page" }),
}));
class WebSocketMock {
    close() { }
}
describe("App routing", () => {
    beforeEach(() => {
        authState.user = null;
        authState.isInitialized = true;
        initialize.mockReset();
        signOut.mockReset();
        vi.stubGlobal("WebSocket", WebSocketMock);
    });
    it("shows loading spinner until auth is initialized", () => {
        authState.isInitialized = false;
        renderWithProviders(_jsx(App, { themeMode: "dark" }), "/login");
        expect(screen.getByRole("progressbar")).toBeInTheDocument();
        expect(initialize).toHaveBeenCalled();
    });
    it("renders login page for anonymous user", () => {
        renderWithProviders(_jsx(App, { themeMode: "dark" }), "/login");
        expect(screen.getByText("Login page")).toBeInTheDocument();
    });
    it("does not request unread notifications for anonymous user", () => {
        renderWithProviders(_jsx(App, { themeMode: "dark" }), "/login");
        expect(unreadCount).not.toHaveBeenCalled();
    });
    it("redirects user with must_change_password to forced password page", async () => {
        authState.user = {
            id: "u-1",
            username: "alice",
            email: "alice@example.com",
            full_name: null,
            tags: [],
            avatar_url: null,
            role: "pentester",
            is_active: true,
            must_change_password: true,
            password_changed_at: null,
            created_at: new Date().toISOString(),
        };
        renderWithProviders(_jsx(App, { themeMode: "dark" }), "/login");
        expect(await screen.findByText("Force change password page")).toBeInTheDocument();
    });
    it("redirects non-admin away from admin route", async () => {
        authState.user = {
            id: "u-2",
            username: "bob",
            email: "bob@example.com",
            full_name: null,
            tags: [],
            avatar_url: null,
            role: "pentester",
            is_active: true,
            must_change_password: false,
            password_changed_at: null,
            created_at: new Date().toISOString(),
        };
        renderWithProviders(_jsx(App, { themeMode: "dark" }), "/users");
        expect(await screen.findByText("Projects page")).toBeInTheDocument();
        expect(screen.queryByText("Users admin page")).not.toBeInTheDocument();
    });
});
