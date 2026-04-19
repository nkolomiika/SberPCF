import { jsx as _jsx } from "react/jsx-runtime";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ForceChangePasswordPage } from "./ForceChangePasswordPage";
import { renderWithProviders } from "../test/renderWithProviders";
const { navigate, forceChangePassword, setUser, signOut, authState } = vi.hoisted(() => {
    const navigate = vi.fn();
    const forceChangePassword = vi.fn();
    const setUser = vi.fn();
    const signOut = vi.fn();
    const authState = {
        user: {
            id: "u-1",
            username: "temp-user",
            email: "temp@example.com",
            full_name: null,
            tags: [],
            avatar_url: null,
            role: "pentester",
            is_active: true,
            must_change_password: true,
            password_changed_at: null,
            created_at: new Date().toISOString(),
        },
        setUser,
        signOut,
    };
    return { navigate, forceChangePassword, setUser, signOut, authState };
});
vi.mock("../api", () => ({
    forceChangePassword,
}));
vi.mock("../store", () => ({
    useAuthStore: (selector) => selector(authState),
}));
vi.mock("react-router-dom", async () => {
    const actual = await vi.importActual("react-router-dom");
    return {
        ...actual,
        useNavigate: () => navigate,
    };
});
describe("ForceChangePasswordPage", () => {
    beforeEach(() => {
        navigate.mockReset();
        forceChangePassword.mockReset();
        setUser.mockReset();
        signOut.mockReset();
    });
    it("keeps save button disabled until passwords match and are long enough", async () => {
        renderWithProviders(_jsx(ForceChangePasswordPage, {}));
        const saveButton = screen.getByRole("button", { name: "Сохранить пароль" });
        expect(saveButton).toBeDisabled();
        await userEvent.type(screen.getByLabelText("Новый пароль"), "Password123");
        await userEvent.type(screen.getByLabelText("Подтвердите пароль"), "Mismatch123");
        expect(saveButton).toBeDisabled();
        await userEvent.clear(screen.getByLabelText("Подтвердите пароль"));
        await userEvent.type(screen.getByLabelText("Подтвердите пароль"), "Password123");
        expect(saveButton).toBeEnabled();
    });
    it("submits new password and redirects to home", async () => {
        forceChangePassword.mockResolvedValue({
            ...authState.user,
            must_change_password: false,
        });
        renderWithProviders(_jsx(ForceChangePasswordPage, {}));
        await userEvent.type(screen.getByLabelText("Новый пароль"), "Password123");
        await userEvent.type(screen.getByLabelText("Подтвердите пароль"), "Password123");
        await userEvent.click(screen.getByRole("button", { name: "Сохранить пароль" }));
        expect(forceChangePassword).toHaveBeenCalledWith("Password123");
        expect(setUser).toHaveBeenCalled();
        expect(navigate).toHaveBeenCalledWith("/", { replace: true });
    });
});
