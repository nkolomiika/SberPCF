import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { LoginPage } from "./LoginPage";
import { renderWithProviders } from "../test/renderWithProviders";

const navigate = vi.fn();
const signIn = vi.fn();

const authState = {
  signIn,
  isLoading: false,
  error: null as string | null,
};

const toastState = {
  toasts: [] as Array<{ id: string; message: string; severity: "success" | "error" | "info" | "warning" }>,
  pushToast: vi.fn(),
  dismissToast: vi.fn(),
};

vi.mock("../store", () => ({
  useAuthStore: (selector: (state: typeof authState) => unknown) => selector(authState),
  useToastStore: (selector: (state: typeof toastState) => unknown) => selector(toastState),
}));

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return {
    ...actual,
    useNavigate: () => navigate,
  };
});

describe("LoginPage", () => {
  beforeEach(() => {
    navigate.mockReset();
    signIn.mockReset();
    authState.error = null;
    toastState.pushToast.mockReset();
    toastState.dismissToast.mockReset();
    toastState.toasts = [];
  });

  it("starts with empty credentials", () => {
    renderWithProviders(<LoginPage />);

    expect(screen.getByRole("textbox")).toHaveValue("");
    expect(screen.getByLabelText(/Пароль/i)).toHaveValue("");
  });

  it("navigates to home after successful login", async () => {
    signIn.mockResolvedValue({ must_change_password: false });

    renderWithProviders(<LoginPage />);
    await userEvent.type(screen.getByRole("textbox"), "admin");
    await userEvent.type(screen.getByLabelText(/Пароль/i), "admin");
    await userEvent.click(screen.getByRole("button", { name: "Войти" }));

    expect(signIn).toHaveBeenCalledWith("admin", "admin");
    expect(navigate).toHaveBeenCalledWith("/");
  });

  it("navigates to force-change-password for temporary password flow", async () => {
    signIn.mockResolvedValue({ must_change_password: true });

    renderWithProviders(<LoginPage />);
    await userEvent.type(screen.getByRole("textbox"), "temp-user");
    await userEvent.type(screen.getByLabelText(/Пароль/i), "Password123");
    await userEvent.click(screen.getByRole("button", { name: "Войти" }));

    expect(navigate).toHaveBeenCalledWith("/force-change-password");
  });

  it("does not navigate when sign in fails", async () => {
    signIn.mockRejectedValue(new Error("login failed"));

    renderWithProviders(<LoginPage />);
    await userEvent.type(screen.getByRole("textbox"), "admin");
    await userEvent.type(screen.getByLabelText(/Пароль/i), "wrong");
    await userEvent.click(screen.getByRole("button", { name: "Войти" }));

    expect(navigate).not.toHaveBeenCalled();
  });
});
