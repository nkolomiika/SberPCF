import { fireEvent, render, screen } from "@testing-library/react";
import { StormLogin } from "./StormLogin";
import { useAuthStore } from "../store";

describe("StormLogin", () => {
  beforeEach(() => {
    useAuthStore.setState({ user: null, error: null, isLoading: false });
  });

  it("renders the STORM sign-in form", () => {
    render(<StormLogin />);
    expect(screen.getByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(screen.getByLabelText("Username")).toBeInTheDocument();
    expect(screen.getByLabelText("Password")).toBeInTheDocument();
  });

  it("enables submit only when both fields are filled", () => {
    render(<StormLogin />);
    const btn = screen.getByRole("button", { name: /Sign in/i });
    expect(btn).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "m.antonov" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "secret" } });
    expect(btn).not.toBeDisabled();
  });
});
