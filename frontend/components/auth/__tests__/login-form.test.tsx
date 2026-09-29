import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach } from "vitest";

const pushMock = vi.fn();
const refreshMock = vi.fn();

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock, refresh: refreshMock }),
}));

const fetchMock = vi.fn();
vi.mock("@/lib/api-client", () => ({
  clientApiFetch: (...args: unknown[]) => fetchMock(...args),
}));

import { LoginForm } from "@/components/auth/login-form";

const noProviders = { google: false, github: false };

describe("LoginForm", () => {
  beforeEach(() => {
    pushMock.mockReset();
    refreshMock.mockReset();
    fetchMock.mockReset();
  });

  it("shows a validation error for an invalid email without calling the API", async () => {
    render(<LoginForm providers={noProviders} />);

    fireEvent.change(screen.getByLabelText(/email/i), { target: { value: "not-an-email" } });
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: "secret" } });
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/valid email/i);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("submits valid credentials and redirects to the dashboard", async () => {
    fetchMock.mockResolvedValueOnce({ user: { email: "user@example.test" } });
    render(<LoginForm providers={noProviders} />);

    fireEvent.change(screen.getByLabelText(/email/i), { target: { value: "user@example.test" } });
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: "secret" } });
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));

    await waitFor(() => expect(pushMock).toHaveBeenCalledWith("/dashboard"));
    expect(fetchMock).toHaveBeenCalledWith(
      "/auth/login",
      expect.objectContaining({ method: "POST" }),
    );
  });
});
