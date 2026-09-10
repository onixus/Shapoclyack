import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { AxiosError } from "axios";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { StepUpDialog } from "@/components/mfa/step-up-dialog";
import { api } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";
import { isStepUpRefusal, STEP_UP_MARKER, useStepUpStore } from "@/lib/step-up";

vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

function installLocalStorage() {
  const store = new Map<string, string>();
  Object.defineProperty(window, "localStorage", {
    configurable: true,
    value: {
      getItem: (key: string) => store.get(key) ?? null,
      setItem: (key: string, value: string) => void store.set(key, String(value)),
      removeItem: (key: string) => void store.delete(key),
      clear: () => store.clear(),
    },
  });
}

beforeEach(() => {
  installLocalStorage();
  useStepUpStore.setState({ detail: null });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("step-up refusals", () => {
  it("tells a stale second factor apart from an ordinary 403", () => {
    expect(
      isStepUpRefusal(403, `This operation ${STEP_UP_MARKER}. Re-verify with …`),
    ).toBe(true);
    // A role refusal must not raise a code prompt: entering one changes nothing.
    expect(isStepUpRefusal(403, "Admin role required")).toBe(false);
    expect(isStepUpRefusal(401, `x ${STEP_UP_MARKER}`)).toBe(false);
  });

  it("raises the prompt from the interceptor rather than from a call site", async () => {
    const original = api.defaults.adapter;
    api.defaults.adapter = async (config) => {
      const error = new Error("Request failed with status code 403") as AxiosError;
      Object.assign(error, {
        isAxiosError: true,
        config,
        response: {
          status: 403,
          data: { detail: `This operation ${STEP_UP_MARKER}. Re-verify …` },
          statusText: "",
          headers: {},
          config,
        },
      });
      throw error;
    };
    // Every call site in the console goes through this instance, which is why
    // the prompt is wired here and not into each of the ~thirty mutations.
    await expect(api.post("/tenants/default/service-tokens", {})).rejects.toThrow();
    api.defaults.adapter = original;

    expect(useStepUpStore.getState().detail).toContain(STEP_UP_MARKER);
  });

  it("verifies a code and closes, without replaying the lost request", async () => {
    const verifyMfa = vi.fn().mockResolvedValue(undefined);
    useAuthStore.setState({ verifyMfa });
    useStepUpStore.setState({ detail: `This operation ${STEP_UP_MARKER}.` });
    render(<StepUpDialog />);

    await userEvent.type(await screen.findByLabelText(/code from the app/i), "123456");
    await userEvent.click(screen.getByRole("button", { name: /verify/i }));

    await waitFor(() => expect(useStepUpStore.getState().detail).toBeNull());
    // Six digits are a code; a recovery code would have gone to the other field.
    expect(verifyMfa).toHaveBeenCalledWith({ code: "123456", recoveryCode: undefined });
  });
});
