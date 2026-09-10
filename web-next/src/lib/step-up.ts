"use client";

import { create } from "zustand";

/**
 * The marker the API puts in the 403 it answers a stale second factor with
 * (`api/auth.py::require_step_up`). Matched on the English detail rather than
 * on a code, because the API has no error-code vocabulary; if that sentence
 * ever changes, the console falls back to showing the detail in a toast, which
 * is what it did before this existed.
 */
export const STEP_UP_MARKER = "needs a recent multi-factor verification";

type StepUpState = {
  /** The API's own explanation, or null when nothing is outstanding. */
  detail: string | null;
  /** What the caller was doing, for the dialog to name it. */
  request: (detail: string) => void;
  clear: () => void;
};

/**
 * One place the console learns that an operation needs a fresh code (#315).
 *
 * Deliberately not a queue and not a retry: the request that hit the 403 is
 * lost, and the dialog says so rather than replaying it. Replaying a POST the
 * user has not seen succeed — creating an account, minting a key — is worse
 * than asking them to press the button again.
 *
 * Lives in its own module so the axios interceptor can poke it without
 * `api.ts` importing anything that imports `api.ts`.
 */
export const useStepUpStore = create<StepUpState>((set) => ({
  detail: null,
  request: (detail: string) => set({ detail }),
  clear: () => set({ detail: null }),
}));

/** Whether an error body is the step-up refusal rather than an ordinary 403. */
export function isStepUpRefusal(status: number | undefined, detail: unknown): boolean {
  return status === 403 && typeof detail === "string" && detail.includes(STEP_UP_MARKER);
}
