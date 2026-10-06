import { render, screen } from "@testing-library/react";
import { afterAll, expect, it, vi } from "vitest";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";

const restoredFocus = vi.fn();

it("finishes dialog focus restoration before disposing the test environment", () => {
  render(
    <Dialog open>
      <DialogContent onCloseAutoFocus={restoredFocus}>
        <DialogTitle>Focus cleanup</DialogTitle>
        <DialogDescription>Exercise the real Radix unmount callback.</DialogDescription>
      </DialogContent>
    </Dialog>,
  );
  expect(screen.getByRole("dialog")).toBeInTheDocument();
});

afterAll(() => {
  // Radix queues this event during RTL cleanup. It must run while its own
  // jsdom Event constructors are still installed, before file teardown.
  expect(restoredFocus).toHaveBeenCalledTimes(1);
});
