import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import axe from "axe-core";
import { DataTable } from "@/components/data-table";
import { SkipLink } from "@/components/skip-link";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";

describe("main-flow accessibility", () => {
  it("moves skip-link focus to the main landmark", async () => {
    const user = userEvent.setup();
    render(
      <>
        <SkipLink />
        <nav aria-label="Primary">
          <a href="/assets">Assets</a>
        </nav>
        <main id="main-content" tabIndex={-1}>
          Content
        </main>
      </>,
    );
    await user.tab();
    expect(screen.getByRole("link", { name: "Skip to main content" })).toHaveFocus();
    await user.keyboard("{Enter}");
    expect(screen.getByRole("main")).toHaveFocus();
  });
  it("names search, announces sorting and follows applied controlled search and sort", async () => {
    const pagination = {
      offset: 0,
      limit: 10,
      total: 1,
      onOffsetChange: () => {},
      search: "old",
      onSearchChange: () => {},
      sort: "name",
      order: "asc" as const,
      sortableColumns: ["name"],
    };
    const props = {
      columns: [{ accessorKey: "name", header: "Name" }],
      data: [{ name: "router" }],
      searchPlaceholder: "Search assets",
    };
    const { rerender, container } = render(<DataTable {...props} serverPagination={pagination} />);
    expect(screen.getByRole("textbox", { name: "Search assets" })).toHaveValue("old");
    rerender(
      <DataTable
        {...props}
        serverPagination={{ ...pagination, search: "router", order: "desc" }}
      />,
    );
    expect(screen.getByRole("textbox", { name: "Search assets" })).toHaveValue("router");
    expect(screen.getByRole("columnheader")).toHaveAttribute("aria-sort", "descending");
    const result = await axe.run(container, {
      runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"] },
      rules: { "color-contrast": { enabled: false } },
    });
    expect(result.violations).toEqual([]);
  });
  it("cancels a pending typed search when applying a view with the same committed search", async () => {
    const user = userEvent.setup();
    const onSearchChange = vi.fn();
    const props = {
      columns: [{ accessorKey: "name", header: "Name" }],
      data: [{ name: "router" }],
      searchPlaceholder: "Search assets",
    };
    const pagination = {
      offset: 0,
      limit: 10,
      total: 1,
      onOffsetChange: () => {},
      search: "",
      searchRevision: 0,
      onSearchChange,
    };
    const { rerender } = render(<DataTable {...props} serverPagination={pagination} />);
    await user.type(screen.getByRole("textbox"), "temporary search");
    rerender(<DataTable {...props} serverPagination={{ ...pagination, searchRevision: 1 }} />);
    expect(screen.getByRole("textbox")).toHaveValue("");
    await new Promise((resolve) => setTimeout(resolve, 350));
    await waitFor(() => expect(onSearchChange).not.toHaveBeenCalled());
    expect(screen.getByRole("textbox")).toHaveValue("");
  });
  it("traps dialog focus, closes on Escape and restores the trigger", async () => {
    const user = userEvent.setup();
    render(
      <Dialog>
        <DialogTrigger>Open details</DialogTrigger>
        <DialogContent>
          <DialogTitle>Asset details</DialogTitle>
          <DialogDescription>Review this asset.</DialogDescription>
          <button>First action</button>
        </DialogContent>
      </Dialog>,
    );
    await user.click(screen.getByRole("button", { name: "Open details" }));
    const dialog = screen.getByRole("dialog");
    expect(dialog).toContainElement(document.activeElement as HTMLElement);
    for (let index = 0; index < 4; index++) {
      await user.tab();
      expect(dialog).toContainElement(document.activeElement as HTMLElement);
    }
    expect(
      (await axe.run(dialog, { rules: { "color-contrast": { enabled: false } } })).violations,
    ).toEqual([]);
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Open details" })).toHaveFocus();
  });
});
