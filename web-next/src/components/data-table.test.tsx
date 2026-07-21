import { describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ColumnDef } from "@tanstack/react-table";
import { DataTable } from "@/components/data-table";

type Row = { name: string; count: number };

const columns: ColumnDef<Row, unknown>[] = [
  { accessorKey: "name", header: "Name" },
  { accessorKey: "count", header: "Count" },
];

const rows: Row[] = [
  { name: "alpha", count: 3 },
  { name: "bravo", count: 1 },
  { name: "charlie", count: 2 },
];

describe("DataTable", () => {
  it("renders all rows", () => {
    render(<DataTable columns={columns} data={rows} />);
    expect(screen.getByText("alpha")).toBeInTheDocument();
    expect(screen.getByText("charlie")).toBeInTheDocument();
  });

  it("shows the loading row while loading", () => {
    render(<DataTable columns={columns} data={[]} isLoading loadingMessage="Loading rows…" />);
    expect(screen.getByText("Loading rows…")).toBeInTheDocument();
  });

  it("shows the empty message when there is no data", () => {
    render(<DataTable columns={columns} data={[]} emptyMessage="Nothing here." />);
    expect(screen.getByText("Nothing here.")).toBeInTheDocument();
  });

  it("renders the error as an alert", () => {
    render(<DataTable columns={columns} data={[]} error={new Error("boom")} />);
    expect(screen.getByRole("alert")).toHaveTextContent("boom");
  });

  it("sorts when a header is clicked (numeric columns descend first)", async () => {
    const user = userEvent.setup();
    render(<DataTable columns={columns} data={rows} />);
    await user.click(screen.getByRole("button", { name: "Count" }));
    let bodyRows = screen.getAllByRole("row").slice(1);
    expect(within(bodyRows[0]).getByText("alpha")).toBeInTheDocument();
    expect(within(bodyRows[2]).getByText("bravo")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Count" }));
    bodyRows = screen.getAllByRole("row").slice(1);
    expect(within(bodyRows[0]).getByText("bravo")).toBeInTheDocument();
    expect(within(bodyRows[2]).getByText("alpha")).toBeInTheDocument();
  });

  it("filters rows through the global search input", async () => {
    const user = userEvent.setup();
    render(<DataTable columns={columns} data={rows} searchPlaceholder="Search…" />);
    await user.type(screen.getByPlaceholderText("Search…"), "brav");
    expect(screen.getByText("bravo")).toBeInTheDocument();
    expect(screen.queryByText("alpha")).not.toBeInTheDocument();
  });

  it("paginates when rows exceed the page size", async () => {
    const user = userEvent.setup();
    const many = Array.from({ length: 5 }, (_, i) => ({ name: `row-${i}`, count: i }));
    render(<DataTable columns={columns} data={many} pageSize={2} />);
    expect(screen.getByText("Page 1 of 3 · 5 rows")).toBeInTheDocument();
    expect(screen.queryByText("row-2")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByText("row-2")).toBeInTheDocument();
  });

  it("hides pagination controls when everything fits on one page", () => {
    render(<DataTable columns={columns} data={rows} />);
    expect(screen.queryByRole("button", { name: "Next" })).not.toBeInTheDocument();
  });
});
