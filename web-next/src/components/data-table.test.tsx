import { describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, within } from "@testing-library/react";
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
    expect(screen.getByText("1 / 3")).toBeInTheDocument();
    expect(screen.getByText(/Showing/).textContent).toContain("2");
    expect(screen.queryByText("row-2")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByText("row-2")).toBeInTheDocument();
  });

  it("hides pagination controls when everything fits on one page", () => {
    render(<DataTable columns={columns} data={rows} />);
    expect(screen.queryByRole("button", { name: "Next" })).not.toBeInTheDocument();
  });
});

describe("DataTable server pagination", () => {
  const server = {
    offset: 0,
    limit: 2,
    total: 5,
    onOffsetChange: vi.fn(),
    sortableColumns: ["name"],
    sort: "name",
    order: "desc" as const,
  };

  it("reports the server total and pages by offset instead of slicing locally", async () => {
    const user = userEvent.setup();
    const onOffsetChange = vi.fn();
    render(
      <DataTable
        columns={columns}
        data={rows.slice(0, 2)}
        serverPagination={{ ...server, onOffsetChange }}
      />,
    );

    expect(screen.getByText("Showing 2 of 5 entries")).toBeInTheDocument();
    expect(screen.getByText("1 / 3")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(onOffsetChange).toHaveBeenCalledWith(2);
  });

  it("disables Previous on the first page and Next on the last", () => {
    const { unmount } = render(
      <DataTable columns={columns} data={rows.slice(0, 2)} serverPagination={server} />,
    );
    expect(screen.getByRole("button", { name: "Previous" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Next" })).toBeEnabled();
    unmount();

    render(
      <DataTable
        columns={columns}
        data={rows.slice(0, 1)}
        serverPagination={{ ...server, offset: 4 }}
      />,
    );
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
  });

  it("only offers sorting on server-sortable columns", async () => {
    const user = userEvent.setup();
    const onSortChange = vi.fn();
    render(
      <DataTable
        columns={columns}
        data={rows}
        serverPagination={{ ...server, onSortChange }}
      />,
    );

    // "Count" is not in sortableColumns, so it renders as plain header text.
    expect(screen.queryByRole("button", { name: "Count" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Name" }));
    expect(onSortChange).toHaveBeenCalledWith("name", "asc");
  });

  it("debounces search and reports it to the server instead of filtering the page", async () => {
    vi.useFakeTimers();
    const onSearchChange = vi.fn();
    render(
      <DataTable
        columns={columns}
        data={rows}
        searchPlaceholder="Search…"
        serverPagination={{ ...server, search: "", onSearchChange }}
      />,
    );

    fireEvent.change(screen.getByPlaceholderText("Search…"), { target: { value: "alp" } });
    expect(onSearchChange).not.toHaveBeenCalled(); // still inside the debounce window
    // Rows are whatever the server returned — local filtering must not kick in.
    expect(screen.getByText("charlie")).toBeInTheDocument();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(300);
    });
    expect(onSearchChange).toHaveBeenCalledWith("alp");
    vi.useRealTimers();
  });

  it("hides the search input when the endpoint has no server-side search", () => {
    render(
      <DataTable
        columns={columns}
        data={rows}
        searchPlaceholder="Search…"
        serverPagination={server}
      />,
    );
    expect(screen.queryByPlaceholderText("Search…")).not.toBeInTheDocument();
  });
});

describe("DataTable row selection (#346)", () => {
  function selectionFor(selected: string[], onChange = vi.fn(), max?: number) {
    return { rowId: (row: Row) => row.name, selected, onChange, max };
  }

  it("renders no checkbox column when selection is not configured", () => {
    render(<DataTable columns={columns} data={rows} />);
    expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
  });

  it("adds the ticked row's id to the selection", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<DataTable columns={columns} data={rows} selection={selectionFor([], onChange)} />);

    await user.click(screen.getByRole("checkbox", { name: "Select bravo" }));

    expect(onChange).toHaveBeenCalledWith(["bravo"]);
  });

  it("unticking removes only that id", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(
      <DataTable
        columns={columns}
        data={rows}
        selection={selectionFor(["alpha", "bravo"], onChange)}
      />,
    );

    await user.click(screen.getByRole("checkbox", { name: "Select alpha" }));

    expect(onChange).toHaveBeenCalledWith(["bravo"]);
  });

  it("the header checkbox selects this page without dropping ids from other pages", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(
      <DataTable
        columns={columns}
        data={rows.slice(0, 2)}
        // An id the operator ticked on a page they have since left. Selection
        // is held as ids precisely so it survives that.
        selection={selectionFor(["from-another-page"], onChange)}
      />,
    );

    await user.click(screen.getByRole("checkbox", { name: "Select all rows on this page" }));

    expect(onChange).toHaveBeenCalledWith(["from-another-page", "alpha", "bravo"]);
  });

  it("clearing the page keeps the selection made elsewhere", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(
      <DataTable
        columns={columns}
        data={rows.slice(0, 2)}
        selection={selectionFor(["from-another-page", "alpha", "bravo"], onChange)}
      />,
    );

    await user.click(screen.getByRole("checkbox", { name: "Select all rows on this page" }));

    expect(onChange).toHaveBeenCalledWith(["from-another-page"]);
  });

  it("stops at the batch ceiling instead of building a request the API refuses", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(
      <DataTable
        columns={columns}
        data={rows}
        selection={selectionFor(["alpha", "bravo"], onChange, 2)}
      />,
    );

    // Already at the ceiling: an unselected row cannot be added...
    expect(screen.getByRole("checkbox", { name: "Select charlie" })).toBeDisabled();
    // ...but a selected one must stay untickable-away, or the limit would be a
    // trap you cannot get out of.
    await user.click(screen.getByRole("checkbox", { name: "Select alpha" }));
    expect(onChange).toHaveBeenCalledWith(["bravo"]);
  });

  it("select-all honours the ceiling too", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(
      <DataTable columns={columns} data={rows} selection={selectionFor([], onChange, 2)} />,
    );

    await user.click(screen.getByRole("checkbox", { name: "Select all rows on this page" }));

    expect(onChange).toHaveBeenCalledWith(["alpha", "bravo"]);
  });

  it("shows the bulk bar with the count and the caller's actions once something is selected", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(
      <DataTable
        columns={columns}
        data={rows}
        selection={{
          ...selectionFor(["alpha", "bravo"], onChange),
          actions: (ids) => <button type="button">Assign {ids.length}</button>,
        }}
      />,
    );

    expect(screen.getByText("2 selected")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Assign 2" })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Clear" }));
    expect(onChange).toHaveBeenCalledWith([]);
  });

  it("hides the bulk bar when nothing is selected", () => {
    render(
      <DataTable
        columns={columns}
        data={rows}
        selection={{
          ...selectionFor([]),
          actions: () => <button type="button">Assign</button>,
        }}
      />,
    );
    expect(screen.queryByText(/selected/)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Assign" })).not.toBeInTheDocument();
  });

  it("keeps the empty-state row spanning every column, including the checkbox one", () => {
    render(
      <DataTable
        columns={columns}
        data={[]}
        emptyMessage="Nothing here."
        selection={selectionFor([])}
      />,
    );
    expect(screen.getByText("Nothing here.").closest("td")).toHaveAttribute("colspan", "3");
  });
});
