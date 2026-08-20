"use client";

import { useEffect, useState } from "react";
import {
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type SortingState,
} from "@tanstack/react-table";
import { ArrowDown, ArrowUp, ArrowUpDown, Search } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { DEFAULT_PAGE_SIZE } from "@/lib/config/constants";
import { useT } from "@/lib/i18n";

function SortIcon({ sorted }: { sorted: false | "asc" | "desc" }) {
  if (sorted === "asc") return <ArrowUp className="h-3.5 w-3.5 text-sky-400" aria-hidden />;
  if (sorted === "desc") return <ArrowDown className="h-3.5 w-3.5 text-sky-400" aria-hidden />;
  return <ArrowUpDown className="h-3.5 w-3.5 opacity-40 text-slate-500" aria-hidden />;
}

interface DataTableProps<TData> {
  columns: ColumnDef<TData, unknown>[];
  data: TData[];
  isLoading?: boolean;
  error?: unknown;
  emptyMessage?: string;
  loadingMessage?: string;
  initialSorting?: SortingState;
  /** When set, renders a global-search input above the table. */
  searchPlaceholder?: string;
  /** Extra controls rendered beside the search input. */
  toolbar?: React.ReactNode;
  pageSize?: number;
  /** Optional caption under the toolbar, e.g. "12 tenants". */
  meta?: string;
  /**
   * Switches the table to server-side paging, search, and sorting (ROADMAP
   * P3.3). `data` is then one page of rows, `total` is the row count for the
   * whole filtered result set, and every control reports back instead of
   * filtering the in-memory page — which would only ever search what happens
   * to be loaded.
   */
  serverPagination?: ServerPagination;
}

export type ServerPagination = {
  offset: number;
  limit: number;
  total: number;
  onOffsetChange: (offset: number) => void;
  /** Wire up when the endpoint supports `q`; omit to hide the search input. */
  search?: string;
  onSearchChange?: (value: string) => void;
  /** Whitelist of server-sortable column ids; others render unsorted. */
  sortableColumns?: string[];
  sort?: string;
  order?: "asc" | "desc";
  onSortChange?: (sort: string | undefined, order: "asc" | "desc") => void;
};

export function DataTable<TData>({
  columns,
  data,
  isLoading,
  error,
  emptyMessage,
  loadingMessage,
  initialSorting = [],
  searchPlaceholder,
  toolbar,
  pageSize = DEFAULT_PAGE_SIZE,
  meta,
  serverPagination,
}: DataTableProps<TData>) {
  const t = useT();
  const resolvedEmpty = emptyMessage ?? t("table.empty");
  const resolvedLoading = loadingMessage ?? t("table.loading");
  const server = serverPagination;
  const [sorting, setSorting] = useState<SortingState>(initialSorting);
  const [globalFilter, setGlobalFilter] = useState("");
  // Debounced so typing doesn't fire a request per keystroke.
  const [searchDraft, setSearchDraft] = useState(server?.search ?? "");

  useEffect(() => {
    if (!server?.onSearchChange) return;
    if (searchDraft === (server.search ?? "")) return;
    const timer = setTimeout(() => server.onSearchChange?.(searchDraft), 300);
    return () => clearTimeout(timer);
  }, [searchDraft, server]);

  const table = useReactTable({
    data,
    columns,
    state: server ? { sorting } : { sorting, globalFilter },
    onSortingChange: (updater) => {
      const next = typeof updater === "function" ? updater(sorting) : updater;
      setSorting(next);
      if (server?.onSortChange) {
        const first = next[0];
        server.onSortChange(first?.id, first?.desc === false ? "asc" : "desc");
      }
    },
    onGlobalFilterChange: setGlobalFilter,
    globalFilterFn: "includesString",
    manualPagination: Boolean(server),
    manualSorting: Boolean(server),
    manualFiltering: Boolean(server),
    getCoreRowModel: getCoreRowModel(),
    ...(server
      ? {}
      : {
          getSortedRowModel: getSortedRowModel(),
          getFilteredRowModel: getFilteredRowModel(),
          getPaginationRowModel: getPaginationRowModel(),
        }),
    initialState: { pagination: { pageSize } },
  });

  const rows = table.getRowModel().rows;
  const totalRows = server ? server.total : table.getFilteredRowModel().rows.length;
  const pageCount = server ? Math.max(1, Math.ceil(server.total / server.limit)) : table.getPageCount();
  const pageIndex = server
    ? Math.floor(server.offset / server.limit)
    : table.getState().pagination.pageIndex;
  const canPrevious = server ? server.offset > 0 : table.getCanPreviousPage();
  const canNext = server ? server.offset + rows.length < server.total : table.getCanNextPage();

  const showSearch = server ? Boolean(searchPlaceholder && server.onSearchChange) : Boolean(searchPlaceholder);
  const searchValue = server ? searchDraft : globalFilter;
  const onSearch = server ? setSearchDraft : setGlobalFilter;
  const canSortColumn = (columnId: string) =>
    !server || (server.sortableColumns ?? []).includes(columnId);

  return (
    <div className="space-y-3.5">
      {showSearch || toolbar || meta ? (
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-1 flex-wrap items-center gap-3">
            {showSearch ? (
              <div className="relative min-w-[240px] max-w-sm">
                <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
                <Input
                  className="pl-9 bg-slate-900/90 border-slate-800 text-slate-100 placeholder:text-slate-500 focus:border-sky-500/60 focus:ring-sky-500/20"
                  placeholder={searchPlaceholder}
                  value={searchValue}
                  onChange={(event) => onSearch(event.target.value)}
                />
              </div>
            ) : null}
            {toolbar}
          </div>
          {meta ? <p className="text-xs font-medium text-slate-400">{meta}</p> : null}
        </div>
      ) : null}

      {error ? (
        <Alert variant="destructive" className="border-rose-500/40 bg-rose-950/40 text-rose-200">
          <AlertDescription>
            {error instanceof Error ? error.message : t("table.loadFailed")}
          </AlertDescription>
        </Alert>
      ) : null}

      <div className="overflow-hidden rounded-xl border border-slate-800/80 bg-slate-900/80 shadow-lg backdrop-blur">
        <Table>
          <TableHeader className="bg-slate-950/80 border-b border-slate-800">
            {table.getHeaderGroups().map((headerGroup) => (
              <TableRow key={headerGroup.id} className="hover:bg-transparent border-slate-800">
                {headerGroup.headers.map((header) => (
                  <TableHead key={header.id} className="text-xs font-bold uppercase tracking-wider text-slate-400 py-3">
                    {header.isPlaceholder ? null : header.column.getCanSort() &&
                      canSortColumn(header.column.id) ? (
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        className="-ml-3 h-8 gap-1.5 px-2 font-bold hover:bg-slate-800/80 hover:text-slate-200 text-slate-300"
                        onClick={header.column.getToggleSortingHandler()}
                      >
                        {flexRender(header.column.columnDef.header, header.getContext())}
                        <SortIcon sorted={header.column.getIsSorted()} />
                      </Button>
                    ) : (
                      flexRender(header.column.columnDef.header, header.getContext())
                    )}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody className="divide-y divide-slate-800/60">
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={columns.length} className="py-10 text-center text-sm text-slate-400">
                  <div className="flex items-center justify-center gap-2">
                    <span className="h-4 w-4 animate-spin rounded-full border-2 border-sky-400 border-t-transparent" />
                    <span>{resolvedLoading}</span>
                  </div>
                </TableCell>
              </TableRow>
            ) : rows.length === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={columns.length}
                  className="py-12 text-center text-sm text-slate-400 font-medium"
                >
                  {resolvedEmpty}
                </TableCell>
              </TableRow>
            ) : (
              rows.map((row) => (
                <TableRow key={row.id} className="hover:bg-slate-800/40 border-slate-800/60 transition-colors">
                  {row.getVisibleCells().map((cell) => (
                    <TableCell key={cell.id} className="py-3 text-sm text-slate-200">
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </TableCell>
                  ))}
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      {pageCount > 1 || (server && server.total > 0) ? (
        <div className="flex items-center justify-between gap-3 pt-1">
          <p className="text-xs text-slate-400">
            {t("table.showing", { shown: String(rows.length), total: totalRows.toLocaleString() })}
          </p>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              className="border-slate-800 bg-slate-900 text-slate-300 hover:bg-slate-800 hover:text-slate-100 disabled:opacity-40"
              onClick={() =>
                server
                  ? server.onOffsetChange(Math.max(0, server.offset - server.limit))
                  : table.previousPage()
              }
              disabled={!canPrevious}
            >
              {t("common.previous")}
            </Button>
            <span className="text-xs font-medium text-slate-400 px-1">
              {pageIndex + 1} / {pageCount}
            </span>
            <Button
              variant="outline"
              size="sm"
              className="border-slate-800 bg-slate-900 text-slate-300 hover:bg-slate-800 hover:text-slate-100 disabled:opacity-40"
              onClick={() =>
                server ? server.onOffsetChange(server.offset + server.limit) : table.nextPage()
              }
              disabled={!canNext}
            >
              {t("common.next")}
            </Button>
          </div>
        </div>
      ) : null}
    </div>
  );
}

