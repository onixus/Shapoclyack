"use client";

import { useState } from "react";
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
}

export function DataTable<TData>({
  columns,
  data,
  isLoading,
  error,
  emptyMessage = "No results found.",
  loadingMessage = "Loading data stream…",
  initialSorting = [],
  searchPlaceholder,
  toolbar,
  pageSize = DEFAULT_PAGE_SIZE,
  meta,
}: DataTableProps<TData>) {
  const [sorting, setSorting] = useState<SortingState>(initialSorting);
  const [globalFilter, setGlobalFilter] = useState("");

  const table = useReactTable({
    data,
    columns,
    state: { sorting, globalFilter },
    onSortingChange: setSorting,
    onGlobalFilterChange: setGlobalFilter,
    globalFilterFn: "includesString",
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: { pagination: { pageSize } },
  });

  const rows = table.getRowModel().rows;
  const totalRows = table.getFilteredRowModel().rows.length;
  const pageCount = table.getPageCount();

  return (
    <div className="space-y-3.5">
      {searchPlaceholder || toolbar || meta ? (
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-1 flex-wrap items-center gap-3">
            {searchPlaceholder ? (
              <div className="relative min-w-[240px] max-w-sm">
                <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
                <Input
                  className="pl-9 bg-slate-900/90 border-slate-800 text-slate-100 placeholder:text-slate-500 focus:border-sky-500/60 focus:ring-sky-500/20"
                  placeholder={searchPlaceholder}
                  value={globalFilter}
                  onChange={(event) => setGlobalFilter(event.target.value)}
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
            {error instanceof Error ? error.message : "Failed to load data stream"}
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
                    {header.isPlaceholder ? null : header.column.getCanSort() ? (
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
                    <span>{loadingMessage}</span>
                  </div>
                </TableCell>
              </TableRow>
            ) : rows.length === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={columns.length}
                  className="py-12 text-center text-sm text-slate-400 font-medium"
                >
                  {emptyMessage}
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

      {pageCount > 1 ? (
        <div className="flex items-center justify-between gap-3 pt-1">
          <p className="text-xs text-slate-400">
            Showing <span className="font-semibold text-slate-200">{rows.length}</span> of{" "}
            <span className="font-semibold text-slate-200">{totalRows.toLocaleString()}</span> entries
          </p>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              className="border-slate-800 bg-slate-900 text-slate-300 hover:bg-slate-800 hover:text-slate-100 disabled:opacity-40"
              onClick={() => table.previousPage()}
              disabled={!table.getCanPreviousPage()}
            >
              Previous
            </Button>
            <span className="text-xs font-medium text-slate-400 px-1">
              {table.getState().pagination.pageIndex + 1} / {pageCount}
            </span>
            <Button
              variant="outline"
              size="sm"
              className="border-slate-800 bg-slate-900 text-slate-300 hover:bg-slate-800 hover:text-slate-100 disabled:opacity-40"
              onClick={() => table.nextPage()}
              disabled={!table.getCanNextPage()}
            >
              Next
            </Button>
          </div>
        </div>
      ) : null}
    </div>
  );
}

