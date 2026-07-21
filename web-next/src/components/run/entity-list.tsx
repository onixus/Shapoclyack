"use client";

import type { ReactNode } from "react";

export type EntityListItem = {
  /** Unique React key for the row. */
  key: string;
  /** Selection value passed to onSelect; defaults to `key`. */
  value?: string;
  title: ReactNode;
  subtitle: ReactNode;
  meta?: ReactNode;
};

/** Selectable list used for both the hosts and ports tabs of the run report. */
export function EntityList({
  items,
  activeKey,
  onSelect,
  emptyMessage,
}: {
  items: EntityListItem[];
  activeKey: string | null;
  onSelect: (key: string) => void;
  emptyMessage: string;
}) {
  if (items.length === 0) {
    return <p className="text-sm text-muted-foreground">{emptyMessage}</p>;
  }
  return (
    <div className="max-h-[28rem] overflow-auto rounded-lg border bg-white">
      <ul className="divide-y">
        {items.map((item) => {
          const value = item.value ?? item.key;
          return (
            <li key={item.key}>
              <button
                type="button"
                className={`flex w-full items-start justify-between gap-3 px-4 py-3 text-left text-sm hover:bg-slate-50 ${
                  activeKey === value ? "bg-slate-100" : ""
                }`}
                onClick={() => onSelect(value)}
              >
                <span>
                  <strong className="text-slate-900">{item.title}</strong>
                  <span className="mt-0.5 block text-muted-foreground">{item.subtitle}</span>
                </span>
                {item.meta != null ? (
                  <span className="shrink-0 text-xs text-muted-foreground">{item.meta}</span>
                ) : null}
              </button>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
