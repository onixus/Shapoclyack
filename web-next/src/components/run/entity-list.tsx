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
    return <p className="text-xs text-muted-foreground py-6 text-center">{emptyMessage}</p>;
  }
  return (
    <div className="max-h-[28rem] overflow-auto rounded-xl border border-border bg-card shadow-lg backdrop-blur">
      <ul className="divide-y divide-border">
        {items.map((item) => {
          const value = item.value ?? item.key;
          const isSelected = activeKey === value;
          return (
            <li key={item.key}>
              <button
                type="button"
                className={`flex w-full items-start justify-between gap-3 px-4 py-3 text-left text-xs transition-colors hover:bg-muted ${
                  isSelected ? "bg-sky-500/10 border-l-2 border-sky-400" : ""
                }`}
                onClick={() => onSelect(value)}
              >
                <span>
                  <strong className="font-mono text-xs font-bold text-foreground">{item.title}</strong>
                  <span className="mt-0.5 block text-muted-foreground text-[11px]">{item.subtitle}</span>
                </span>
                {item.meta != null ? (
                  <span className="shrink-0 font-mono text-[11px] text-muted-foreground">{item.meta}</span>
                ) : null}
              </button>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
