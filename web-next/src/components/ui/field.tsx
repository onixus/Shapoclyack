import * as React from "react";

import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";

type HintTone = "muted" | "warning" | "danger";

const HINT_TONE: Record<HintTone, string> = {
  muted: "text-muted-foreground",
  warning: "text-warning",
  danger: "text-destructive",
};

/**
 * One form field with a fixed anatomy (APEX): a 20px label row, the control,
 * and a hint row that is always there, even empty. Neighbours in a FieldGrid
 * therefore put their controls on the same line whether or not they have a
 * hint, an "optional" mark or an action in the label row.
 */
export function Field({
  label,
  htmlFor,
  hint,
  hintTone = "muted",
  optional,
  action,
  reserveHint = true,
  className,
  children,
}: {
  label: React.ReactNode;
  htmlFor?: string;
  hint?: React.ReactNode;
  hintTone?: HintTone;
  /** Text of the "optional" mark, shown at the end of the label row. */
  optional?: React.ReactNode;
  /** A text-sized action at the end of the label row (no taller than 20px). */
  action?: React.ReactNode;
  /** Keep the empty hint row so the next grid row does not move; off for filter bars. */
  reserveHint?: boolean;
  className?: string;
  children: React.ReactNode;
}) {
  const showHint = reserveHint || hint != null;
  return (
    <div className={cn("grid min-w-0 content-start gap-y-2", className)}>
      <div className="flex h-5 min-w-0 items-center justify-between gap-2">
        <Label
          htmlFor={htmlFor}
          className="truncate text-body-sm font-semibold leading-5 text-foreground"
        >
          {label}
        </Label>
        {optional != null || action != null ? (
          <div className="flex shrink-0 items-center gap-2">
            {action}
            {optional != null ? (
              <span className="text-xs font-medium text-muted-foreground">{optional}</span>
            ) : null}
          </div>
        ) : null}
      </div>
      {children}
      {showHint ? (
        <p
          id={htmlFor ? fieldHintId(htmlFor) : undefined}
          className={cn("min-h-4 text-xs leading-4", HINT_TONE[hintTone])}
        >
          {hint}
        </p>
      ) : null}
    </div>
  );
}

export function fieldHintId(htmlFor: string) {
  return `${htmlFor}-hint`;
}

const GRID_COLS = {
  1: "",
  2: "sm:grid-cols-2",
  3: "sm:grid-cols-2 lg:grid-cols-3",
  filters: "grid-cols-[repeat(auto-fill,minmax(11.5rem,1fr))]",
} as const;

/**
 * The grid that holds Fields: cells start at the top (never stretch to the
 * tallest neighbour) and tracks are minmax(0, 1fr), so a long value cannot
 * widen its column.
 */
export function FieldGrid({
  cols = 2,
  className,
  children,
}: {
  cols?: keyof typeof GRID_COLS;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <div
      className={cn(
        "grid grid-cols-1 items-start",
        cols === "filters" ? "gap-4" : "gap-x-6 gap-y-5",
        GRID_COLS[cols],
        className,
      )}
    >
      {children}
    </div>
  );
}

/** A checkbox row of at least 44px with an optional one-line description. */
export function CheckboxOption({
  label,
  description,
  checked,
  disabled,
  onCheckedChange,
}: {
  label: React.ReactNode;
  description?: React.ReactNode;
  checked: boolean;
  disabled?: boolean;
  onCheckedChange: (checked: boolean) => void;
}) {
  return (
    <Label
      className={cn(
        "flex min-h-11 cursor-pointer items-start gap-3 rounded-md border border-border p-3 font-normal leading-normal transition-colors hover:bg-muted/50",
        disabled && "cursor-not-allowed opacity-60 hover:bg-transparent",
      )}
    >
      <Checkbox
        className="mt-0.5"
        checked={checked}
        disabled={disabled}
        onCheckedChange={(value) => onCheckedChange(value === true)}
      />
      <span className="grid gap-0.5">
        <span className="text-sm font-semibold leading-5 text-foreground">{label}</span>
        {description != null ? (
          <span className="text-xs text-muted-foreground">{description}</span>
        ) : null}
      </span>
    </Label>
  );
}
