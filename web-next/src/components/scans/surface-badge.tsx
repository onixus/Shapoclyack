"use client";

import Link from "next/link";
import { Globe2, Layers, Shuffle, CircleHelp } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { useT } from "@/lib/i18n";
import {
  SCAN_SURFACE_STATUS,
  surfaceHref,
  type ScanSurface,
  type SurfaceFilter,
} from "@/lib/scan-surface";
import { cn } from "@/lib/utils";

const ICONS = { external: Globe2, internal: Layers, mixed: Shuffle, unknown: CircleHelp } as const;

/** The surface pill. `null` renders as "unclassified", never as internal. */
export function SurfaceBadge({
  surface,
  link = false,
  className,
}: {
  surface: ScanSurface | null | undefined;
  /** Wrap in a link to that surface's operations page. */
  link?: boolean;
  className?: string;
}) {
  const t = useT();
  const key: SurfaceFilter = surface ?? "unknown";
  const Icon = ICONS[key];
  const body = (
    <Badge
      variant={SCAN_SURFACE_STATUS[key].variant ?? "default"}
      title={t(`surface.hint.${key}`)}
      className={cn(
        "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] shadow-sm",
        SCAN_SURFACE_STATUS[key].className,
        className,
      )}
    >
      <Icon className="h-3 w-3" aria-hidden />
      {t(`surface.${key}`)}
    </Badge>
  );
  if (!link || !surface || surface === "mixed") return body;
  return (
    <Link
      href={surfaceHref(surface)}
      className="inline-flex rounded-full focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
    >
      {body}
    </Link>
  );
}
