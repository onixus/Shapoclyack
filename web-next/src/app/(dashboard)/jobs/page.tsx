"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";
import { useT } from "@/lib/i18n";

/**
 * `/jobs` moved to `/scans` when the launcher split into external and
 * internal surfaces. Kept as a client redirect: the console is a static
 * export, so there is no server to answer 301, and bookmarks and runbooks
 * still point here.
 */
export default function JobsRedirectPage() {
  const router = useRouter();
  const t = useT();
  useEffect(() => {
    // Keep the query: `/jobs?job=<id>` from an old runbook still opens the drawer.
    router.replace(`/scans${window.location.search}`);
  }, [router]);
  return <p className="py-16 text-center text-sm text-muted-foreground">{t("auth.redirecting")}</p>;
}
