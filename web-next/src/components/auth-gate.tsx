"use client";

import { useEffect, type ReactNode } from "react";
import { usePathname, useRouter } from "next/navigation";
import { useAuthStore } from "@/lib/auth-store";
import { useT } from "@/lib/i18n";

export function AuthGate({ children }: { children: ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const { user, loading, hydrated, hydrate } = useAuthStore();
  const t = useT();

  useEffect(() => {
    void hydrate();
  }, [hydrate]);

  useEffect(() => {
    if (!hydrated || loading) return;
    if (!user && pathname !== "/login") {
      router.replace("/login");
    }
  }, [hydrated, loading, user, pathname, router]);

  if (!hydrated || loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background text-sm text-muted-foreground">
        {t("auth.loading")}
      </div>
    );
  }

  if (!user) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background text-sm text-muted-foreground">
        {t("auth.redirecting")}
      </div>
    );
  }

  return <>{children}</>;
}
