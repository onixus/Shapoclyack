"use client";

import Link from "next/link";
import { AssetGroups } from "@/components/asset/asset-groups";
import { useAuthStore } from "@/lib/auth-store";

export default function AssetGroupsPage() {
  const tenant = useAuthStore((state) => state.activeTenant);
  return (
    <div className="space-y-6">
      <Link href="/assets" className="text-sm text-primary hover:underline">
        ← Assets
      </Link>
      <div className="border-b border-border pb-4">
        <h1 className="text-2xl font-extrabold">Dynamic asset groups</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Explain membership, preview context assignments and recalculate rules in the active
          tenant.
        </p>
      </div>
      <AssetGroups key={tenant ?? "resolved-tenant"} />
    </div>
  );
}
