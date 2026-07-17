"use client";

import { useRouter } from "next/navigation";
import { LogOut, UserRound } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useAuthStore } from "@/lib/auth-store";

export function TopHeader() {
  const router = useRouter();
  const { user, logout } = useAuthStore();

  function onLogout() {
    logout();
    router.replace("/login");
  }

  return (
    <header className="sticky top-0 z-20 flex h-14 items-center justify-between border-b bg-white/90 px-4 backdrop-blur md:px-6">
      <div>
        <p className="text-sm font-medium text-slate-900">Vulnerability Management</p>
        <p className="text-xs text-muted-foreground">Tenant-aware operations console</p>
      </div>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline" className="gap-2">
            <UserRound className="h-4 w-4" />
            <span className="hidden sm:inline">{user?.username || "signed out"}</span>
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-52">
          <DropdownMenuLabel>Signed in</DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem className="text-muted-foreground" disabled>
            Role: {user?.role || "—"}
          </DropdownMenuItem>
          <DropdownMenuItem onClick={onLogout}>
            <LogOut className="mr-2 h-4 w-4" />
            Logout
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </header>
  );
}
