"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Menu, X, ShieldAlert, Play } from "lucide-react";
import { useState } from "react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { NAV } from "@/lib/config/nav";

export function Sidebar() {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);

  return (
    <>
      <div className="flex items-center justify-between border-b border-slate-800 bg-slate-950/90 px-4 py-3 backdrop-blur lg:hidden">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/20">
            <ShieldAlert className="h-4 w-4" />
          </div>
          <div>
            <p className="text-sm font-bold tracking-wide text-slate-100">SHAPOCLYACK</p>
            <p className="text-[10px] uppercase tracking-wider text-sky-400 font-semibold">Web UI v2</p>
          </div>
        </div>
        <Button
          type="button"
          variant="ghost"
          size="icon"
          className="text-slate-300 hover:text-white hover:bg-slate-800"
          aria-label={open ? "Close navigation" : "Open navigation"}
          onClick={() => setOpen((prev) => !prev)}
        >
          {open ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
        </Button>
      </div>

      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-40 w-64 border-r border-slate-800/80 bg-slate-950/95 text-slate-100 backdrop-blur transition-transform lg:static lg:translate-x-0",
          open ? "translate-x-0" : "-translate-x-full",
        )}
      >
        <div className="flex h-full flex-col">
          <div className="border-b border-slate-800/80 px-5 py-5">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-sky-500/20 to-indigo-500/20 text-sky-400 border border-sky-500/30 shadow-lg shadow-sky-500/10">
                <ShieldAlert className="h-5 w-5" />
              </div>
              <div>
                <p className="text-base font-extrabold tracking-wider text-slate-100">OCTO-MAN</p>
                <p className="text-[11px] font-medium tracking-tight text-slate-400">Cyber Recon & Exposure</p>
              </div>
            </div>
          </div>

          <div className="px-3 pt-4 pb-2">
            <Link
              href="/jobs"
              onClick={() => setOpen(false)}
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-sky-600/20 px-3 py-2 text-xs font-semibold text-sky-300 border border-sky-500/30 hover:bg-sky-600/30 hover:border-sky-400 transition-all shadow-sm shadow-sky-950"
            >
              <Play className="h-3.5 w-3.5 fill-sky-300" />
              New Scan Job
            </Link>
          </div>

          <nav className="flex-1 space-y-1 p-3" aria-label="Primary">
            {NAV.map((item) => {
              const active = item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
              const Icon = item.icon;
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  onClick={() => setOpen(false)}
                  className={cn(
                    "group relative flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-all duration-150",
                    active
                      ? "bg-slate-900/90 text-sky-300 border border-slate-800 shadow-inner"
                      : "text-slate-400 hover:bg-slate-900/50 hover:text-slate-200",
                  )}
                >
                  {active && (
                    <span className="absolute left-0 top-2 bottom-2 w-1 rounded-r-full bg-sky-400 shadow-[0_0_8px_rgba(56,189,248,0.8)]" />
                  )}
                  <Icon className={cn("h-4 w-4 shrink-0 transition-transform group-hover:scale-110", active ? "text-sky-400" : "text-slate-400")} />
                  <span>{item.label}</span>
                </Link>
              );
            })}
          </nav>

          <div className="border-t border-slate-800/80 p-4">
            <div className="flex items-center justify-between text-xs text-slate-500">
              <span className="flex items-center gap-1.5">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
                </span>
                Engine Active
              </span>
              <span className="font-mono text-[10px] text-slate-600">v0.36-0723</span>
            </div>
          </div>
        </div>
      </aside>

      {open ? (
        <button
          type="button"
          aria-label="Close menu overlay"
          className="fixed inset-0 z-30 bg-black/60 backdrop-blur-sm lg:hidden"
          onClick={() => setOpen(false)}
        />
      ) : null}
    </>
  );
}

