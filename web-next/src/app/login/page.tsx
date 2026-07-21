"use client";

import { FormEvent, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useAuthStore } from "@/lib/auth-store";

export default function LoginPage() {
  const router = useRouter();
  const { user, loading, hydrated, hydrate, login } = useAuthStore();
  const [username, setUsername] = useState("viewer");
  const [password, setPassword] = useState("viewer-change-me");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    void hydrate();
  }, [hydrate]);

  useEffect(() => {
    if (hydrated && !loading && user) {
      router.replace("/");
    }
  }, [hydrated, loading, user, router]);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await login(username, password);
      router.replace("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-slate-950 px-4">
      <div
        className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top,_rgba(56,189,248,0.18),_transparent_55%),radial-gradient(ellipse_at_bottom,_rgba(15,23,42,0.9),_#020617)]"
        aria-hidden
      />
      <section className="relative z-10 w-full max-w-md space-y-6 rounded-xl border border-slate-800 bg-slate-900/80 p-8 text-slate-100 shadow-2xl backdrop-blur">
        <div className="space-y-2">
          <p className="text-sm font-semibold uppercase tracking-[0.2em] text-sky-400">
            Shapoclyack
          </p>
          <h1 className="text-2xl font-semibold tracking-tight">Sign in</h1>
          <p className="text-sm text-slate-400">
            Review scan runs, agents, jobs, and MSSP tenants against the live API.
          </p>
        </div>
        <form className="space-y-4" onSubmit={onSubmit}>
          <label className="grid gap-2 text-sm">
            Username
            <Input
              className="border-slate-700 bg-slate-950 text-slate-100"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              required
            />
          </label>
          <label className="grid gap-2 text-sm">
            Password
            <Input
              className="border-slate-700 bg-slate-950 text-slate-100"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
            />
          </label>
          {error ? <p className="text-sm text-rose-400">{error}</p> : null}
          <Button type="submit" className="w-full" disabled={submitting}>
            {submitting ? "Signing in…" : "Enter dashboard"}
          </Button>
        </form>
      </section>
    </div>
  );
}
