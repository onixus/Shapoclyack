import { AuthGate } from "@/components/auth-gate";
import { Sidebar } from "@/components/layout/Sidebar";
import { MfaPendingBanner } from "@/components/mfa/mfa-pending-banner";
import { StepUpDialog } from "@/components/mfa/step-up-dialog";
import { TopHeader } from "@/components/layout/TopHeader";
import { SessionExpiryBanner } from "@/components/session-expiry-banner";
import { Toaster } from "@/components/ui/sonner";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <AuthGate>
      <div className="min-h-screen bg-background lg:flex">
        <Sidebar />
        <div className="flex min-h-screen min-w-0 flex-1 flex-col">
          <MfaPendingBanner />
          <SessionExpiryBanner />
          <TopHeader />
          <main className="flex-1 px-4 py-6 md:px-6">{children}</main>
        </div>
      </div>
      <StepUpDialog />
      <Toaster richColors closeButton position="top-right" />
    </AuthGate>
  );
}
