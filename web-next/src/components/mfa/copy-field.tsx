"use client";

import { useState } from "react";
import { Check, Copy } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useT } from "@/lib/i18n";

/**
 * A value shown in full with a copy button beside it (#315).
 *
 * The value is always rendered, never hidden behind the button: `navigator.
 * clipboard` is unavailable over plain HTTP and in a few managed browsers, and
 * an enrolment secret nobody can select by hand is an enrolment nobody can
 * finish. The button is the convenience; the text is the feature.
 */
export function CopyField({
  label,
  value,
  buttonOnly = false,
}: {
  label: string;
  value: string;
  buttonOnly?: boolean;
}) {
  const t = useT();
  const [copied, setCopied] = useState(false);

  async function onCopy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      // No clipboard permission, or no clipboard at all. The value is on
      // screen and selectable, which is the fallback this component is shaped
      // around — a toast about it would be noise on top of a working page.
    }
  }

  const button = (
    <Button type="button" variant="outline" size="sm" onClick={() => void onCopy()}>
      {copied ? <Check className="mr-1.5 h-3.5 w-3.5" /> : <Copy className="mr-1.5 h-3.5 w-3.5" />}
      {copied ? t("mfa.copied") : buttonOnly ? label : t("mfa.copy")}
    </Button>
  );

  if (buttonOnly) return button;

  return (
    <div className="grid gap-1.5">
      <span className="text-xs font-medium text-muted-foreground">{label}</span>
      <div className="flex items-start gap-2">
        <code className="min-w-0 flex-1 break-all rounded-md border border-border bg-muted/50 px-2 py-1.5 font-mono text-xs text-foreground">
          {value}
        </code>
        {button}
      </div>
    </div>
  );
}
