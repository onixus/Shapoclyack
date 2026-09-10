"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useBulkAssetAction } from "@/hooks/use-bulk-actions";
import type {
  AssetEnvironment,
  AssetExposureLevel,
  BulkActionReport,
  UpdateAssetBody,
} from "@/lib/api";

/**
 * The bulk bar for the asset registry (#346).
 *
 * This is `PATCH /api/assets/{id}` applied to a selection, and it is here
 * because the context it sets is what the *findings* are scored and
 * prioritised by: an unowned, uncategorised asset is a finding nobody is
 * accountable for, and fixing that one asset at a time is the other half of the
 * four-hundred-clicks problem.
 *
 * Only the fields the operator actually filled are sent, so an owner can be set
 * across forty assets without flattening their criticality to whatever this
 * form happened to show.
 */
const ENVIRONMENTS: readonly AssetEnvironment[] = [
  "production",
  "staging",
  "development",
  "lab",
  "other",
];

const EXPOSURES: readonly AssetExposureLevel[] = ["internet", "partner", "internal", "unknown"];

const BUTTON_CLASS =
  "h-7 text-xs border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 hover:text-white";

export function AssetBulkContext({
  ids,
  onApplied,
}: {
  ids: string[];
  /** Given the ids that failed, so the page can leave them selected. */
  onApplied: (remaining: string[], report: BulkActionReport) => void;
}) {
  const bulk = useBulkAssetAction();
  const [open, setOpen] = useState(false);
  const [ownerEmail, setOwnerEmail] = useState("");
  const [businessUnit, setBusinessUnit] = useState("");
  const [criticality, setCriticality] = useState("");
  const [environment, setEnvironment] = useState<AssetEnvironment | "">("");
  const [exposure, setExposure] = useState<AssetExposureLevel | "">("");

  const payload = (): UpdateAssetBody => {
    const next: UpdateAssetBody = {};
    if (ownerEmail.trim()) next.owner_email = ownerEmail.trim();
    if (businessUnit.trim()) next.business_unit = businessUnit.trim();
    if (criticality !== "") next.asset_criticality = Number(criticality);
    if (environment) next.environment = environment;
    if (exposure) next.exposure_level = exposure;
    return next;
  };

  // An empty payload is refused by the API with a 422 ("a context update needs
  // at least one field"), so the button is disabled rather than producing it.
  const filled = Object.keys(payload()).length > 0;

  const apply = () => {
    bulk.mutate(
      { action: "context", asset_ids: ids, payload: payload() },
      {
        onSuccess: (report) => {
          setOpen(false);
          onApplied(
            report.results.filter((item) => !item.ok).map((item) => item.id),
            report,
          );
        },
      },
    );
  };

  return (
    <>
      <Button variant="outline" size="sm" className={BUTTON_CLASS} onClick={() => setOpen(true)}>
        Set context…
      </Button>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="bg-slate-900 border-slate-800 text-slate-100">
          <DialogHeader>
            <DialogTitle className="text-slate-100">Set asset context</DialogTitle>
            <DialogDescription className="text-xs text-slate-400">
              {ids.length} asset{ids.length === 1 ? "" : "s"} selected. Blank fields are left
              untouched on every one of them.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor="bulk-owner-email" className="text-xs text-slate-300">
                Owner email
              </Label>
              <Input
                id="bulk-owner-email"
                value={ownerEmail}
                onChange={(event) => setOwnerEmail(event.target.value)}
                placeholder="ada@example.com"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="bulk-business-unit" className="text-xs text-slate-300">
                Business unit
              </Label>
              <Input
                id="bulk-business-unit"
                value={businessUnit}
                onChange={(event) => setBusinessUnit(event.target.value)}
                placeholder="payments"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="bulk-criticality" className="text-xs text-slate-300">
                Criticality (0–4)
              </Label>
              <Input
                id="bulk-criticality"
                type="number"
                min={0}
                max={4}
                value={criticality}
                onChange={(event) => setCriticality(event.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <span className="text-xs text-slate-300">Environment</span>
              <div className="flex flex-wrap gap-1.5">
                {ENVIRONMENTS.map((value) => (
                  <Button
                    key={value}
                    type="button"
                    size="sm"
                    variant={environment === value ? "default" : "outline"}
                    className="h-7 text-xs"
                    onClick={() => setEnvironment(environment === value ? "" : value)}
                  >
                    {value}
                  </Button>
                ))}
              </div>
            </div>
            <div className="space-y-1.5">
              <span className="text-xs text-slate-300">Exposure</span>
              <div className="flex flex-wrap gap-1.5">
                {EXPOSURES.map((value) => (
                  <Button
                    key={value}
                    type="button"
                    size="sm"
                    variant={exposure === value ? "default" : "outline"}
                    className="h-7 text-xs"
                    onClick={() => setExposure(exposure === value ? "" : value)}
                  >
                    {value}
                  </Button>
                ))}
              </div>
            </div>
          </div>

          <DialogFooter>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setOpen(false)}
              disabled={bulk.isPending}
            >
              Cancel
            </Button>
            <Button size="sm" disabled={bulk.isPending || !filled} onClick={apply}>
              {bulk.isPending ? "Applying…" : `Apply to ${ids.length}`}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
