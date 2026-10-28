"use client";

import { useEffect, useState } from "react";
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
import { Textarea } from "@/components/ui/textarea";
import { useCampaignPreview, useCreateCampaign } from "@/hooks/use-campaigns";
import { dueAtFromInput, type Campaign, type CampaignSelection } from "@/lib/campaigns";
import { useT } from "@/lib/i18n";

/**
 * Creates a campaign from what the operator selected, after showing the exact
 * composition the server would freeze. The preview is not trusted by the
 * server — it resolves the selection again — but its `composition_hash` is sent
 * back so that a composition that changed under the operator's feet is refused
 * ("preview again") instead of silently becoming a different campaign.
 */
export function CreateCampaignDialog({
  open,
  onOpenChange,
  selection,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  selection: CampaignSelection;
  onCreated: (campaign: Campaign) => void;
}) {
  const t = useT();
  const preview = useCampaignPreview();
  const create = useCreateCampaign((campaign) => {
    onOpenChange(false);
    onCreated(campaign);
  });
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [owner, setOwner] = useState("");
  const [due, setDue] = useState("");

  const selectionKey = JSON.stringify(selection);
  const { mutate: runPreview } = preview;
  useEffect(() => {
    if (open) runPreview(selection);
    // The selection is compared by value: the page rebuilds the object on
    // every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, selectionKey, runPreview]);

  const data = preview.data;
  const stale = create.error?.message.includes("preview again") ?? false;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] max-w-2xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{t("campaign.dialog.title")}</DialogTitle>
          <DialogDescription>{t("campaign.dialog.description")}</DialogDescription>
        </DialogHeader>
        <form
          className="space-y-4"
          onSubmit={(event) => {
            event.preventDefault();
            if (!data || !data.total) return;
            create.mutate({
              name: name.trim(),
              description: description.trim(),
              owner: owner.trim() || null,
              due_at: dueAtFromInput(due),
              selection,
              composition_hash: data.composition_hash,
            });
          }}
        >
          <div className="space-y-1.5">
            <Label htmlFor="campaign-name">{t("campaign.field.name")}</Label>
            <Input
              id="campaign-name"
              value={name}
              maxLength={160}
              required
              onChange={(event) => setName(event.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="campaign-action">{t("campaign.field.action")}</Label>
            <Textarea
              id="campaign-action"
              value={description}
              maxLength={4000}
              onChange={(event) => setDescription(event.target.value)}
            />
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="campaign-owner">{t("campaign.field.owner")}</Label>
              <Input
                id="campaign-owner"
                value={owner}
                maxLength={200}
                onChange={(event) => setOwner(event.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="campaign-due">{t("campaign.field.due")}</Label>
              <Input
                id="campaign-due"
                type="date"
                value={due}
                onChange={(event) => setDue(event.target.value)}
              />
            </div>
          </div>

          <section aria-label={t("campaign.dialog.preview")} className="space-y-2 rounded-md border border-border p-3">
            <h3 className="text-sm font-semibold">{t("campaign.dialog.preview")}</h3>
            {preview.isPending ? (
              <p className="text-xs text-muted-foreground">…</p>
            ) : preview.error ? (
              <p role="alert" className="text-xs text-rose-600 dark:text-rose-400">
                {preview.error.message}
              </p>
            ) : data ? (
              <div className="space-y-2 text-xs">
                <p data-testid="campaign-preview-totals" className="font-medium">
                  {t("campaign.dialog.previewTotals", {
                    total: data.total,
                    assets: data.assets,
                    problems: data.problems.length,
                  })}
                </p>
                {data.already_in_other_campaigns ? (
                  <p className="text-amber-600 dark:text-amber-400">
                    {t("campaign.dialog.elsewhere", { count: data.already_in_other_campaigns })}
                  </p>
                ) : null}
                {data.skipped.length ? (
                  <p className="text-muted-foreground">
                    {t("campaign.dialog.skipped", { count: data.skipped.length })}
                  </p>
                ) : null}
                {!data.total ? (
                  <p role="alert">{t("campaign.dialog.empty")}</p>
                ) : (
                  <ul className="max-h-40 space-y-0.5 overflow-y-auto font-mono text-xs">
                    {data.problems.map((problem) => (
                      <li key={problem.problem_key}>
                        {problem.problem_key} — {problem.instances} / {problem.assets}
                      </li>
                    ))}
                  </ul>
                )}
                {data.truncated ? (
                  <p className="text-muted-foreground">
                    {t("campaign.dialog.truncated", { count: data.items.length })}
                  </p>
                ) : null}
              </div>
            ) : null}
            {stale ? (
              <p role="alert" className="text-xs text-rose-600 dark:text-rose-400">
                {t("campaign.dialog.stale")}
              </p>
            ) : null}
          </section>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              {t("campaign.cancel")}
            </Button>
            {stale ? (
              <Button type="button" variant="outline" onClick={() => {
                  create.reset();
                  runPreview(selection);
                }}>
                {t("campaign.dialog.preview")}
              </Button>
            ) : null}
            <Button
              type="submit"
              disabled={!name.trim() || !data?.total || create.isPending || stale}
            >
              {t("campaign.dialog.submit")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
