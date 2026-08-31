"use client";

import { DevicePatchGapCard } from "@/components/endpoint/patch-gap-panel";
import { useDevicePatchGap } from "@/hooks/use-endpoint-inventory";

/** Fetches one device's patch gap and renders it, or nothing.
 *
 * Split from the card so the card stays a pure render of data a test can hand
 * it, and so a device with nothing outstanding adds no empty section. */
export function DevicePatchGapSection({
  deviceId,
  tenantId = "default",
}: {
  deviceId: string;
  tenantId?: string;
}) {
  const query = useDevicePatchGap(deviceId, tenantId);
  if (query.isLoading || !query.data) return null;
  return <DevicePatchGapCard gap={query.data} />;
}
