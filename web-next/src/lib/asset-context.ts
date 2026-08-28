import type {
  AssetContextEvent,
  AssetDataClassification,
  AssetEnvironment,
  AssetExposureLevel,
  AssetRisk,
  NistRiskLevel,
} from "@/lib/api";
import { RISK_LEVEL_STATUS } from "@/lib/config/statuses";

export const ASSET_ENVIRONMENTS: readonly AssetEnvironment[] = [
  "production",
  "staging",
  "development",
  "lab",
  "other",
] as const;

export const ASSET_DATA_CLASSIFICATIONS: readonly AssetDataClassification[] = [
  "public",
  "internal",
  "confidential",
  "restricted",
] as const;

export const ASSET_EXPOSURE_LEVELS: readonly AssetExposureLevel[] = [
  "internet",
  "partner",
  "internal",
  "unknown",
] as const;

export const CONTEXT_FIELD_LABELS: Record<string, string> = {
  owner_email: "Owner",
  business_unit: "Business unit",
  business_service: "Business service",
  environment: "Environment",
  data_classification: "Data classification",
  exposure_level: "Exposure",
  asset_criticality: "Criticality",
};

export function contextFieldLabel(field: string): string {
  return CONTEXT_FIELD_LABELS[field] ?? field;
}

export function formatContextValue(value: string | null): string {
  return value == null || value === "" ? "unset" : value;
}

export function describeContextEvent(event: AssetContextEvent): string {
  return `${contextFieldLabel(event.field)}: ${formatContextValue(event.old_value)} → ${formatContextValue(event.new_value)}`;
}

/** Worst open NIST level on this asset — same reading as the estate tile. */
export function assetRiskLabel(
  risk: Pick<AssetRisk, "estate_risk" | "open_total"> | null | undefined,
): string {
  if (!risk) return "…";
  if (risk.estate_risk) {
    const known = RISK_LEVEL_STATUS[risk.estate_risk as NistRiskLevel];
    return known?.label ?? risk.estate_risk.replaceAll("_", " ");
  }
  return risk.open_total === 0 ? "none" : "unset";
}
