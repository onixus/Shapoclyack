import { api, type UpdateAssetBody } from "@/lib/api";

export const GROUP_FIELDS = [
  "ip",
  "fqdn",
  "status",
  "owner_email",
  "business_unit",
  "business_service",
  "environment",
  "data_classification",
  "exposure_level",
  "asset_criticality",
] as const;
export type GroupField = (typeof GROUP_FIELDS)[number] | `tag:${string}`;
export type RuleOperator =
  "eq" | "ne" | "in" | "not_in" | "contains" | "starts_with" | "ends_with" | "cidr";
export type GroupRule =
  | { all: GroupRule[]; negate?: boolean }
  | { any: GroupRule[]; negate?: boolean }
  | {
      field: GroupField;
      op: RuleOperator;
      value: string | number | (string | number)[];
      negate?: boolean;
    };
export type GroupContext = Omit<UpdateAssetBody, "context_source" | "status" | "exposure_level">;
export type GroupDraft = {
  name: string;
  description: string;
  enabled: boolean;
  priority: number;
  rules: GroupRule;
  context: GroupContext;
};
export type AssetGroup = GroupDraft & {
  id: string;
  version: number;
  member_count: number;
  updated_at: string;
  last_success_at?: string | null;
};
export type GroupPage<T> = {
  items: T[];
  total: number;
  offset: number;
  limit: number;
  has_more: boolean;
};
export type GroupMember = {
  asset_id: string;
  reasons: unknown;
  version: number;
  evaluated_at: string;
};
export type GroupEvaluation = {
  id?: string;
  evaluation_id?: string;
  status?: string;
  version?: number;
  started_at?: string;
  completed_at?: string | null;
  report?: { evaluated?: number; matched?: number; has_more?: boolean };
  error?: string | null;
  evaluated?: number;
  matched?: number;
  has_more?: boolean;
};
export type GroupPreviewRow = {
  asset_id: string;
  matched: boolean;
  reasons: unknown;
  changes: unknown;
  conflicts?: unknown;
  entrant?: boolean;
  exited?: boolean;
};
export type GroupPreview = {
  items: GroupPreviewRow[];
  evaluated: number;
  matched: number;
  has_more: boolean;
  next_asset_id?: string | null;
  entrants?: number;
  exits?: number;
  changes?: number;
  conflicts?: number;
  changed?: number;
  evaluation_id?: string;
};

export function ruleOperators(field: string): RuleOperator[] {
  if (field === "asset_criticality") return ["eq", "ne", "in", "not_in"];
  if (field === "ip") return ["eq", "ne", "in", "not_in", "cidr"];
  return ["eq", "ne", "in", "not_in", "contains", "starts_with", "ends_with"];
}
export function parseRuleValue(
  field: string,
  op: RuleOperator,
  value: string,
): string | number | (string | number)[] {
  const numeric = field === "asset_criticality";
  const parts =
    op === "in" || op === "not_in" ? value.split(",").map((item) => item.trim()) : [value.trim()];
  if (parts.some((item) => item === "")) throw new Error("Rule values cannot be empty.");
  const parsed = parts.map((item) => {
    if (!numeric) return item;
    if (!/^\d+$/.test(item)) throw new Error(`${field} requires whole numbers.`);
    const number = Number(item);
    if (field === "asset_criticality" && number > 4) throw new Error("Criticality must be 0–4.");
    return number;
  });
  return op === "in" || op === "not_in" ? parsed : parsed[0];
}

const endpoint = "/asset-groups";
export const assetGroupsApi = {
  list: async (offset: number) =>
    (await api.get<GroupPage<AssetGroup>>(endpoint, { params: { offset, limit: 20 } })).data,
  save: async (draft: GroupDraft, id?: string) =>
    (id
      ? await api.patch<AssetGroup>(`${endpoint}/${encodeURIComponent(id)}`, draft)
      : await api.post<AssetGroup>(endpoint, draft)
    ).data,
  remove: async (id: string) => {
    await api.delete(`${endpoint}/${encodeURIComponent(id)}`);
  },
  preview: async (draft: GroupDraft, groupId?: string, after?: string) =>
    (
      await api.post<GroupPreview>(`${endpoint}/preview`, {
        name: draft.name,
        description: draft.description,
        enabled: draft.enabled,
        priority: draft.priority,
        rules: draft.rules,
        context: draft.context,
        group_id: groupId,
        limit: 100,
        after_asset_id: after,
      })
    ).data,
  recalculate: async (id: string, after?: string) =>
    (
      await api.post<GroupPreview>(`${endpoint}/${encodeURIComponent(id)}/recalculate`, {
        limit: 100,
        after_asset_id: after,
      })
    ).data,
  members: async (id: string, offset: number) =>
    (
      await api.get<GroupPage<GroupMember>>(`${endpoint}/${encodeURIComponent(id)}/members`, {
        params: { offset, limit: 20 },
      })
    ).data,
  evaluations: async (id: string) =>
    (
      await api.get<GroupPage<GroupEvaluation>>(
        `${endpoint}/${encodeURIComponent(id)}/evaluations`,
        { params: { limit: 10 } },
      )
    ).data,
};
