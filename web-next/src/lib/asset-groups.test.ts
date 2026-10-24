import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "@/lib/api";
import { assetGroupsApi, type AssetGroup } from "@/lib/asset-groups";
afterEach(() => vi.restoreAllMocks());
describe("asset group request contracts", () => {
  it("sends only allowed draft keys to strict preview endpoint and includes the cursor", async () => {
    const post = vi.spyOn(api, "post").mockResolvedValue({ data: { items: [], has_more: false } });
    const group: AssetGroup = {
      id: "g1",
      name: "Test",
      version: 5,
      priority: 100,
      description: "",
      enabled: true,
      rules: { all: [{ field: "status", op: "eq", value: "active" }] },
      context: {},
      member_count: 4,
      updated_at: "now",
    };
    await assetGroupsApi.preview(group, group.id, "a100");
    expect(post).toHaveBeenCalledWith("/asset-groups/preview", {
      name: "Test",
      description: "",
      enabled: true,
      priority: 100,
      rules: group.rules,
      context: {},
      group_id: "g1",
      limit: 100,
      after_asset_id: "a100",
    });
  });
  it("keeps member pagination server-side and escapes group identifiers", async () => {
    const get = vi.spyOn(api, "get").mockResolvedValue({ data: { items: [], total: 0 } });
    await assetGroupsApi.members("a/b", 20);
    expect(get).toHaveBeenCalledWith("/asset-groups/a%2Fb/members", {
      params: { offset: 20, limit: 20 },
    });
  });
});
