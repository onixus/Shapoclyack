import { describe, expect, it } from "vitest";
import { ownershipGroup, uniqueOwnershipGroups } from "@/lib/attack-surface";
import type { AliveHost } from "@/lib/api";

function host(overrides: Partial<AliveHost> & { host: string }): AliveHost {
  return {
    hostname: null,
    names: [],
    country: null,
    city: null,
    country_iso: null,
    latitude: null,
    longitude: null,
    os_name: null,
    os_accuracy: null,
    asn: null,
    asn_org: null,
    vulnerability_count: 0,
    owner_email: null,
    business_unit: null,
    asset_id: null,
    registrable_domain: null,
    ownership_source: null,
    ...overrides,
  };
}

describe("ownershipGroup", () => {
  it("prefers business unit over owner email", () => {
    expect(
      ownershipGroup(
        host({
          host: "1.1.1.1",
          business_unit: "payments",
          owner_email: "a@x",
          registrable_domain: "example.com",
        }),
      ),
    ).toEqual({ key: "unit:payments", label: "payments", source: "unit" });
  });

  it("does not treat a registrable domain as an owner", () => {
    const group = ownershipGroup(host({ host: "1.1.1.1", registrable_domain: "example.com" }));
    expect(group.source).toBe("domain");
    expect(group.label).toBe("example.com (domain)");
  });

  it("does not treat ASN as an owner", () => {
    const group = ownershipGroup(
      host({ host: "1.1.1.1", asn_org: "CLOUDFLARENET", asn: "AS13335" }),
    );
    expect(group).toEqual({ key: "unowned", label: "Unowned", source: "none" });
  });
});

describe("uniqueOwnershipGroups", () => {
  it("dedupes units case-insensitively", () => {
    const groups = uniqueOwnershipGroups([
      host({ host: "1.1.1.1", business_unit: "Payments" }),
      host({ host: "2.2.2.2", business_unit: "payments" }),
      host({ host: "3.3.3.3", owner_email: "ops@x" }),
    ]);
    expect(groups.map((g) => g.key)).toEqual(["owner:ops@x", "unit:payments"]);
  });
});
