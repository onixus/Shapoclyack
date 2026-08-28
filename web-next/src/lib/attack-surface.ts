import type { AliveHost } from "@/lib/api";

export type GraphGroupBy = "topology" | "owner";

export type OwnershipSource = "unit" | "owner" | "domain" | "none";

export type OwnershipGroup = {
  key: string;
  label: string;
  source: OwnershipSource;
};

/** Cluster key for the ownership graph (P4.3).
 *
 * Operator-set business unit wins, then owner email. Unowned names cluster
 * by registrable domain and are labelled as a domain so a DNS name is not
 * read as an owner. ASN is never an owner — it is the network operator.
 */
export function ownershipGroup(host: AliveHost): OwnershipGroup {
  const unit = host.business_unit?.trim();
  if (unit) {
    return { key: `unit:${unit.toLowerCase()}`, label: unit, source: "unit" };
  }
  const owner = host.owner_email?.trim();
  if (owner) {
    return { key: `owner:${owner.toLowerCase()}`, label: owner, source: "owner" };
  }
  const domain = host.registrable_domain?.trim();
  if (domain) {
    return {
      key: `domain:${domain.toLowerCase()}`,
      label: `${domain} (domain)`,
      source: "domain",
    };
  }
  return { key: "unowned", label: "Unowned", source: "none" };
}

export function uniqueOwnershipGroups(hosts: AliveHost[]): OwnershipGroup[] {
  const seen = new Map<string, OwnershipGroup>();
  for (const host of hosts) {
    const group = ownershipGroup(host);
    if (!seen.has(group.key)) seen.set(group.key, group);
  }
  return Array.from(seen.values()).sort((a, b) => a.key.localeCompare(b.key));
}
