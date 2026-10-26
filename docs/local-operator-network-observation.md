# Network observation and IPv4-only runtime namespaces

The Mac inference and embedding profile uses IPv4. Its model namespaces disable
IPv6 through both `net.ipv6.conf.all.disable_ipv6=1` and
`net.ipv6.conf.default.disable_ipv6=1`; disabling IPv6 on the Docker bridge alone
does not establish those namespace settings. Runtime and offline startup
attestation check the configured sysctls. A new physical observation is still
required after recreating the namespaces.

The observer does not exempt IPv6, link-local addresses, multicast, or ICMPv6
from the destination allowlist. Its bounded extension-header decoder exposes
TCP/UDP ports behind hop-by-hop/routing/destination/AH headers, so DNS port 53
remains visible. Truncated, malformed, opaque, fragmented or excessive chains
produce `receive_errors`; an undecodable packet cannot establish absence of DNS
or external traffic. Kernel packet/drop counters and capture-duration checks
remain independent requirements.

For diagnosis, `link_local_control_candidates` separately counts two positively
identified header patterns: unspecified-source duplicate-address-detection
Neighbor Solicitation with hop limit 255 and the matching solicited-node
destination/target, and link-local-source MLDv2 Listener Report to `ff02::16`
with hop limit 1 and hop-by-hop Router Alert. These patterns follow
[Neighbor Discovery](https://www.rfc-editor.org/rfc/rfc4861.html#section-7.1.1)
and [MLDv2](https://www.rfc-editor.org/rfc/rfc3810.html#section-5).
They are descriptive candidates, **not** packet-checksum validation, proof of
kernel/process origin, or an allowlist exception: the packets still appear in
`unexpected_destinations` when outside the configured allowed networks.
No packet bodies or DNS questions are retained.

The earlier pilot's `ip58` and `ip0` flow keys lacked ICMPv6 type, hop limit and
extension details. They are consistent with startup control traffic, but those
historical metadata cannot prove that classification and must not be relabelled
as a passing no-egress receipt. The pilot also stopped early and reported
sampling errors; a new complete exact-source run is required. Namespace IPv6
disablement removes this startup traffic without weakening the no-external,
no-DNS, no-drop or complete-capture gates.
