# Operator evidence index (#587)

The tenant-owned PostgreSQL index retains only bounded observations from a
completed, published run: whitelisted integer summary counts and scalar fields
from `vulnerabilities.json`. CVE, CWE, host, numeric port, service, severity,
asset_id, package and version are retained only when explicitly supplied with a
restricted token syntax. No title, raw banner, credentials, markdown, raw evidence,
arbitrary file or remote URL enters this index. Source time is artifact storage
modification time; it does not establish observation freshness.

Refresh atomically replaces the tenant/run snapshot and all documents within one
transaction. Tenant locking serializes refresh; legal holds forbid replacement.
Each document records source hash, document hash, source time, snapshot and index
time. Search and citation opening recheck publication eligibility and both source
fingerprints. Changed or deleted artifacts are refused until a new refresh.
Previously indexed chunks cannot be used after source deletion. Maintenance can
prune stale snapshots; legal holds preserve stored data while reads still fail.
Tenant deletion and run retention must also remove these derived tables.

CVE and package equality preserves the supplied identifier without guessing
numeric versions. PostgreSQL `simple` full-text search supplements exact matches;
`semantic_status=unsupported` is explicit. There is no embedding provider, Qwen
embedding execution, vector similarity or claim about model retrieval quality.
All results remain partial observations rather than assertions of scan coverage.
Missing findings are marked `missing`; oversized files and row/context caps are
marked `truncated`. Invalid findings remain partial; zero indexed findings never
means a clean scan. Limits: 2 MiB findings file, 1000 finding rows, 50 results,
512 query characters and 24000 output context characters.

Every API/worker call must additionally perform current actor authorization.
Tenant ownership of evidence does not grant personal conversation access.
Tests with small frozen documents establish deterministic exact/full-text recall,
atomic rebuilds and stale-source rejection only; GPU/offline/model quality remains
unverified.
