# Operator security contract gate

The optional operator separates untrusted observations and model suggestions
from console authorization, typed action proposals and the existing control
plane. `tests/test_operator_security_gate.py` is an executable negative gate
for [#592](https://github.com/onixus/Shapoclyack/issues/592). It exercises actual
analysis/action/MCP/config validators, a mocked provider transport and real
authenticated PostgreSQL-backed HTTP routes.

The gate includes 80 adversarial cases:

- 24 RU/EN retrieved-instruction attacks across descriptions, banners, owner,
  hostname, titles, advisory text, forged tool results, service, severity,
  CVE/CWE and port values. Untrusted text cannot enter the closed analysis
  prompt or server-rendered answer as instructions, HTML or a beacon URL.
- 16 RU/EN generated-output attacks that try to supply tenant/actor authority,
  tool calls, commands, fixed versions, `machine_verified`, finding closure
  or arbitrary URLs. The selection-only contract rejects them.
- Eight scan-plan privilege injections for quota exemption, foreign tenant,
  another actor, raised priority, scope bypass, config overrides, shell and URL.
- Eight attempts to turn the external read-only MCP registry into shell,
  scan start/cancel, verification, file/SQL/HTTP access or package installation.
- Eight local-provider URL attacks covering metadata endpoints, DNS/public
  hosts, file URLs, credentials and query/fragment smuggling.
- Four provider redirects (301/302/307/308): transport performs one local
  request, refuses the redirect, discloses no upstream secret and never falls
  back to a hosted provider.
- Ten authenticated HTTP attacks covering effect injection, finding closure,
  caller privilege escalation, foreign actor/viewer confirmation and chat text
  presented as scan confirmation. All leave the job count unchanged.
- One authenticated evidence read that presents a default-tenant citation to a
  principal of another tenant. Tenant resolution refuses a caller with no
  membership before the evidence route runs; that 403 is not the evidence
  check. The evidence check is a second principal whose tenant is the other
  one. A canary `api_token` in the published artifact does not appear in the
  owner's search body or in the foreign principal's refusal.
- One audit-redaction case: `record()` keeps a refusal reason and replaces
  `api_token` and `client_secret` in the row it would append. A secret that
  appears only as prose, not as a credential field name, is not claimed to be
  removed. The canary field value is absent from the stored documents.

Adjacent suites supply the other required boundaries:
`test_operator_actions.py` checks immutable confirmation hashes, expiry,
fresh scope/policy/quota checks, auth-session binding, durable single dispatch,
unknown outcome and reconciliation. `test_operator_remediation_api.py` checks
tenant isolation, held-read session revocation and source replacement, stale
citations and service-token rejection. `test_operator_remediation.py` checks
vendor seed/staleness, native Debian/RPM/MSRC semantics and zero unsupported
fixed-version claims for its deterministic golden cases. The existing worker,
authority, retention and evidence suites cover leases/cancellation, revoked
membership, deletion and source hashes.

These are software contract tests. They do not establish resistance of a real
language model to every prompt injection, physical network egress isolation,
8 GiB GPU feasibility, real-model answer quality, production backup/restore,
browser XSS acceptance or an installed offline workstation. Those gates need
their own frozen inputs, exact runtime/model/build provenance, packet/deny
counter evidence and deployment reports under #585/#593. A private-IP URL
allowlist is not an OS/container egress firewall.

Run this gate with the normal project PostgreSQL test setup:

```console
python -m pytest -q --no-cov tests/test_operator_security_gate.py \
  tests/test_operator_actions.py tests/test_operator_remediation.py \
  tests/test_operator_remediation_api.py
```

Without `OCTO_POSTGRES_URL`, the ten HTTP gate cases are skipped; such a run
must not be reported as passing the authenticated endpoint acceptance gate.
