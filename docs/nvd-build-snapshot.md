# NVD snapshot for builds

Jenkins and ordinary Docker builds use the versioned
`scanner/data/cvss4/cvss4.json`, rather than querying the NVD API on every
build. The scanner and all-in-one images default to `NVD_FETCH=0`; the API
image also carries this snapshot. This works on a cold builder and with
`docker build --no-cache` and across architectures, without a shared volume,
registry service, or credentials.

All three image builds verify `cvss4.sha256` and the snapshot's format, date,
and minimum corpus size before using it. A modified or missing snapshot fails
the build, including a non-strict development build. Git records the bytes
and checksum together; the checksum detects corruption, and is not an
independent signature or a completeness guarantee.

The parked snapshot contains **34,697 entries**, dated **2026-10-22**. It was
captured from Jenkins #595 branch build #4 on commit `d01f2af3`, after its
eight-day NVD harvest completed all 55 pages. It combines the prior committed
baseline with that window; this capture does not claim a complete historical
refresh since the baseline's August date. The data's `updated`, `source`, and
`origin_url` remain visible in the enrichment manifest and System API. Builds
do not label the parked data as newly fetched.

## Update deliberately

On a connected host with Python and optional `NVD_API_KEY` in the environment:

```sh
make nvd-snapshot-verify
make nvd-snapshot-refresh
make nvd-snapshot-verify
git diff --stat -- scanner/data/cvss4
```

The refresh performs a full harvest into a temporary file. A failed or partial
harvest leaves the existing snapshot and checksum intact. After a successful
refresh, review and commit both `cvss4.json` and `cvss4.sha256` together, and
update the capture notes above. No scheduled refresh is configured by this
change.

To park another already completed harvest without fetching again:

```sh
python3 scripts/nvd_snapshot.py park /path/to/completed-cvss4.json scanner/data/cvss4/cvss4.json
```

The `park` command validates the supplied corpus, but cannot establish that its
upstream harvest completed; retain that evidence with the snapshot update.

For a deliberate live image build, `docker build --build-arg NVD_FETCH=1 .`
enables the former incremental fetch. An optional key still uses the existing
BuildKit secret `--secret id=nvd_api_key,src=/path/to/key`, never a build argument.
This opt-in updates only that image, not the parked repository snapshot.

Runtime `scripts/fetch-enrichment.sh`, Kubernetes refresh jobs, and offline
bundle creation continue refreshing NVD by default. An explicit
`OCTO_CVSS4_FETCH_ENABLED=false` skips just CVSS4 and preserves its prior origin;
the other feeds continue as before. NVD CPE ranges retain their separate opt-in.
