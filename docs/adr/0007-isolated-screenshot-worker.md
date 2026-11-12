# ADR 0007: Isolated screenshot worker

| | |
|---|---|
| **Status** | **Accepted** — user, 2026-11-12 (implementation requested) |
| **Date** | 2026-11-12 |
| **Related** | [P4.4](../../ROADMAP.md), [configuration.md](../configuration.md), [k8s-hardening.md](../k8s-hardening.md) |

The sections below are the implementation contract, not a menu of options.
Capture returns only through the worker described here.

## Context

Web screenshot capture was withdrawn in #367. Published scanner and all-in-one
images must not contain Playwright or Chromium, and installing a browser inside
the scanner pod is not a supported deployment. Historical artifacts remain:
`screenshots.json`, operator-only PNG downloads, and the screenshot retention
reaper.

Phase 9.3 / P4.4 requires capture again, but only from an isolated browser
runtime.

## Decision

Capture returns as an opt-in stage that delegates every navigation to a
separate screenshot-worker process. The scanner image stays browser-free.

### Worker

- New image `Dockerfile.screenshot-worker`, published as
  `ghcr.io/onixus/shapoclyack-screenshot-worker`. It is the only image that
  installs Playwright's Chromium.
- Process: `python -m scanner.screenshot_worker`. Loopback HTTP only.
- `POST /capture` JSON body:

```json
{"url": "https://203.0.113.10/", "timeout_seconds": 15, "verify_tls": false}
```

- Success `200`:

```json
{"png_base64": "<standard base64, no newlines>", "redacted_fields": 2}
```

  `png_base64` decodes to a non-empty PNG (`\\x89PNG` magic). `redacted_fields`
  is a non-negative int.
- Failure `200` with `{"error": "capture_failed"}` for navigation, timeout, or
  an empty page. Never include exception text, response bodies, or cookies.
- `GET /healthz` returns `200` `{"status": "ok"}` when the browser can launch.
- Bind `127.0.0.1` by default. `SCREENSHOT_WORKER_BIND=0.0.0.0` is for the
  container, which has no other listeners.
- No shared volume with the scanner. The worker returns pixels; it does not
  write the run directory.
- Chromium flags: headless, no sandbox only inside the container's own
  seccomp/user namespace story documented in k8s (the pod is non-root and
  drops all capabilities). Do not add raw-socket capabilities.
- Viewport 1280×720. `full_page` is false. Wait until `domcontentloaded`.
- Before `page.screenshot`, run the existing redaction script from
  `scanner/pipeline/screenshots.py` (`REDACT_SELECTOR` / `REDACT_SCRIPT`).
  Clear matching input values. Unredacted pixels are never returned.
- Ignore HTTPS errors only when `verify_tls` is false.
- One capture at a time per request; the scanner's semaphore is the concurrency
  cap. The worker may run a small thread pool but must not browse a URL the
  scanner did not send.
- Reject URLs that are not `http` or `https`, or that carry userinfo.

### Scanner stage

`scanner/pipeline/screenshots.py` stays the stage. It still selects candidates
with `_candidate_endpoints` (already-open web ports only; no new scan, no extra
GET). It still writes `screenshots/<sha256>.png` and `screenshots.json`.

When `screenshots.enabled` is false, the stage writes
`skipped_reason: screenshots.disabled` and does not call the worker.

When enabled, the capture function is an HTTP client of
`SCREENSHOT_WORKER_URL` (default `http://127.0.0.1:8077`). A missing or
unreachable worker writes `skipped_reason: worker.unavailable` and no pixels.
A per-URL failure stays `error: capture_failed` on that finding and does not
fail the scan. Empty PNG is `error: empty_capture`.

`SCREENSHOT_WORKER_URL` empty means "no worker configured" and is the same skip
as unreachable. The stage must not import or launch Playwright.

The injected `capture` callable in tests remains the seam. Production capture
talks to the worker.

### Kubernetes

New base component `k8s/shapoclyack/base/screenshot-worker/`:

- Deployment, 1 replica, port 8077, non-root, read-only root, drop ALL
  capabilities, no NET_RAW/NET_ADMIN, `/tmp` emptyDir for the browser profile.
- Service `shapoclyack-screenshot-worker` in `network-scan`.
- NetworkPolicy: ingress only from `scanner-executor` pods is not possible
  across namespaces. Allow ingress from pods in `network-scan-executor`
  (namespace selector) on TCP 8077, and egress to anywhere except the
  cluster's datastore ports are already denied by existing policies. Document
  that the worker must reach the same targets the executor scans.
- Executor env `SCREENSHOT_WORKER_URL=http://shapoclyack-screenshot-worker.network-scan.svc:8077`.
- Local-scan Job gets the same env, pointing at the in-cluster Service.
- Do not add the worker container to the scanner StatefulSet.
- Image tag in manifests: `shapoclyack-0.49-screenshot-worker` (placeholder
  until publish). `imagePullPolicy: IfNotPresent`.

### Configuration

- `screenshots.enabled` is an editable bool again (`EDITABLE_PATHS`,
  `_STATIC_SPEC`). Remove it from `_WITHDRAWN_PATHS` and from the #367
  rejection hint.
- System status `scan_config.stages.screenshots` reports the effective bool.
- Overlay: an overlay may set `screenshots.enabled`, but
  `out["screenshots"]["enabled"] = overlay and host` stays. A sensor whose
  own file has the stage off cannot be turned on remotely.
- Default remains `enabled: false` in `scanner/config/default.yaml` and
  `k8s/shapoclyack/base/config/k8s.yaml`.
- Console configurator already renders `*.enabled` as a toggle once the path
  is editable. Label copy, if any special case exists, must say the stage
  needs the isolated worker and does not install a browser on the scanner.

### API and console

- `GET /api/runs/{id}/screenshots` and operator-only PNG download stay as they
  are. Do not weaken viewer denial.
- Restore the Screenshots tab on the run view for operator-or-higher
  (`canOperate`). Viewers do not see the tab and do not call the endpoint.
- A `tab=screenshots` link opens that tab for an operator and Findings for a
  viewer.
- Panel copy stays honest: redaction covers obvious form fields only; PNGs
  can still hold personal data; retention deletes pixels.

### Honesty

- Do not claim capture works in published scanner images. It works when the
  worker Deployment is running and the stage is enabled.
- Do not mark ROADMAP 9.3 / P4.4 Done until the worker, stage client, k8s
  manifests, config toggle, console tab, and tests exist. Wording: capture
  is supported only through the isolated worker; scanner images still ship
  no browser.

## Non-goals

- No new port scan, no scope expansion, no change to retention windows.
- No Playwright dependency in `requirements.txt` of the scanner/API images.
  The worker image installs it.
- No screenshot of arbitrary operator-typed URLs. Only already-open web ports
  from the run.
