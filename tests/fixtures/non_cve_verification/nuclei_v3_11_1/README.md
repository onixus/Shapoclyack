# Exact HTTP object verification capture

Actual local Nuclei v3.11.1, fabricated non-CVE template and secret marker.
Captured on 2026-10-15 (Europe/Istanbul) using immutable scanner image
`sha256:62e891b874733b4d1396066fa16e30b1e5d07eac3364f72b67e75a36340fd7f9`.
The container used `--network none`; only its own loopback server was probed.
No external target, production detector efficacy, or release acceptance claim.

`capture.py` starts the loopback server and runs the current scanner stage.
The positive and remediated phases each received exactly `/backup.zip`.
The template with `{{BaseURL}}/backup.zip` was refused before any HTTP request.
`-disable-redirects` and Nuclei's template-loading statistics worked with this
pinned engine. Captured raw JSONL remains unchanged; its request/response body
contains only the deliberately fabricated local marker. `positive.json`,
`remediated.json`, `appended-path.json` are actual scanner adapter outputs.
Offline tests consume these artifacts; rerunning capture requires the pinned
image and an isolated container, and is not part of the test suite.
