Actual Nuclei v3.11.1 JSONL captured on 2026-10-15 inside an isolated
`--network none` local container, against its own loopback fixture HTTP server.
Binary: `/out/nuclei` from local `shapo-go-tools-check:latest`, image
`sha256:9c84d15ed039` (short local image ID; not an immutable registry pin).
The local template is included. CVE-2099-9999 is deliberately fabricated;
this demonstrates the real engine output format, not detection of a real CVE.
No external systems were scanned. The randomized loopback port and timestamp
are retained as emitted by the engine. Capture includes raw HTTP material and
must be treated as a restricted artifact by production consumers.
