# Host deadline for sealed quality runs

Run `scripts/operator-quality-watchdog.py` on the host to launch one **new**
sealed evaluator container. Pass the same sealed runtime options, immutable
image, source mounts, output mount and evaluator arguments after `--`. The
controller creates the runner with its own fresh name, nonce label and `--cidfile`,
verifies ownership, then starts it separately;
the supplied options must not override them or use `--rm`. No image is pulled.

On Docker Desktop for Mac, use a **new native Docker results volume**. The
2026-10-26 bind-mounted pilot returned one valid response in 26.71 seconds,
then directory `fsync` failed with `EBADF` on VirtioFS. That attempt remains a
failed harness attempt; its response and unresolved journal are retained. File
`fsync` alone cannot establish durable journal rename or deletion. The evaluator
now exercises write/file-fsync/rename/directory-fsync/readback/unlink/directory-fsync
before any model call. An unsupported operation aborts; it is never ignored.

For native-volume mode, provision a uniquely named empty local Docker volume;
never reuse a previous attempt's volume. Initialize only its root directory for
the runner's UID (for example mode `01777` with a network-none, read-only-root,
capability-dropped setup helper). Keep the volume and stopped runner on success
and failure. Mount frozen inputs read-only and give the runner no Docker socket.
Use these additional controller/evaluator arguments:

```sh
# Controller arguments, before its -- separator:
--run-directory /absolute/host/new-attempt/exported-results \
--container-run-directory /artifacts/results

# Docker arguments, after -- and before the pinned image:
--mount type=volume,src=NEW_OWNED_LOCAL_VOLUME,dst=/artifacts,volume-nocopy

# Evaluator arguments, after the image and script:
--output /artifacts/results --require-native-filesystem --require-launch-permit
```

`exported-results` must not exist at launch. Native mode verifies a writable
local volume mount and requires the evaluator's ext4 preflight. The host polls
at two-second intervals, reading at most 8192 bytes of `inflight.json` through
`docker exec` only after verifying the immutable CID/name/nonce. Each RPC has a
five-second timeout. Case age is checked before and after polling; a changed or
missing journal cannot erase the previous deadline. There is no host bind
mirror whose weaker durability could authorize a retry.

Native production evaluators also require a launch permit. The controller
injects its fresh nonce and writes a permit only **after start returned success
and the same owned CID is verified Running**. The native permit is file-fsynced,
atomically renamed and directory-fsynced. It binds that nonce, the full immutable
CID and UTC requested/issued/expiry timestamps; expiry is at most 60 seconds
from the original start request. The evaluator checks the nonce, its default
Docker hostname/CID prefix, timestamp order and expiry, then fsyncs an
authorization copy with the results. It rechecks expiry immediately before its
first provider dispatch. Missing, foreign, expired or malformed authority
cannot reach the provider. This is a one-time launch gate, not permission to
retry cases or a change to the 120/150-second case deadlines.

A failed start RPC never issues a permit, so a later start remains unable to
call the model. A permit-write RPC can be uncertain *after delivery*: distributed
delivery cannot atomically revoke authority already received by the runner.
That failure stays failed and under active terminal supervision; a bounded
inference window may exist before owned cleanup completes. Do not claim zero
late effects for every possible control-plane failure. No permit write or start
is retried. Caller-supplied `--restart` policies are forbidden; the fresh runner
uses Docker's default no-restart policy.

After confirmed terminal state, `docker cp` exports the directory into a new
temporary host directory. The controller rejects symlinks/special entries,
hashes and fsyncs each file, fsyncs the directory, renames it into the new host
destination and fsyncs its parent. Only then does it record the export receipt.
An export failure makes the controller fail even after process exit zero;
partial host exports and the authoritative native volume are retained. A
failed/unconfirmed kill cannot be called a completed export. The native
`inflight.json` is included even when SIGKILL prevented a final report. Recovery
uses that original native evidence, never a reconstructed successful receipt.

The remaining host-bind example is for filesystems on which the same durability
preflight succeeds; it is not the production Mac configuration.

```sh
python3 scripts/operator-quality-watchdog.py \
  --cidfile /private/tmp/quality-attempt-new.cid \
  --receipt /private/tmp/quality-attempt-new-watchdog.json \
  --run-directory /absolute/host/path/to/evaluator-output \
  -- \
  --network SEALED_PRIVATE_NETWORK --read-only --user 65532:65532 \
  --memory 512m --pids-limit 64 \
  --mount type=bind,src=/absolute/frozen/source,dst=/workspace,readonly \
  --mount type=bind,src=/absolute/host/path/to/evaluator-output,dst=/evidence \
  --entrypoint python sha256:EXISTING_LOCAL_IMAGE_ID \
  /workspace/scripts/operator-evaluate.py run --output /evidence \
  --manifest /evidence/manifest.json --provenance-json /evidence/provenance.json \
  --external-resource-sampling --base-url http://FIXED_PRIVATE_GATEWAY:8082/v1
```

Paths, network and image above are placeholders; retain the established sealed
runner configuration and permissions. The host `--run-directory` must map to
the evaluator's output directory so the controller can read `inflight.json`.
The cidfile must not already exist. Retain the stopped runner and its logs for
evidence; the controller does not remove it or restart it.

For each case, the first observed source UTC `started_at` establishes the case
age. The host then keeps a monotonic deadline; rewriting the same case's clock
or repeating its initial execution fails. Initial identities are
`initial:<case_id>`. Soak identities are `soak:<iteration>:<case_id>` with a
strictly increasing positive iteration; a gold case may legitimately recur
under a new soak execution. Every initial and soak call publishes its inflight
journal atomically and fsyncs it before inference, then fsyncs its result before
removing the journal. This keeps the deadline live through the entire soak.
At **120 seconds**, the controller records failure
and sends SIGINT to the evaluator's PID 1. At **150 seconds**, including an
explicit 30-second cleanup grace, it sends SIGKILL if still running. A soft
timeout remains failed even if cleanup exits with code zero. The evaluator's
30/120-second acceptance criteria, model, prompt, gold labels and thresholds
are unchanged. A watchdog pass means only normal process termination without
a watchdog violation; the evaluator's quality report remains authoritative.

Every signal requires the complete immutable container ID from this launch's
new cidfile, the exact controller-generated name and its fresh nonce label to
match a current Docker inspection. No model container is stopped. Missing or
mismatched identity prevents signalling and is recorded as failure. Docker
commands have a five-second host timeout; their errors are recorded separately
from case overruns. The host scheduler and Docker daemon can still stall, so
actual elapsed time and a failed kill attempt must not be represented as an
exactly enforced deadline or proof that the runner stopped.

If a host/polling gap crosses a case deadline and the journal disappears,
changes to another execution, or Docker returns an exited runner, the previous
deadline remains failed as `case_completion_control_gap`. A missing journal or
exit code zero is not a durable timed completion receipt. This conservative
uncertain outcome prevents a blocked poll from silently erasing an overrun.

The receipt's JSONL journal fsyncs each control event. Final/checkpoint JSON is
written through an fsynced temporary file and directory rename. Prior attempts'
receipts are never reused; the same controller updates its failed/pending
checkpoint until terminal proof. Raw evaluator inflight/record files are read-only to this
controller. If SIGKILL prevents the evaluator from writing a final receipt,
retain the unresolved inflight case as failed/unknown; existing recovery does
not retry it. An uncertain soak execution goes only to `soak-records.jsonl` as
failed; it never replaces or appends an initial gold record. Resume advances to
the next soak iteration and retains the failed iteration in load totals. A fresh run is a separate attempt, never a replacement for a
failed attempt. Startup or a gap with no inflight progress is bounded to 60
seconds plus cleanup. An invalid journal has a three-second write-race grace;
it cannot reset an already observed case deadline.

Creation and start are separate Docker calls. If creation times out before a
valid cidfile is returned, the controller never starts an untracked workload.
Preserve the generated name/nonce receipt and inspect any leftover created
container manually when Docker responds; a missing ID never authorizes a kill.

A timed-out **start** is different: Docker may execute that one queued request
after both the start RPC and cleanup inspection have timed out. A real native
pilot exposed this race on 2026-10-26. The previous controller returned failed
while its known runner started later; that attempt is retained as failed and
was stopped separately. It must not be treated as an unattended successful run.

After any issued start, the controller now remains responsible for its verified
CID until terminal state is confirmed. `created`, paused, unknown and an exit
with zero/absent `StartedAt` are not terminal proof. Sticky failed supervision
continues with two-second polling and five-second RPC bounds, rechecks all
ownership fields before SIGKILL, and never retries start. Only a completed start
followed by `exited`, `dead`, or an explicit missing response for that exact CID
resolves the pending-start risk. The controller fsyncs failed/pending checkpoint
receipts while Docker is unavailable; it does not impose a total give-up time
that could abandon a later start. Export occurs only after terminal proof.
If checkpoint I/O/fsync itself fails, the controller remains failed and continues
owned cleanup, reports bounded failure metadata to stderr, and retries evidence
persistence on subsequent cycles. It does not call that missing checkpoint
durable; persistence failures remain explicit in the final receipt when storage
recovers. A logging failure must not unwind the reaper before terminal proof.

SIGINT/SIGTERM of the host controller requests owned-runner cleanup instead of
unwinding supervision. If Docker remains unavailable the failed controller may
therefore remain alive until manual recovery permits inspection and stopping.
Do not SIGKILL it while a known runner is unresolved. Host failure or SIGKILL
cannot be made safe by Python signal handlers: preserve the CID/name/nonce
receipt and verify/stop that specific runner after recovery before any new run.
This control limitation never authorizes a model request retry or a PASS.
