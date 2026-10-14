# Scanner invocation and process ownership

`agent.runtime.invocation` owns the portable `ScanInvocation` and input file /
CLI flag mapping. `agent.runtime.process` owns process spawn, both output pipes,
monotonic waiting, cancellation and TERM/KILL mechanics. Both modules use only
the Python standard library. The API imports this small runtime, never the
worker. The autonomous sensor has no dependency on API, FastAPI or SQLAlchemy.
The runtime ships as part of the signed sensor bundle alongside `agent.worker`.

API admission still resolves tenant permissions and materializes approved scope,
policy and overlays before dispatch. Sensor materialization copies the accepted
text unchanged and only substitutes host-local file paths. Wire inputs remain
filename-to-text objects; API absolute paths are never portable sensor references.
Missing inputs retain installation defaults. Explicit empty files retain empty
content and remain CLI inputs. A legacy ranges-only or domains-only payload
creates the absent counterpart as an empty file rather than reading installation
targets. Unknown filenames, repeated flags and unsupported modes are refused.
Scope and policy JSON are not interpreted or broadened by the sensor. Before
claiming a job, the API checks that every input required by its persisted
accepted command is present. Missing admitted files return 503 with logical
filenames, retain the queued job and create no lease. Restore the accepted input
files before retrying; this condition does not request an agent upgrade. Legacy
commands without input flags retain their original behavior.

The two adapters retain different business outcomes: local invocation has no
implicit timeout, and replica-local `stop_all` remains teardown rather than a
cross-replica cancel API. Sensor scans retain their configurable 7200-second
default and result codes 124 for timeout and 143 for cancellation. Cancellation
preserves a best-effort partial archive; timeout does not introduce one. Spawn
errors retain the local exception / sensor failed-result distinction.

A cancellation already present prevents spawn. A cancellation set during spawn
is checked immediately after registering the process. The runtime uses list argv
without a shell and drains both pipes while waiting. POSIX children share a new
session whose initial process-group id is captured as the original parent PID,
so TERM/KILL still reaches children if the leader exited first. Natural leader
exit also cleans remaining group members, including children that closed their
inherited pipes, before releasing registry ownership. Completed handles cannot
signal that group again. One shutdown
budget bounds graceful waiting, escalation, reaping and final output collection;
local teardown also shares its total deadline across registered processes and
thread joins. Concurrent stops share one owner per process handle; a shorter
waiter deadline tightens the owner's graceful wait and reaping. Once the group
is observed absent, no subsequent escalation may signal its reused identifier. Failed local shutdown retains its barrier and visible handles
until a later stop observes completion.

Supported sensor platforms remain Linux and macOS. The shared runtime's Windows
fallback only terminates the direct child; it neither establishes process-tree
support nor introduces Windows sensor support. Children deliberately escaping the
POSIX group are outside this process-group contract.
