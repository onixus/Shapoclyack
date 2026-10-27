# Isolated operator console on this Mac

The optional local development stand serves the exported operator console at
[http://127.0.0.1:8083/operator](http://127.0.0.1:8083/operator). It uses an
independent PostgreSQL container/database and a separate singleton operator
worker. It does not use or migrate the existing kind deployment or test DB.
There are no synthetic scans, devices, findings or model answers in this stand.

Start the verified local inference runtime with
[`scripts/operator-mac.sh`](../scripts/operator-mac.sh), build `web-next/out`,
then run:

```console
python3 scripts/operator-console.py up
python3 scripts/operator-console.py smoke
python3 scripts/operator-console.py ps
```

`up` generates one random bootstrap admin account and independent random
PostgreSQL, JWT and encryption secrets. The username/password and recovery
secrets are in `.operator-local/credentials`; this directory is ignored by Git,
mode 0700, and secret files are mode 0600. Commands and smoke output never print
secret values. `console.env` and `postgres.env` are generated private files,
not repository configuration. The database becomes the account source of
truth after bootstrap: changing a saved password in the credential file does
not rotate an existing account. Use the ordinary password-change API.

The compose file pins already-cached local API and PostgreSQL image IDs. This
is a development overlay: current `api`, scanner configuration/pipeline and
`web-next/out` are mounted read-only. It is not an immutable release image or
a portable published bundle. New source changes require recreating/restarting
API and worker; UI export changes require rebuilding the export.

The API and PostgreSQL join only `shapo-operator-console_console`, an internal
network. The worker also joins the shared internal
`shapo-operator-offline` network at `172.30.83.3`; inference owns
`172.30.83.2:8082`. The adapter therefore receives a configured private IP
literal, not a request-selected hostname or URL. Inference cannot reach the
database network. There are no cloud credentials or hosted-provider opt-ins.

Docker Desktop does not expose published ports for an internal-only network.
A separate fixed-target ingress joins the console network and its own normal
bridge and publishes only `127.0.0.1:8083`. It receives no account/database
secrets or application mounts; its only target is `api:8080`. A second
credential-free gateway in the inference compose file publishes
`127.0.0.1:8082` to the fixed `172.30.83.2:8082` target. Neither proxy accepts
CONNECT or absolute request URLs, follows redirects, or permits a client to
choose its upstream. Proxy bridge access is not a physical egress acceptance
report; inference/API isolation still requires the documented final test.

This loopback HTTP stand explicitly uses the development environment and
non-secure refresh cookies. Random credentials and encrypted integration
secrets remain enabled. It is not configured for production or LAN exposure.
Scan start/verification dispatch, ordinary scheduling, reports, mail/webhooks,
tracker sync and unrelated matching dispatchers are disabled. Operator tasks
remain bounded and run only after the authenticated user submits them. A
missing runtime is reported through existing task/provider failure states;
configuration status remains `not_checked` and quality `quality_unverified`.

Persistent stand data lives under `.operator-local/postgres-data`, `state` and
`output`, using task-owned host bind mounts. This also avoids consuming the
already full Docker VM disk. The private parent protects these directories;
only their specific container mounts are shared. PostgreSQL on Docker Desktop
host sharing is a development convenience, not a production durability or
backup/restore result.

Stop only this console stack, preserving its data:

```console
python3 scripts/operator-console.py down
```

The inference project has its own lifecycle (`scripts/operator-mac.sh down`).
Neither stop command removes existing projects, databases, models or host data.
Retain the private credentials/encryption keys with any backup; do not commit
them or include their values in reports or screenshots.
