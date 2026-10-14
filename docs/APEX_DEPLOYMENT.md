# APEX deployment contract 1.0 — shapoclyack

The root `apex-deploy.json` declares the installation method and required parameter names.
The common schema is `apex-contract/deployment/apex-deploy.schema.json`.
APEX reserves one dedicated server for one product, archives the selected Git SHA,
and only reports Docker readiness after the declared service's real healthcheck.

Mode: **docker**. Required parameters: SHAPOCLYACK_IMAGE, POSTGRES_IMAGE, POSTGRES_PASSWORD, OCTO_JWT_SECRET, OCTO_MASTER_KEY, OCTO_API_USERS, OCTO_API_CORS.
Also provide `APEX_GATEWAY_URL` and `APEX_SERVICE_URL`. They declare the integration
addresses; domain-specific adapters and credentials still require operator configuration.
Secrets must never be committed. The platform's `deployment/install.py` asks for SSH
key paths and lets OpenSSH request passwords/passphrases in the terminal.
Environment values are entered with hidden input and written to a protected
`/etc/apex/shapoclyack.env` on the target only on explicit first-time setup.

Recipe: `compose.apex.yml`; readiness service: `api`.
Run `docker compose --env-file /etc/apex/shapoclyack.env -p apex-shapoclyack -f compose.apex.yml config --quiet` before installation.
Published images should be verified and selected by digest. Build/healthcheck validation
is not physical-server acceptance. Root or prepared `/opt/apex` and Docker permissions
are required. A host reverse proxy with trusted TLS must expose loopback-bound APIs
to APEX; do not publish unauthenticated management ports.

Supply a verified all-in-one image in SHAPOCLYACK_IMAGE and PostgreSQL image in POSTGRES_IMAGE. OCTO_API_USERS must contain real operator credentials, never shipped demo users. PostgreSQL passwords used in the URL must be URL-safe. Public origin and CORS must be HTTPS origins of your reverse proxy.
