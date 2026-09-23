# farcmd-mcp

OAuth-protected MCP server for predefined SSH command capabilities.

## Phase 1

Phase 1 establishes the secure MCP/OAuth foundation. Phase 2 adds the browser control plane with Vite, account registration/login, persistent browser sessions, account settings, and baseline CSRF/origin and login-rate protections. The SSH command registry and execution model arrive in later phases.

Implemented:

- MCP Streamable HTTP at `/mcp`
- OAuth Authorization Code + PKCE S256
- CIMD-first client identification
- OAuth protected-resource metadata
- OAuth authorization-server metadata
- issuer/resource-bound JWT access tokens
- refresh tokens
- Argon2id passwords
- durable SQLite persistence
- authenticated MCP health tool
- health endpoint

## Deployment

Production runs behind a TLS-terminating reverse proxy (Traefik or nginx). See [`docs/deployment.md`](docs/deployment.md) for the Docker image and `docker-compose.yml`, the nginx example in `deploy/nginx/`, `FARCMD_TRUST_PROXY`, the environment reference, and backup, restore and upgrades.

## Development

Requires Node.js 22+.

```sh
cp .env.example .env
# Set JWT_SECRET to base64 for at least 32 random bytes.
# Set MCP_DEFAULT_USER_PASSWORD to a development password.
npm install
npm run typecheck
npm run build
npm run dev
```

The default OAuth account is bootstrapped from `MCP_DEFAULT_USER_EMAIL` and `MCP_DEFAULT_USER_PASSWORD`.

The OAuth authorization page uses a short-lived server-side login session between password authentication and consent; credentials are not carried into the consent form.

## Architecture

```
MCP client
   │
   │ OAuth + Bearer
   ▼
farcmd-mcp
   ├── OAuth authorization server
   ├── MCP Streamable HTTP
   └── authenticated connector
```

The OAuth/MCP baseline is derived from the reusable architecture in `codestash/mcp/api-connector-style`.

See `IMPLEMENTATION_PLAN.md` for the nine-phase roadmap.


## Phase 2 web control plane

The Vite application lives under `web/`. In development, run:

```bash
npm install
npm run dev
```

This starts the Fastify API on port 5999 and the Vite development server on port 5173. The Vite server proxies `/api` requests to Fastify.

For a production build:

```bash
npm run build
NODE_ENV=production npm start
```

The production Fastify server serves `dist/web`.

### Accounts and sessions

Users can create an account, sign in, sign out, and update their name/email. Browser sessions are stored in SQLite as opaque random tokens and sent in an HttpOnly, SameSite=Lax cookie. Passwords are hashed with Argon2id.

**Registration is off by default.** New accounts are created by the operator with the `farcmd-admin` CLI. Self-service sign-up in the web UI can be switched on with `farcmd-admin registration enable`; the setting lives in the database (`app_settings.registration_enabled`), and the sign-up link is shown only while it is on.

### User administration (`farcmd-admin`)

The CLI works directly on the database, so run it on the server with the same `STORAGE_PATH` and `FARCMD_ENCRYPTION_KEY` as the service (for example `node --env-file=.env dist/cli/admin.js …`, or `npm run admin -- …` in development). Every change goes into the audit log with actor `system`.

```sh
farcmd-admin user list [--json]
farcmd-admin user create --email alice@example.org --name "Alice"      # prompts for the password
farcmd-admin user password --email alice@example.org                    # ends all sessions and refresh tokens
farcmd-admin user disable --email alice@example.org                     # refuses web, OAuth and MCP at once; reversible
farcmd-admin user enable --email alice@example.org
farcmd-admin user logout --email alice@example.org                      # ends all web sessions and refresh tokens
farcmd-admin user delete --email alice@example.org [--yes] [--force]
farcmd-admin registration status|enable|disable
farcmd-admin mcp status [--email alice@example.org]
farcmd-admin mcp disable --all                                          # MCP off for every user; server keeps running
farcmd-admin mcp disable --email alice@example.org                      # MCP off for one user; the user cannot undo it
farcmd-admin mcp enable --all | --email alice@example.org
```

Passwords are never accepted as arguments, because they would end up in shell history and the process list. They are read from a hidden prompt, or from the first line of stdin with `--password-stdin` (e.g. `printf '%s\n' "$PW" | farcmd-admin user create … --password-stdin`). `user delete` removes the user and all of their farcmd data, but not the audit log. It refuses while the user still has capabilities or verifiers installed on remote hosts (remove them in the web UI first) unless `--force` is given. A disabled user's existing MCP access tokens are refused immediately, not just when they expire.

### MCP access switch

MCP can be turned off without stopping the farcmd process. Three switches apply, and MCP works for a user only while all three allow it:

| Switch | Who | How |
|---|---|---|
| Own access | the user | **Turn off MCP access** button at the top of the Commands page (the page after sign-in) and on OAuth Sources (`PUT /api/mcp-access`) |
| Per user | operator | `farcmd-admin mcp disable --email …`; the user sees "disabled by the administrator" and cannot lift it |
| All users | operator | `farcmd-admin mcp disable --all` (setting `mcp_enabled`) |

While MCP is off, execution tools are no longer listed. `farcmd_health` and `list_commands` stay listed but return an error that says why. Execution is refused even with a still-valid access token or a confirmation token obtained earlier, and a pending level 4/5 confirmation cannot be approved. The web UI, OAuth grants and tokens are left untouched, so turning MCP back on works immediately without reconnecting clients. Every change and refused call is audited. farcmd has no admin role in the web UI: operator actions are CLI-only.

### Web and execution hardening

- **CSRF.** Every state-changing `/api/` call must carry the `X-Farcmd-Request: 1` header, which the web UI always sends. A cross-site page cannot set it without a CORS preflight, and farcmd never grants one. Requests whose `Sec-Fetch-Site` is `cross-site` or `same-site` are refused, and so is an `Origin` other than `MCP_PUBLIC_URL`. The session cookie is `HttpOnly` and `SameSite=Lax`, and `Secure` in production.
- **Rate limits.** Login, registration and web confirmations have per-IP rate limits. MCP executions are limited per user and OAuth client: `FARCMD_MCP_EXECUTIONS_PER_MINUTE` defaults to 30, and `0` turns the limit off. New executions and level 4/5 confirmation requests count; fetching a confirmed result does not.
- **SSH concurrency.** At most `FARCMD_SSH_MAX_CONCURRENT` executions run at once (default 8), and at most `FARCMD_SSH_MAX_PER_TARGET` per target (default 2). A call over the limit is refused immediately with a "try again shortly" error, not queued, and the refusal is audited.
- **OAuth sign-in step.** The short-lived session between sign-in and consent on `/oauth/authorize` is stored in SQLite as a hash. It survives a restart, is single use and is purged when it expires.

The Phase 1 development bootstrap account remains optional: set `MCP_DEFAULT_USER_PASSWORD` to create it. Omitting that variable is now valid when using normal account registration.


## Phase 3 configuration

SSH private keys are encrypted at rest with AES-256-GCM. Set `FARCMD_ENCRYPTION_KEY` to a base64-encoded random 32-byte key before starting the server:

```sh
openssl rand -base64 32
```

The SSH private-key passphrase, when one exists, is never persisted by farcmd-mcp. The web UI unlocks a key for a short in-memory session (15 minutes), after which the passphrase must be entered again. Host fingerprints are verified during connection tests; an unknown host is not silently trusted.

Never commit `FARCMD_ENCRYPTION_KEY`, SSH private keys, or passphrases.


## Command registry

Commands are predefined SSH capabilities owned by a user. Each command has a human-assigned level from 1 to 5:

1. Safe/read-only operations
2. Low-impact operations
3. Normal mutating operations
4. High-impact operations
5. Dangerous/destructive operations

The exact shell command is stored server-side and is visible in the authenticated human web UI. It is intentionally not part of MCP discovery. Phase 4 provides the registry and management UI; MCP discovery and execution are implemented in Phase 5.


### SSH master keys and command capabilities

SSH credentials are split into two roles:

- **Master keys** are provisioning credentials. They can be generated in the SSH page or uploaded by the human, with or without a passphrase. The private key is encrypted at rest; a passphrase is kept only in short-lived process memory after an explicit web-UI unlock.
- **Command installations** are runtime capabilities. Farcmd generates a dedicated Ed25519 key for each installed command and encrypts the private half at rest.
- The command's executable content is installed as a farcmd-managed script under `~/.ssh/farcmd/`. The filename is based on the MCP public hostname and command UUID, for example `~/.ssh/farcmd/mcp.example.com-<command-id>.sh`.
- The authorized-key entry is forced to that exact script path with OpenSSH's `restrict,command="..."` mechanism. OpenSSH ignores the command supplied by the client for such a key, so the command key cannot be turned into a general shell capability.
- A command has two executable-content types: **shell command** (single line) and **Bash script** (multi-line). The installed capability points to the generated script rather than embedding the operation directly in `authorized_keys`.
- MCP execution uses only the installed command key. The master key is never a runtime fallback, and it is not used for verification either.
- If executable content or the target of an installed command changes, the existing capability must first be removed/replaced. If the master key is unavailable, the existing capability can still run, but replacement/removal is deferred.
- Deleting a command or command capability is allowed even without a master key. If farcmd cannot remove the remote authorized-key entry and script immediately, it records the exact remote capability in a **remote capability ledger** for later cleanup.
- When a master key becomes available again, the web UI can retry cleanup of pending/failed ledger entries.
- Master-key deletion or replacement is intentionally allowed even while command capabilities exist. Existing command capabilities remain independent; deleting the master key simply removes provisioning/revocation authority until another master is configured.

Per-command capability installation currently expects a POSIX/Linux-style target with the standard `base64` utility.

### Capability integrity verification (levels 3–5)

Immediately before a level 3, 4 or 5 command runs (after human approval or password confirmation for L4/L5), farcmd verifies that the remote capability is still exactly what it provisioned. Without a successful verification the command is **blocked**; there is no unverified fallback. Levels 1–2 keep their previous behaviour.

- Each target gets its own **verification authority**: a verification SSH key forced (`restrict,command=…`) to a **root-owned verifier** through an argument-free sudoers rule, plus a 32-byte **HMAC secret** readable only by root on the target and stored encrypted in farcmd.
- farcmd sends a fresh 256-bit nonce. The verifier measures the capability scripts, every `authorized_keys` entry sshd uses, and itself, and returns the measurement authenticated with `HMAC-SHA256(secret, measurement)`. A fake or modified verifier can't read the secret, so it can't claim "unchanged". An old response can't be replayed.
- Verification uses no master key, so it keeps working after the master key is deleted. Provisioning, replacement and remote cleanup do not.
- Install or repair the verifier on the SSH page: automatically (farcmd connects with a master key as the command account or as another account on the same host, such as an admin account, and gets root through the root account, that account's sudo password entered once in the UI and never stored, or passwordless sudo), or with a one-time **manual root install script**, which works without any master key. Target requirements: `python3` and `sudo`.
- The target account must not have unrestricted sudo/root: root on the target is outside what any on-host verifier can defend against.

See [`docs/capability-integrity.md`](docs/capability-integrity.md) for the threat model, protocol, trust boundary, TOCTOU analysis and lifecycle. `sudo -E npm run test:e2e` runs the end-to-end tests against a real OpenSSH server.

### Approving level 4 and 5 commands

A level 4 or 5 tool call never runs the command itself. It creates an approval request (valid for 5 minutes) with a link to the web UI, where the signed-in owner approves it (level 5 also needs the command's execution password). An approval runs the command once. Approving again, or approving an expired or declined request, is refused.

- **Clients that support URL elicitation** (they declare `elicitation.url` in `initialize`): the call sends the link to the client as an `elicitation/create` request in URL mode, so the client shows it to the person directly. The call then stays open until the command has run and returns its result, followed by `notifications/elicitation/complete`. If the client passed a progress token, a progress notification every 15 seconds keeps the connection alive. If the person declines or dismisses the link, the request is expired and the call returns an error. This works on the stateless endpoint: farcmd sends the elicitation on the call's own response stream and routes the client's answer (a separate `POST /mcp` from the same user and OAuth client) back to it. There is no standalone SSE stream (`GET /mcp` stays 405).
- **Fallback, for every other client**, or when the elicitation fails or the call ends early: the call returns `pending: true` with `approvalUrl` and `confirmationToken`. After approval, calling the same tool with the token returns the result, once.

Behind a proxy, allow MCP requests to stay open for about 6 minutes (the nginx example uses `proxy_read_timeout 360s`).

### Running commands from the web UI

Every command has a **Run** button on the Commands page (it needs an installed SSH capability).

- **Levels 1–3** run at once, and the result (exit code, duration, stdout and stderr) is shown in a dialog.
- **Level 4** asks for confirmation first, and **level 5** for the command's execution password.
- **Show output after approval** is a per-command setting for levels 4–5. When it is off (the default), the approval page and Run show only the exit code and duration. The MCP client always gets the full result, and History always records it.

Web runs go through the same integrity verification, SSH limits, history and audit as MCP runs, recorded with client `web` (`command.web_run` plus `command.execute` with actor `web`). The MCP access switch does not apply to them, because they are not MCP calls. Output is returned when the command finishes; it is not streamed.


## OAuth tokens

Access tokens are short-lived JWTs (1 hour). Refresh tokens:

- **Rotate** on every use: the response carries a new refresh token and the old one stops working.
- Belong to a **family** that expires 30 days after the original authorization; refreshing does not extend it. The user then authorizes again.
- Are **reuse-detected**: presenting an already-used refresh token (a sign it was copied) revokes every live token in its family, and the event is audited as `oauth.refresh_token_reuse`. Authorization codes are single use in the same way (`oauth.code_reuse`).
- Are stored only as **SHA-256 hashes**, as are authorization codes, so a copy of the database contains no usable tokens.
- Are deleted when the OAuth grant is revoked in the web UI, when the password changes, and when the account is disabled or logged out with `farcmd-admin`.

## Audit log

Security-relevant actions are recorded in an append-only audit log (`security_events`) and shown on the **Audit** page of the web UI (`GET /api/audit`, filterable by event, outcome and text).

What is recorded:

- **Web control plane**: every state-changing API call, recorded automatically by one Fastify hook with the event name, acting user, target, outcome, HTTP status, error and a list of changed field names (plus non-secret values such as level, enabled, hostname or visible levels). Covers sign-in, failed sign-in (attributed to the targeted account), registration, logout, account changes, SSH key upload/generate/unlock/lock/delete, target changes (including host fingerprint pinning), commands, capability install/remove/cleanup, level-5 password changes (including an automatic clear when a level 5 command is moved off level 5 or its script or target changes, recorded as `command.level5_password_cleared` with the reason), verifier install/repair/manual script/verify/removal, OAuth grant changes/revocation, and reading remote shell history. A test fails if a new mutating route is not mapped to an audit event.
- **OAuth**: consent approved or denied (with the granted levels), failed OAuth sign-in, token issue and refresh, rejected grants.
- **MCP**: confirmation requested, attempted and executed; level-5 password failures; refused calls (revoked grant, hidden level, wrong tool); integrity verification passed or blocked; every command execution with exit status.

Secrets are never recorded: request bodies are not logged as a whole, secret-looking keys (passwords, passphrases, private keys, tokens, …) are always removed, and command content is stored only as its SHA-256.

**Tamper evidence.** Each entry has a sequence number and `hash = HMAC-SHA256(K, previous hash ‖ entry)`, with `K` derived (HKDF) from `FARCMD_ENCRYPTION_KEY`. *Verify integrity* on the Audit page (`GET /api/audit/verify`) recomputes the chain. It detects any modified, reordered or deleted entry, and someone with database access alone cannot recompute it. It cannot detect removal of the *newest* entries unless you compare against a head hash noted earlier; the verify result shows the current head for that purpose.

**Retention.** `FARCMD_AUDIT_RETENTION_DAYS` (default 365, `0` = keep forever). Pruning runs at startup and daily, removes only the oldest entries, and records an `audit.pruned` entry with the last removed hash, so the remaining chain still verifies. Execution output is kept separately in the execution history.
