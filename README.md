# farcmd-mcp

**Let an AI assistant run a fixed set of SSH commands on your servers — and nothing else.**

farcmd-mcp is an OAuth-protected [Model Context Protocol](https://modelcontextprotocol.io) server. A person defines *commands* in a web UI (for example "restart the web service on host A" or "show disk usage on host B"), gives each one a risk level from 1 to 5, and installs it on the target host as a single-purpose SSH key. MCP clients such as Claude or ChatGPT can then list those commands and run them by ID. They never see the shell command itself, cannot pass arguments to it, and cannot get a shell.

- **Five risk levels.** Levels 1–3 run at once; levels 4 and 5 need a person to approve each run in the browser (level 5 also needs the command's own password).
- **Per-client visibility.** When you connect an MCP client you choose which levels it may see. Level 5 can be hidden from a client permanently.
- **One key per command.** Each command gets its own Ed25519 key, pinned on the target with OpenSSH `restrict,command="…"` to one farcmd-managed script.
- **Integrity checks.** Before a level 3–5 command runs, a root-owned verifier on the target proves with an HMAC over a fresh nonce that the script and `authorized_keys` are still exactly what farcmd installed. If the check fails, the command does not run.
- **Audit trail.** Every security-relevant action goes into an HMAC-chained, tamper-evident audit log.

Version: **1.0.0** · License: [EUPL-1.2](LICENSE)

---

## Contents

- [How it works](#how-it-works)
- [Installation](#installation)
- [Connecting an MCP client](#connecting-an-mcp-client)
- [The MCP interface](#the-mcp-interface)
- [The web UI](#the-web-ui)
- [Administration (`farcmd-admin`)](#administration-farcmd-admin)
- [Security](#security)
- [Development](#development)
- [Reference](#reference)
- [License](#license)

---

## How it works

```
 MCP client (Claude, ChatGPT, Cursor…)          Browser (the human)
        │  OAuth 2.1 + PKCE, Bearer JWT               │  session cookie
        ▼                                              ▼
 ┌──────────────────────────── farcmd-mcp ────────────────────────────┐
 │  /mcp  Streamable HTTP MCP      /oauth/*  authorization server     │
 │  /api  web control plane        /         Vite web UI              │
 │  SQLite: users, commands, encrypted keys, grants, history, audit   │
 └───────────────────────────────┬────────────────────────────────────┘
                                 │ SSH, one restricted key per command
                                 ▼
                 target host:  ~/.ssh/authorized_keys
                   restrict,command="~/.ssh/farcmd/<host>-<command-id>.sh" ssh-ed25519 …
                 + root-owned integrity verifier (levels 3–5)
```

1. **The operator** deploys farcmd behind HTTPS and creates user accounts with the `farcmd-admin` CLI.
2. **The user** signs in to the web UI and adds an SSH *master key* and a *target* (host, port, account, pinned host fingerprint).
3. The user creates **commands**: a single-line shell command or a Bash script, a target and a level from 1 to 5.
4. The user **installs** each command. farcmd uses the master key once to upload the script to `~/.ssh/farcmd/` and add a forced-command `authorized_keys` entry for a new per-command key. After that the master key is not needed to run the command, and it can be locked or deleted.
5. For level 3–5 commands, the user installs the **integrity verifier** on the target (automatically with sudo, or with a one-time root install script). The account that runs sudo can be a separate admin account, so the command account needs no sudo rights.
6. An **MCP client** connects to `https://<your-host>/mcp`. On first use it goes through OAuth: the user signs in and chooses which levels this client may see.
7. The client calls `list_commands` and then `command_level_<n>` with a `commandId`. farcmd checks the grant, the MCP switches, the rate limits and (for levels 3–5) the integrity of the target, then runs the command over SSH with that command's key and returns the exit code, stdout and stderr.

The five levels:

| Level | Meaning | Before it runs |
|---|---|---|
| 1 | Safe/read-only operations | — |
| 2 | Low-impact operations | — |
| 3 | Normal mutating operations | integrity verification |
| 4 | High-impact operations | human approval in the browser + integrity verification |
| 5 | Dangerous/destructive operations | human approval + the command's execution password + integrity verification |

---

## Installation

farcmd is a single Node.js process with a SQLite database. It **must** run behind a TLS-terminating reverse proxy (nginx, Traefik, Caddy…): OAuth, MCP clients and the `Secure` session cookie all need HTTPS. The full guide is in [`docs/deployment.md`](docs/deployment.md).

### 1. Secrets

```sh
openssl rand -base64 32   # FARCMD_ENCRYPTION_KEY: encrypts SSH keys at rest and keys the audit chain
openssl rand -base64 32   # JWT_SECRET: signs OAuth access tokens
```

Store `FARCMD_ENCRYPTION_KEY` safely and separately from backups. **If you lose it, the stored SSH keys cannot be decrypted and the audit chain cannot be verified.**

### 2. Docker image (recommended)

Images are published to GitHub Container Registry for `linux/amd64` and `linux/arm64`:

```
ghcr.io/jsilvanus/farcmd-mcp:1.0.0   # exact version
ghcr.io/jsilvanus/farcmd-mcp:1.0     # latest patch of 1.0
ghcr.io/jsilvanus/farcmd-mcp:1       # latest 1.x
ghcr.io/jsilvanus/farcmd-mcp:latest
```

#### Option A: with the repository's compose files

```sh
git clone https://github.com/jsilvanus/farcmd-mcp.git && cd farcmd-mcp
cp .env.example .env
#   MCP_PUBLIC_URL=https://farcmd.example.org
#   JWT_SECRET=…  FARCMD_ENCRYPTION_KEY=…
#   FARCMD_TRUST_PROXY=…   (see docs/deployment.md)
#   FARCMD_VERSION=1.0.0   (optional: pin the image version)

# nginx (or another proxy) on the host: the app is published on 127.0.0.1:5999 only
docker compose up -d
# or behind an existing Traefik on the external "proxy" network
docker compose -f docker-compose.traefik.yml up -d

# create the first account (prompts for the password)
docker compose exec farcmd farcmd-admin user create --email you@example.org --name "You"
```

`docker compose up -d --build` builds the image from the checkout instead of pulling it. An nginx site example is in [`deploy/nginx/farcmd.conf`](deploy/nginx/farcmd.conf). It sets up TLS, forwarded headers, and `proxy_buffering off` with long timeouts for MCP streams.

#### Option B: image only, no clone

This option needs only Docker and `openssl`. The secrets are generated **once** into an `.env` file. Don't put `$(openssl rand …)` directly on the `docker run` line: every re-run would then create new keys. A new `FARCMD_ENCRYPTION_KEY` makes the stored SSH keys unreadable, and a new `JWT_SECRET` signs out every MCP client.

```sh
mkdir -p ~/farcmd && cd ~/farcmd
umask 077
cat > .env <<EOF
MCP_PUBLIC_URL=https://farcmd.example.org
JWT_SECRET=$(openssl rand -base64 32)
FARCMD_ENCRYPTION_KEY=$(openssl rand -base64 32)
# Docker's default bridge gateway, which is where the host's reverse proxy connects from
FARCMD_TRUST_PROXY=172.17.0.1
EOF

docker run -d --name farcmd --restart unless-stopped \
  --env-file .env \
  -v farcmd-data:/data \
  -p 127.0.0.1:5999:5999 \
  ghcr.io/jsilvanus/farcmd-mcp:1

# create the first account (prompts for the password)
docker exec -it farcmd farcmd-admin user create --email you@example.org --name "You"
```

Then point your reverse proxy at `http://127.0.0.1:5999` (the nginx example above works as is).

**Why `FARCMD_TRUST_PROXY` isn't `127.0.0.1` here:** nginx connects to `127.0.0.1:5999` on the host, but Docker forwards that connection into the container, and inside the container it arrives from the bridge gateway (usually `172.17.0.1`), not from `127.0.0.1`. With `127.0.0.1`, farcmd would ignore `X-Forwarded-For`. Every client would then look like the gateway: they would share one login rate-limit budget, and the audit log would show the wrong IP. Check the gateway with `docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}'`. Compose projects get their own network with a different gateway (see [`docs/deployment.md`](docs/deployment.md#behind-nginx)). `127.0.0.1` is right only when farcmd runs directly on the host, without Docker.

Back up `.env` somewhere safe, separately from the data volume.

To upgrade, pull the new image and recreate the container. The data stays in the `farcmd-data` volume:

```sh
docker pull ghcr.io/jsilvanus/farcmd-mcp:1
docker rm -f farcmd   # then run the same docker run command again
```

The image runs as the unprivileged `node` user, keeps all state in the `/data` volume, has a `HEALTHCHECK` on `/health`, and puts `farcmd-admin` on `PATH`.

Images are built by [`.github/workflows/release.yml`](.github/workflows/release.yml) when a `vX.Y.Z` tag is pushed. The tag must match the `package.json` version. Each image has SBOM and build-provenance attestations, which you can check with `gh attestation verify oci://ghcr.io/jsilvanus/farcmd-mcp:1.0.0 --repo jsilvanus/farcmd-mcp`.

### 3. Without Docker

Requires Node.js 22.5 or newer (farcmd uses the built-in `node:sqlite`).

```sh
npm ci && npm run build && npm prune --omit=dev
NODE_ENV=production node --env-file=.env dist/server.js
node --env-file=.env dist/cli/admin.js user create --email you@example.org --name "You"
```

Run it under systemd (or similar) as a dedicated unprivileged user, and make `.env` readable only by that user.

### 4. Prepare target hosts

- An account for farcmd to run commands as. Use a dedicated, **unprivileged** account without unrestricted sudo.
- OpenSSH with `authorized_keys` options (`restrict` needs OpenSSH 7.2 or newer), plus `base64` and a POSIX shell.
- For level 3–5 commands (the integrity verifier): `python3` and `sudo`.

### Configuration

| Variable | Required | Meaning |
|---|---|---|
| `MCP_PUBLIC_URL` | yes | Public origin, e.g. `https://farcmd.example.org` (no path). Used as the OAuth issuer, the MCP resource and the allowed web Origin. |
| `FARCMD_ENCRYPTION_KEY` | yes | Base64, exactly 32 bytes. |
| `JWT_SECRET` | yes | Base64, at least 32 bytes. |
| `NODE_ENV` | `production` | Serves the web UI, sends HSTS/CSP and turns on the startup safety checks. Set by the image. |
| `STORAGE_PATH` | – | SQLite file (image: `/data/app.sqlite`). |
| `PORT`, `HOST` | – | Listen address (default `0.0.0.0:5999`). |
| `FARCMD_TRUST_PROXY` | behind a proxy | Proxies allowed to set `X-Forwarded-For`/`-Proto`: IPs/CIDRs, a hop count or `true`. |
| `FARCMD_AUDIT_RETENTION_DAYS` | – | Audit log retention (default 365, `0` = forever). |
| `FARCMD_EXECUTION_RETENTION_DAYS` | – | Execution history retention, stdout/stderr included (default 365, `0` = forever). |
| `FARCMD_MAX_OUTPUT_BYTES` | – | Captured stdout/stderr per execution (default 262144). |
| `FARCMD_SSH_MAX_CONCURRENT`, `FARCMD_SSH_MAX_PER_TARGET` | – | Concurrent SSH executions in total (8) and per target (2). |
| `FARCMD_MCP_EXECUTIONS_PER_MINUTE` | – | New MCP executions per user and client per minute (default 30, `0` = off). |
| `FARCMD_VERSION` | – | Image tag used by the compose files (default `1`). |

In production, farcmd refuses to start when `MCP_PUBLIC_URL` is missing, not `https://` or has a path, or when the development bootstrap `MCP_DEFAULT_USER_PASSWORD` is set.

### Backups and upgrades

```sh
docker compose exec farcmd farcmd-admin backup /data/backup-$(date +%F).sqlite
docker compose exec farcmd farcmd-admin audit verify
```

The backup is a consistent online copy with mode 0600. To upgrade, pull the new image and restart; migrations run automatically at startup. See [`docs/deployment.md`](docs/deployment.md#4-backup-and-restore) for restore steps.

---

## Connecting an MCP client

Add a remote MCP server (in Claude this is a "custom connector") with the URL:

```
https://farcmd.example.org/mcp
```

The client discovers OAuth by itself. An unauthenticated request gets `401` with a `WWW-Authenticate` challenge that points to `/.well-known/oauth-protected-resource/mcp`, and from there to the authorization server metadata.

- **Client registration uses [Client ID Metadata Documents](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/) (CIMD).** The client's `client_id` is an `https://` URL of a JSON document that lists its name and redirect URIs. farcmd does **not** support dynamic client registration or pre-registered client secrets, so the client must support CIMD.
- Authorization Code with PKCE (S256) only, as a public client (`token_endpoint_auth_methods_supported: none`), with scope `mcp`.
- On the consent page the user signs in, sees the client's name, chooses which levels (1–5) it may see, and can hide level 5 from it permanently.
- Access tokens are 1-hour JWTs bound to the issuer and the `/mcp` resource. Refresh tokens rotate on every use and expire 30 days after the original consent.

You can change the granted levels, or revoke a client, at any time on the **OAuth Sources** page.

---

## The MCP interface

farcmd uses the stateless Streamable HTTP transport: `POST /mcp` only (`GET` and `DELETE` return 405).

| Tool | Listed when | What it does |
|---|---|---|
| `farcmd_health` | always | Checks that the authenticated endpoint is reachable. |
| `list_commands` | always | Returns the commands this client may see: `id`, `name`, `description`, `level`, `enabled` and the confirmation it needs (`none`, `human` or `password`). **The shell command or script is never included.** |
| `command_level_1` … `command_level_5` | for each level granted to this client | Runs one command. Input: `commandId` (UUID) and, for levels 4–5, optionally `confirmationToken`. The tool must match the command's level. |

A run returns the exit code, signal, duration, stdout and stderr (up to `FARCMD_MAX_OUTPUT_BYTES`).

**Level 4 and 5 approvals.** Calling a level 4 or 5 tool never runs the command right away. It creates an approval request that is valid for 5 minutes:

- **Clients that support URL elicitation** show the approval link to the person directly. The call stays open (with progress notifications every 15 s when the client sent a progress token) until the person approves in the browser, and then returns the result. If the person declines the link in the client, the request is cancelled.
- **Other clients** receive `pending: true`, an `approvalUrl` and a `confirmationToken`. After the person has approved, the client calls the same tool again with the token and gets the result once.

Behind a proxy, allow MCP requests to stay open for about 6 minutes (the nginx example uses `proxy_read_timeout 360s`).

---

## The web UI

After signing in you land on **Commands**. The navigation bar has these pages:

| Page | What you do there |
|---|---|
| **Commands** | The **MCP access** bar at the top turns MCP off or on for your account. Create, edit, enable/disable and delete commands (name, description, target, level, *shell command* or *Bash script*). Install or remove each command's SSH capability, set the level-5 execution password, choose **Show output after approval** (levels 4–5), and **Run** a command directly from the browser. |
| **SSH** | **Master keys**: generate or upload (optionally passphrase-protected), unlock for 15 minutes, lock, rename, delete. **Targets**: host, port, account, master key and pinned **host fingerprint** (the connection test shows the fingerprint the server presents; unknown hosts are never trusted silently). **Integrity verifier** per target: install/repair automatically, download a manual root install script, verify now, remove. **Remote cleanup ledger**: capabilities that could not be removed yet, with a retry. |
| **OAuth Sources** | Every MCP client you have authorized: last use, visible levels, permanently hide level 5, revoke. |
| **History** | MCP and web executions with client, exit status, duration and output, plus per-command counts. A human-only view of a target's remote **shell history** (read with the master key). |
| **Audit** | Your audit events, with filters by event, outcome and text, and **Verify integrity** for the HMAC chain. |
| **Settings** | Name and email. Passwords are changed by the operator with `farcmd-admin user password`. |

**Approval page.** The `approvalUrl` of a level 4/5 request opens `/?page=confirm&token=…`. It shows the command, level, requesting client and expiry. Only the signed-in owner can approve (level 5 also asks for the execution password) or decline. An approval runs the command once.

**Run from the web.** Levels 1–3 run at once. Level 4 asks for confirmation and level 5 for the execution password. Web runs go through the same integrity verification, limits, history and audit as MCP runs (client `web`). The MCP access switch does not apply to them.

The web UI is a Vite single-page app (`web/`) served by Fastify from `dist/web` in production. It talks to the JSON API under `/api/`.

---

## Administration (`farcmd-admin`)

Operator actions are CLI-only, and there is no admin role in the web UI. The CLI works directly on the database, so run it with the same `STORAGE_PATH` and `FARCMD_ENCRYPTION_KEY` as the service (in Docker: `docker compose exec farcmd farcmd-admin …`). Every change is audited with actor `system`.

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
farcmd-admin mcp disable --all | --email alice@example.org
farcmd-admin mcp enable --all | --email alice@example.org
farcmd-admin backup <file>
farcmd-admin audit verify
```

- Passwords are never accepted as arguments, because they would end up in shell history and the process list. They are read from a hidden prompt, or from the first line of stdin with `--password-stdin`.
- **Registration is off by default.** `farcmd-admin registration enable` shows a sign-up link in the web UI.
- `user delete` removes the user and all of their farcmd data, but not their audit entries. It refuses while the user still has capabilities or verifiers installed on remote hosts (remove those in the web UI first) unless `--force` is given.

**MCP kill switches.** MCP works for a user only while all three switches allow it. The web UI, OAuth grants and tokens stay as they are, so turning MCP back on works immediately.

| Switch | Who | How |
|---|---|---|
| Own access | the user | **Turn off MCP access** on the Commands page |
| Per user | operator | `farcmd-admin mcp disable --email …` (the user cannot lift it) |
| All users | operator | `farcmd-admin mcp disable --all` |

While MCP is off, execution tools are not listed, `farcmd_health` and `list_commands` return an error that says why, and pending level 4/5 approvals cannot be approved.

---

## Security

farcmd is a remote-execution gateway: whoever controls it can run every installed command. It is built so that **an AI client can only run what a human set up for it**, and so that a stolen token, database copy or tampered target is contained or detected. This section describes what it protects, what it does not, and what you as the operator are responsible for.

### What farcmd protects

**MCP clients cannot run arbitrary commands**
- Tools take only a command ID. There are no arguments, no environment variables and no shell, so nothing can be injected into the command.
- The stored command content never appears in MCP responses.
- Each command runs with its own key. On the target, that key is limited by `restrict,command="<script>"` to one script, with no PTY and no forwarding. The master key is never used at run time.
- Level visibility is enforced per OAuth client on every call, as well as in `tools/list`. Calling a hidden level, or a tool that doesn't match the command's level, is refused and audited.
- Levels 4–5 need a human approval tied to the owner's browser session. Each approval runs the command once, expires after 5 minutes and cannot be replayed. Level 5 also needs a per-command Argon2id password.

**Tampered targets are detected**
- Target host keys are pinned, and unknown host keys are refused.
- Level 3–5 runs are blocked unless the root-owned verifier returns a valid HMAC over a fresh nonce for the expected scripts and `authorized_keys`. See [`docs/capability-integrity.md`](docs/capability-integrity.md) for the threat model and TOCTOU analysis.

**Stolen tokens and database copies are limited**
- Access tokens are HS256 JWTs bound to the issuer and resource and valid for 1 hour. Tokens of a disabled or deleted user are refused immediately.
- Refresh tokens rotate on every use and have reuse detection that revokes the whole token family. Authorization codes are single use.
- Refresh tokens, authorization codes, OAuth sign-in sessions and **web session tokens** are stored only as SHA-256 hashes.
- SSH private keys (master, per-command and verifier) and verifier HMAC secrets are encrypted with AES-256-GCM, with a per-record AAD. Master-key passphrases are never stored: they are held in memory for 15 minutes after an explicit unlock.
- Passwords use Argon2id.

**The web UI is protected against common browser attacks**
- CSRF: state-changing calls need a custom header, Fetch Metadata and Origin checks, and a `SameSite=Lax`, `HttpOnly`, `Secure` cookie.
- A strict CSP (`script-src 'self'`, `frame-ancestors 'none'`), HSTS, `X-Frame-Options: DENY`, `nosniff` and `Referrer-Policy: no-referrer`.

**Abuse is limited**
- Password sign-in, on both the web login and the OAuth consent form, allows 8 attempts per IP per 15 minutes, shared between the two. Registration and approvals have their own limits.
- MCP executions are limited per user and client, and SSH concurrency is limited in total and per target.
- CIMD metadata fetches accept only `https://` URLs. They refuse private, loopback, link-local, CGNAT, multicast, reserved and IPv4-mapped/NAT64 addresses, allow at most 3 redirects, time out after 5 s and read at most 64 KB.

**Everything is audited**
- An append-only, HMAC-chained audit log that someone with database access alone cannot rewrite unnoticed.
- Secrets are never logged, and command content is recorded only as its SHA-256.

**Production safety checks**
- farcmd refuses to start in production without `https` or with the development bootstrap password set.

### Known limitations and residual risks

- **The AI decides when to run levels 1–3.** A client that has been tricked by prompt injection (for example through a web page, an email or a command's own output) can run any level 1–3 command it can see, without asking. Put only commands you would let the model run unattended at those levels, and grant each client the fewest levels it needs.
- **Command output goes to the AI provider.** stdout and stderr are returned to the MCP client and so reach its model provider. Don't expose commands that print secrets. Output can also carry prompt-injection text back into the conversation.
- **Execution history is stored unencrypted.** The stdout/stderr of every run and the command content are kept in plaintext in SQLite. History is pruned after `FARCMD_EXECUTION_RETENTION_DAYS` (default 365). Lower that if your commands print sensitive data, and protect the database and backups as sensitive data. Results of approved level 4/5 runs that are waiting to be collected by the MCP client are deleted after a day.
- **Anyone who has both the database and `FARCMD_ENCRYPTION_KEY` has every SSH key**, and anyone who has `JWT_SECRET` can mint access tokens. Both are passed in the environment, so they can be seen with `docker inspect` and in `/proc/<pid>/environ` by root or the service user. Restrict access to the host and to the Docker socket.
- **Master keys are powerful.** A master key can write to `authorized_keys` on its targets. The recommended practice is to delete it when you have finished provisioning (see [Master keys: delete after provisioning](#master-keys-delete-after-provisioning)). Existing commands keep working without it. The remote shell-history view also uses the master key.
- **Levels 1–2 are not integrity-verified.** Someone who controls the target account could change those scripts. Put anything that matters at level 3 or higher.
- **Root on the target defeats the verifier.** Don't give the command account unrestricted sudo.
- **No multi-factor authentication.** Accounts use a password (at least 12 characters). Put farcmd behind an SSO or VPN front door if you need MFA.
- **Rate limits live in memory, in one process.** They reset on restart, and farcmd supports a single instance only. If `FARCMD_TRUST_PROXY` is wrong, all clients appear to come from the proxy's IP: they share one login budget, and audit IPs are wrong. Never set `FARCMD_TRUST_PROXY=true` when the app port is reachable other than through the proxy.
- **CIMD DNS rebinding.** The address check and the actual fetch resolve DNS separately, so a hostile DNS server could in theory switch to a private address in between. Restrict outbound traffic from the container if that matters in your network.
- **Approval tokens appear in URLs** (`/?page=confirm&token=…` and `/api/confirm/<token>`), so they can show up in proxy and application logs. Approving still needs the owner's signed-in session and, for level 5, the execution password.
- **Web sessions last 7 days** and have no idle timeout. Log out on shared machines. `farcmd-admin user logout` ends every session of a user.
- **Users trust the operator.** Users' data is kept separate in the application, but the operator (anyone with database and key access) can read every user's commands, output and keys. farcmd is meant for one person or a small trusted team.

### Security sweep for 1.0.0

A review before the 1.0.0 release led to these changes:

- The OAuth consent sign-in form (`POST /oauth/authorize`) had **no password rate limit**, so the web login limit could be bypassed. It now shares the per-IP budget with `/api/auth/login`, and refusals are audited.
- **Web session tokens were stored in plaintext** in SQLite, so a database copy gave usable sessions. They are now stored as SHA-256 hashes. Existing sessions are migrated in place and keep working, and expired sessions are purged.
- The **CIMD SSRF filter** missed IPv4-mapped IPv6 (`::ffff:127.0.0.1`), NAT64, CGNAT (`100.64/10`), `::`, multicast and other reserved ranges. It now uses a `BlockList` and checks embedded IPv4 addresses.
- **Execution history had no retention limit.** Runs and their output are now pruned after `FARCMD_EXECUTION_RETENTION_DAYS` (default 365, the same as the audit log), and each prune is audited as `execution_history.pruned`.
- Password sign-in for an **unknown email** now takes as long as a wrong password (a dummy Argon2 check), so response time no longer reveals which accounts exist. The rate-limit table is also swept so it cannot grow without bound.

### Reporting a vulnerability

Please report security issues privately through [GitHub security advisories](https://github.com/jsilvanus/farcmd-mcp/security/advisories/new) rather than in public issues.

---

## Development

Requires Node.js 22.5+.

```sh
cp .env.example .env     # set JWT_SECRET and FARCMD_ENCRYPTION_KEY (openssl rand -base64 32)
npm install
npm run dev              # Fastify API on :5999 + Vite dev server on :5173 (proxies /api)
npm run typecheck
npm test                 # unit and integration tests
npm run test:ui          # built web UI in headless Chromium (after npm run build)
sudo -E npm run test:e2e # integrity verification against a real OpenSSH server
npm run admin -- user create --email dev@example.org --name Dev
```

For development you can bootstrap an account with `MCP_DEFAULT_USER_EMAIL` and `MCP_DEFAULT_USER_PASSWORD`. This is refused in production.

Layout: `src/` server (`mcp/` MCP transport and tools, `oauth/` authorization server, `storage/` SQLite stores, `cli/` farcmd-admin), `web/` Vite UI, `test/` tests, `docs/` deployment and integrity design, `deploy/` proxy examples. `IMPLEMENTATION_PLAN.md` records the original nine-phase roadmap.

**Releasing:** set `version` in `package.json`, merge, then push a tag `vX.Y.Z` with the same version. The release workflow publishes the image and creates the GitHub release.

---

## Reference

### SSH master keys and command capabilities

- **Master keys** are provisioning credentials, generated or uploaded in the web UI. The private key is encrypted at rest; a passphrase is kept only in short-lived process memory after an explicit unlock.
- **Command installations** are runtime capabilities. farcmd generates a dedicated Ed25519 key per command, encrypts the private half at rest and installs the command content as `~/.ssh/farcmd/<mcp-host>-<command-id>.sh`. The `authorized_keys` entry forces that script with `restrict,command="…"`, and OpenSSH ignores whatever command the client sends.
- Changing a command's content or target requires the capability to be replaced. Without a master key, existing capabilities still run, but replacing or removing them is deferred.
- Deleting a command or capability always works. If farcmd cannot remove the remote entry and script right away, it records them in the **remote cleanup ledger** and retries once a master key is available.
- Deleting or replacing a master key does not affect installed capabilities. It only removes farcmd's ability to provision and revoke on that target.

#### Master keys: delete after provisioning

A master key is needed only to change things on a target. **The recommended practice is to delete it when you have finished and add it again for the next change.** Then a compromised farcmd can run only the commands already installed, and cannot write to `authorized_keys`.

| Without a master key | Still works | Needs a master key again |
|---|---|---|
| Running installed commands (MCP and web) | ✓ | |
| Integrity verification of level 3–5 commands | ✓ (uses the verifier key) | |
| Removing a command or capability | ✓ (recorded in the cleanup ledger, removed later) | |
| Installing the verifier with the manual root script | ✓ | |
| Installing, replacing or removing capabilities on the target | | ✓ |
| Automatic verifier install or repair, ledger cleanup, shell history, target Test | | ✓ |

The workflow:

1. Keep your own **passphrase-protected** master key safely outside farcmd, and put its public key in the target account's `authorized_keys`.
2. When you need to make a change, **upload** the key on the SSH page and unlock it.
3. If the target shows **No master key: provisioning off**, click **Edit** on the target and select the key.
4. Make your changes: install commands, clean up the ledger, and so on.
5. **Delete** the master key.

A key generated in farcmd never leaves it, so once deleted it cannot be uploaded again. If you use one, remove its line from the target's `authorized_keys` after deleting it. For the next change you'll need a new key whose public key you add to the target.

### Capability integrity verification (levels 3–5)

- Each target has a **verification authority**: a verification SSH key forced to a root-owned verifier through an argument-free sudoers rule, and a 32-byte HMAC secret that only root can read on the target (and that farcmd stores encrypted).
- farcmd sends a fresh 256-bit nonce. The verifier measures the capability scripts, every `authorized_keys` entry sshd uses, and itself, and returns `HMAC-SHA256(secret, measurement)`. A fake verifier cannot read the secret, and an old response cannot be replayed.
- Verification uses no master key.
- Install the verifier automatically, or with a manual root install script (which needs no master key).
- For the automatic install, **the account that runs sudo doesn't have to be the account the commands run as.** The verifier is always installed for the command account, but farcmd can connect as any account on the same host that can become root: an admin account with sudo (its password is entered once and never stored), an account with passwordless sudo, or root. The chosen master key must be authorized for that account. Keep the command account itself **without** sudo rights: unrestricted sudo on it would defeat the verifier.

Details: [`docs/capability-integrity.md`](docs/capability-integrity.md).

### Web and execution hardening

- **CSRF:** every state-changing `/api/` call needs `X-Farcmd-Request: 1`. Requests with `Sec-Fetch-Site: cross-site|same-site`, or an `Origin` other than `MCP_PUBLIC_URL`, are refused.
- **Rate limits:** password sign-in (web and OAuth) allows 8 attempts per IP per 15 minutes. Registration and web approvals have their own per-IP limits. MCP executions are limited per user and client (`FARCMD_MCP_EXECUTIONS_PER_MINUTE`).
- **SSH concurrency:** calls over `FARCMD_SSH_MAX_CONCURRENT` / `FARCMD_SSH_MAX_PER_TARGET` are refused immediately (not queued) and audited.
- **OAuth sign-in step:** the session between sign-in and consent is stored hashed in SQLite, is single use and expires after 5 minutes.

### OAuth tokens

- Access tokens: JWT (HS256), valid for 1 hour, audience `<MCP_PUBLIC_URL>/mcp`.
- Refresh tokens rotate on every use. A token family expires 30 days after the original authorization; refreshing does not extend it.
- Presenting a used refresh token revokes its whole family (`oauth.refresh_token_reuse`). Reusing an authorization code revokes what it produced (`oauth.code_reuse`).
- Refresh tokens are deleted when the grant is revoked, the password changes, or the account is disabled or logged out.

### Audit log

- **Recorded:** every state-changing web API call (one Fastify hook; a test fails if a mutating route is not mapped), OAuth consent, sign-in failures and token events, and MCP confirmations, refusals, integrity results and executions.
- **Never recorded:** request bodies as a whole and secret-looking fields. Command content is reduced to its SHA-256.
- **Tamper evidence:** `hash = HMAC-SHA256(K, previous hash ‖ entry)`, with `K` derived from `FARCMD_ENCRYPTION_KEY`. **Verify integrity** (or `farcmd-admin audit verify`) recomputes the chain. To detect truncation of the newest entries, compare against a head hash you noted earlier.
- **Retention:** `FARCMD_AUDIT_RETENTION_DAYS` (default 365). Pruning records `audit.pruned` so the remaining chain still verifies. Execution history has its own retention, `FARCMD_EXECUTION_RETENTION_DAYS` (default 365). Pruning it also lowers the per-command run counts on the History page. The `command.execute` audit entries are kept for the audit retention period.

---

## License

Copyright © jsilvanus. Licensed under the [European Union Public Licence v. 1.2](LICENSE) (EUPL-1.2).
