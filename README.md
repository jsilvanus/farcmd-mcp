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

Mutating browser API requests validate the `Origin` header when present. Login and registration have a basic per-IP rate limit. This is intentionally a baseline; Phase 8 will add full CSRF strategy, stronger abuse controls, security event logging, and operational hardening.

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
- Install or repair the verifier on the SSH page: automatically (the master key needs root on the target via root or sudo), or with a one-time **manual root install script**, which works without any master key. Target requirements: `python3` and `sudo`.
- The target account must not have unrestricted sudo/root: root on the target is outside what any on-host verifier can defend against.

See [`docs/capability-integrity.md`](docs/capability-integrity.md) for the threat model, protocol, trust boundary, TOCTOU analysis and lifecycle. `sudo -E npm run test:e2e` runs the end-to-end tests against a real OpenSSH server.
