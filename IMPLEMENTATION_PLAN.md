# farcmd-mcp implementation plan

## Goal

Build **farcmd-mcp** as a secure, OAuth-protected MCP server for executing a user's predefined SSH commands.

The project has two interfaces:

- **MCP / AI interface** — discovers predefined commands and executes them according to OAuth-granted command levels.
- **Vite web interface** — account management, SSH targets, private keys, command definitions, OAuth authorization, permissions, and human-only shell history.

The AI must never receive the stored shell command itself. It receives the command's name, description, level, and execution output.

The project should reuse the OAuth/MCP architecture already developed in `codestash/mcp/api-connector-style`, particularly Streamable HTTP, OAuth Authorization Code + PKCE, CIMD-first client identification, protected-resource metadata, authorization-server metadata, Argon2id passwords, and durable token storage.

## Command model

Every command belongs to exactly one of five levels:

| Level | Purpose |
|---|---|
| 1 | Safe/read-only operations |
| 2 | Low-impact operations |
| 3 | Normal mutating operations |
| 4 | High-impact operations |
| 5 | Dangerous/destructive operations |

The exact semantic definitions should be documented in the UI and project documentation. The level is explicitly assigned by the human owner; it is never inferred by the AI.

A command contains:

- ID
- human-visible name
- description
- exact SSH command
- SSH target
- level
- enabled/disabled state
- timestamps

The exact SSH command is server-side data only.

## Security invariants

These are architectural invariants, not optional UI behavior:

1. An MCP client can never retrieve the raw shell command.
2. Execution is only possible through a command's assigned level-specific MCP tool.
3. The server verifies the command's real level instead of trusting the tool name.
4. OAuth authorization grants explicitly contain the enabled command levels.
5. A revoked/expired authorization cannot execute commands.
6. Users can permanently disallow level 5 for an OAuth source.
7. SSH private keys are encrypted at rest and never returned to MCP clients.
8. SSH host keys/fingerprints are verified; unknown hosts are not silently trusted.
9. MCP execution output is returned to the AI and recorded in execution history.
10. Remote shell history is a separate human-only feature and is not part of normal MCP discovery.
11. V1 commands have no arbitrary AI-supplied shell arguments. Dynamic arguments, if ever added, must use typed/validated parameters rather than shell-string interpolation.
12. Every execution is auditable.

---

# Nine-phase implementation plan

## Phase 1 — Foundation and OAuth/MCP server

Establish the application skeleton and copy/adapt the proven OAuth/MCP baseline from codestash.

Implement:

- Node.js + TypeScript ESM project
- Fastify HTTP server
- MCP Streamable HTTP endpoint
- OAuth Protected Resource Metadata
- OAuth Authorization Server Metadata
- Authorization Code + PKCE S256
- CIMD-first OAuth client identification
- JWT access tokens bound to issuer/resource
- refresh tokens
- Argon2id user passwords
- durable local persistence
- health endpoint
- environment configuration
- build/test scripts

The implementation should preserve the separation:

`OAuth → MCP transport → command authorization → SSH execution`

**Deliverable:** an empty but fully authenticated farcmd MCP that a real MCP client can connect to.

---

## Phase 2 — Accounts, Vite web application, and sessions

Create the web control plane.

Implement:

- Vite frontend
- backend API for the web UI
- account creation
- login/logout
- authenticated browser session
- account settings
- basic CSRF/session protections
- production-oriented password handling
- login rate limiting
- user/account lifecycle

Initial UI navigation:

- Dashboard
- SSH Targets
- SSH Keys
- Commands
- OAuth Sources
- Execution History
- Shell History

The browser UI is the only place where sensitive configuration is exposed to the human owner.

**Deliverable:** a user can create an account and manage the application through the Vite UI.

---

## Phase 3 — SSH targets and encrypted credentials

Implement SSH configuration.

Data model:

`ssh_target`

- id
- user_id
- name
- hostname
- port
- username
- ssh_key_id
- host_key/fingerprint
- enabled
- timestamps

`ssh_key`

- id
- user_id
- name
- encrypted_private_key
- optional encrypted passphrase
- fingerprint
- timestamps

Implement:

- add/edit/delete SSH targets
- add/edit/delete SSH keys
- encrypted-at-rest credential storage
- SSH host-key verification
- connection test from the web UI
- clear errors and connection timeouts

Implemented in V1 with AES-256-GCM credential encryption, an environment-provided 32-byte master key, session-only SSH passphrases with a 15-minute in-memory unlock TTL, SSH target CRUD, host-fingerprint-aware connection tests, and a dedicated web unlock flow. Do not expose private keys, decrypted credentials, or host configuration through MCP.

**Deliverable:** a user can securely configure and verify an SSH target. Phase 3 is complete; command execution remains intentionally deferred to Phases 4–5.

---

## Phase 4 — Command registry and five-level model

Implement the command registry.

Data model:

`command`

- id
- user_id
- target_id
- name
- description
- shell_command
- level (1–5)
- enabled
- created_at
- updated_at

Implement the web UI for:

- creating commands
- editing commands
- deleting commands
- enabling/disabling commands
- selecting the SSH target
- selecting the command level
- viewing the exact command
- testing a command manually

The exact command is visible to the owner in the web UI, but never returned by an MCP discovery tool.

V1 deliberately uses **fixed commands without AI-provided arguments**.

**Deliverable:** a user can build a private registry of safe, predefined SSH operations. Phase 4 is implemented: commands are persisted with levels 1–5, bound to user-owned SSH targets, editable/enabled/disabled/deletable through the web UI, and the exact shell command is exposed only to the authenticated human UI. MCP exposure and execution remain deferred to Phase 5.

---

## Phase 5 — MCP command discovery and level-specific execution tools

Expose the command registry through MCP.

Implement:

`list_commands`

Returns only metadata such as:

- command ID
- name
- description
- level
- enabled state

It never returns `shell_command`.

Implement separate execution tools:

- `command_level_1`
- `command_level_2`
- `command_level_3`
- `command_level_4`
- `command_level_5`

All five tools must use one internal execution path:

`executeCommand(commandId, expectedLevel, oauthContext)`

The internal path verifies:

1. authenticated user
2. OAuth client/grant
3. command ownership
4. command exists
5. command is enabled
6. command's actual level equals `expectedLevel`
7. OAuth grant permits that level
8. target is enabled
9. SSH credentials are available
10. SSH host identity is valid

Only then is the stored command sent to SSH.

**Deliverable:** an MCP client can discover and execute predefined commands without ever learning their shell implementations. Phase 5 is implemented: MCP exposes metadata-only command discovery plus five level-specific execution tools, with one server-side execution path enforcing ownership, enabled state, exact level matching, target/key checks, pinned host identity, and SSH-key unlock requirements. OAuth level grants remain wired for Phase 6.

---

## Phase 6 — OAuth source permissions and five-level consent

Connect OAuth authorization to command-level permissions.

Model an OAuth authorization/grant roughly as:

`oauth_grant`

- user_id
- client_id
- client metadata
- allowed_levels
- created_at
- expires_at/revoked_at
- last_used_at

During authorization, the consent UI shows something like:

- Level 1 — allowed
- Level 2 — allowed
- Level 3 — allowed
- Level 4 — not allowed
- Level 5 — not allowed

The user chooses the permitted levels for that OAuth source.

Support:

- per-source level selection
- later permission changes
- revocation
- optional permanent prohibition of level 5
- token/grant invalidation when permissions are revoked

The MCP authorization layer must derive effective permissions from the stored grant, not from client claims.

**Deliverable:** each AI connection has its own explicit command-power boundary. Phase 6 is implemented: OAuth grants persist per user/client, authorization consent selects levels 1–5, level 5 can be permanently prohibited, grants can be edited or revoked in the web UI, and MCP execution checks the live grant so revocation/permission changes take effect immediately.

---

## Phase 7 — Execution history and human shell history

Implement the two intentionally separate histories.

### MCP execution history

Store:

- execution ID
- user ID
- OAuth client/source
- command ID
- target ID
- level
- start/end time
- duration
- exit code
- stdout
- stderr
- status
- error information where appropriate

The execution result is returned directly to the MCP caller.

The AI therefore sees what **its own command produced**, without seeing the underlying shell command.

The web UI provides searchable/filterable execution history.

### Human shell history

Implement separately as a human administration feature.

The shell-history feature may retrieve the relevant remote shell history from an SSH target, but it must:

- require explicit human access
- never be included in normal `list_commands`
- never be returned automatically to MCP
- support redaction
- support retention limits
- clearly distinguish remote shell history from MCP executions

Treat shell history as potentially sensitive because humans may have entered passwords, tokens, API keys, URLs with credentials, or unrelated private commands.

**Deliverable:** AI execution context and human server history remain cleanly separated.

---

## Phase 8 — Security hardening, audit, and operational controls

Harden the complete system before production use.

Implement:

- command execution timeouts
- stdout/stderr size limits
- SSH connection limits
- no PTY unless explicitly required
- controlled environment handling
- host-key verification
- credential encryption/key management
- OAuth token revocation
- refresh-token rotation/revocation
- CSRF protection
- login brute-force/rate limiting
- audit logging
- security event logging
- command enable/disable audit trail
- OAuth permission-change audit trail
- credential-change audit trail
- safe error messages
- sensitive-output redaction where appropriate
- configurable execution-history retention
- configurable shell-history retention

Particular attention should be paid to output: command output may itself contain secrets. The system should preserve useful output for MCP while providing configurable storage/redaction policy for historical records.

**Deliverable:** a deployment-ready security model with an explicit threat boundary.

---

## Phase 9 — Integration tests, documentation, deployment, and production release

Build the complete test matrix.

### OAuth tests

- authorization code + PKCE
- invalid redirect URI
- invalid client
- expired code
- refresh token
- revoked grant
- changed permissions
- expired access token

### Command authorization tests

Test every combination of:

`command level × OAuth allowed levels`

including:

- level 1 → allowed
- level 1 → denied
- level 3 → allowed
- level 3 → denied
- level 5 → allowed only when explicitly permitted
- wrong level-specific tool
- disabled command
- command belonging to another user
- deleted command
- changed command level
- revoked OAuth source

### SSH tests

- valid host key
- unknown host
- wrong host fingerprint
- unreachable target
- authentication failure
- command timeout
- non-zero exit code
- large output
- stderr output

### Information-boundary tests

Explicitly verify:

- `list_commands` never contains `shell_command`
- MCP responses never contain private keys
- MCP responses never contain decrypted SSH credentials
- shell history is not exposed through normal MCP tools
- unauthorized command levels cannot be executed
- execution output is returned correctly

### Documentation

Document:

- architecture
- five command levels
- OAuth authorization model
- MCP tool API
- security model
- credential storage
- shell history model
- execution history
- deployment
- backup/recovery
- threat model
- adding future command argument support

### Deployment

Provide:

- production environment configuration
- database/storage setup
- reverse-proxy guidance
- HTTPS requirements
- health checks
- logging
- backup strategy
- migration strategy

**Deliverable:** a tested, documented farcmd-mcp release suitable for real MCP clients and controlled SSH automation.

---

# Target architecture

```
                         ┌──────────────────────┐
                         │      Vite Web UI     │
                         │                      │
                         │ account / SSH / cmds │
                         │ OAuth / history      │
                         └──────────┬───────────┘
                                    │
                              HTTPS / API
                                    │
              ┌─────────────────────▼─────────────────────┐
              │              farcmd-mcp                   │
              │                                           │
              │  OAuth  ──► grants / level permissions   │
              │     │                                     │
              │     ▼                                     │
              │  MCP ──► command registry                │
              │              │                            │
              │              ▼                            │
              │       authorization                       │
              │              │                            │
              │              ▼                            │
              │       SSH command executor                │
              │              │                            │
              └──────────────┼────────────────────────────┘
                             │
                             ▼
                       ┌─────────────┐
                       │  SSH target │
                       └─────────────┘

AI receives:
  command metadata + execution output

AI never receives:
  raw shell command
  SSH private key
  SSH credentials
  human shell history
```

## Recommended implementation order

Do not build the Vite UI first in isolation. Build the security and domain model underneath it.

The practical sequence is:

**1. OAuth/MCP foundation → 2. Web accounts → 3. SSH → 4. commands → 5. MCP tools → 6. OAuth levels → 7. histories → 8. hardening → 9. full integration/release.**

The codestash API-connector scaffold is the starting point for Phase 1, but farcmd-mcp should own its command/SSH/authorization domain rather than turning the SSH executor into a generic connector.

## Important v1 boundary

A command is a **predefined capability**, not an arbitrary shell gateway.

That means:

```
AI
 │
 ├── "restart application"
 │
 ▼
command_id = 42
level = 3
 │
 ▼
server looks up exact command
 │
 ▼
"sudo systemctl restart my-app"
 │
 ▼
SSH
```

The AI never gets a general-purpose:

```
run_shell("...")
```

tool.

This is the core property that makes the five-level authorization model meaningful.
