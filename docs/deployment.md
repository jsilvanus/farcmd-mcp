# Deploying farcmd-mcp

farcmd is a single Node.js process with a SQLite database. It must run behind a TLS-terminating
reverse proxy: OAuth, MCP clients and the `Secure` session cookie all require HTTPS.

```
MCP client / browser ──HTTPS──► Traefik or nginx ──HTTP──► farcmd (port 5999) ──SSH──► targets
                                                              │
                                                          /data/app.sqlite
```

## 1. Secrets and configuration

Generate the two secrets once and keep them outside the repository:

```sh
openssl rand -base64 32   # FARCMD_ENCRYPTION_KEY — encrypts SSH keys at rest, keys the audit chain
openssl rand -base64 32   # JWT_SECRET — signs OAuth access tokens
```

| Variable | Required | Meaning |
|---|---|---|
| `MCP_PUBLIC_URL` | yes | Public origin, e.g. `https://farcmd.example.org` (no path). Must be `https://` in production; used as OAuth issuer, MCP resource and allowed web Origin. |
| `FARCMD_ENCRYPTION_KEY` | yes | Base64, exactly 32 bytes. **Losing it makes stored SSH credentials and the audit chain unusable.** |
| `JWT_SECRET` | yes | Base64, at least 32 bytes. Changing it invalidates issued access tokens (clients refresh). |
| `NODE_ENV` | `production` | Enables the static web UI, HSTS/CSP and the startup safety checks. Set by the Docker image. |
| `STORAGE_PATH` | – | SQLite file (image default `/data/app.sqlite`). |
| `PORT`, `HOST` | – | Listen address (default `0.0.0.0:5999`). |
| `FARCMD_TRUST_PROXY` | behind a proxy | Which proxies may set `X-Forwarded-For`/`-Proto` (see §4). Without it every request appears to come from the proxy, which breaks per-IP login limits and audit IPs. |
| `FARCMD_AUDIT_RETENTION_DAYS` | – | Audit log retention (default 365, `0` = forever). |
| `FARCMD_MAX_OUTPUT_BYTES` | – | Captured stdout/stderr per execution (default 262144). |
| `FARCMD_SSH_MAX_CONCURRENT`, `FARCMD_SSH_MAX_PER_TARGET` | – | Concurrent SSH executions in total (default 8) and per target (default 2); over the limit, calls are refused. |
| `FARCMD_MCP_EXECUTIONS_PER_MINUTE` | – | New MCP executions per user and OAuth client per minute (default 30, `0` = no limit). |

In production the server refuses to start with a missing or non-`https` `MCP_PUBLIC_URL`, with a
URL that has a path, or with the development bootstrap `MCP_DEFAULT_USER_PASSWORD` set.

## 2. Docker (recommended)

```sh
cp .env.example .env        # fill in MCP_PUBLIC_URL, secrets, FARCMD_TRUST_PROXY
docker compose up -d        # pulls ghcr.io/jsilvanus/farcmd-mcp:${FARCMD_VERSION:-1}
docker compose exec farcmd farcmd-admin user create --email you@example.org --name "You"
```

Release images are published to `ghcr.io/jsilvanus/farcmd-mcp` (`linux/amd64`, `linux/arm64`) with
tags `X.Y.Z`, `X.Y`, `X` and `latest` whenever a `vX.Y.Z` tag is pushed. Pin an exact version with
`FARCMD_VERSION=1.0.0` in `.env`. `docker compose up -d --build` builds from the checkout instead.

`docker-compose.yml` is for a reverse proxy on the host such as nginx; `docker-compose.traefik.yml`
is for an existing Traefik (see below).

The image runs as the unprivileged `node` user, keeps all state in the `/data` volume, has a
`HEALTHCHECK` on `/health`, and puts `farcmd-admin` on `PATH`. Registration is off by default:
accounts are created with `farcmd-admin` (see the README).

### Behind nginx

`docker-compose.yml` publishes the app on loopback only (`127.0.0.1:5999`; change the host port with
`FARCMD_HOST_PORT` in `.env`), so only a reverse proxy on the host can reach it. Use
`deploy/nginx/farcmd.conf` (TLS, HTTP→HTTPS redirect, forwarded headers, and
`proxy_buffering off` + long timeouts for MCP streams); its `proxy_pass` must match the host port.

With a published port, connections reach the container from the compose network's gateway, not
from 127.0.0.1, so trust that address:

```sh
docker network inspect <project>_default -f '{{(index .IPAM.Config 0).Gateway}}'   # e.g. 172.18.0.1
# .env
FARCMD_TRUST_PROXY=172.18.0.1
```

When running node directly on the host, use `127.0.0.1`.

### Behind Traefik

`docker-compose.traefik.yml` assumes an existing Traefik attached to an external Docker network named
`proxy`, an entrypoint `websecure` and a certificate resolver `letsencrypt`; adjust the labels
(`Host(...)`, resolver name) to your setup. The service publishes **no port**, so only Traefik can
reach it, and `FARCMD_TRUST_PROXY` can name the proxy network:

```sh
docker network inspect proxy -f '{{(index .IPAM.Config 0).Subnet}}'   # e.g. 172.20.0.0/16
# .env
FARCMD_TRUST_PROXY=172.20.0.0/16
```

Run it with `docker compose -f docker-compose.traefik.yml ...` (or set
`COMPOSE_FILE=docker-compose.traefik.yml` in `.env`). Traefik streams responses by default, so MCP's server-sent events need no extra configuration.

Never set `FARCMD_TRUST_PROXY=true` if the app port is reachable other than through the proxy:
anyone could then forge their client IP.

## 3. Without Docker

Node.js 22.5 or newer (the app uses the built-in `node:sqlite`).

```sh
npm ci && npm run build && npm prune --omit=dev
NODE_ENV=production node --env-file=.env dist/server.js
node --env-file=.env dist/cli/admin.js user create --email you@example.org --name "You"
```

Run it under systemd (or similar) as a dedicated unprivileged user whose home is not the data
directory, and keep `.env` readable only by that user.

## 4. Backup and restore

```sh
docker compose exec farcmd farcmd-admin backup /data/backup-$(date +%F).sqlite
docker compose cp farcmd:/data/backup-$(date +%F).sqlite ./backups/
```

`farcmd-admin backup` makes a transactionally consistent copy (`VACUUM INTO`) while the server keeps
running, writes it with mode 0600, and records the backup in the audit log. The copy contains
encrypted SSH keys, verification secrets and the audit log. **Store `FARCMD_ENCRYPTION_KEY`
separately and securely**: without it a backup cannot decrypt credentials or verify its audit
chain; with it, anyone holding the backup can.

Restore: stop farcmd, replace `/data/app.sqlite` with the backup (remove stale `app.sqlite-wal` /
`-shm` files), start farcmd with the same `FARCMD_ENCRYPTION_KEY`, then run
`farcmd-admin audit verify`.

## 5. Upgrades

Pull the new image (`docker compose pull`, or change `FARCMD_VERSION`) or rebuild, and restart. Database migrations run automatically at startup and
only add tables/columns, but take a backup first. After upgrading, `farcmd-admin audit verify`
confirms the audit chain is intact.

## 6. Targets

Level 3–5 commands need the per-target integrity verifier (SSH page in the web UI). Targets need
`python3` and `sudo` for it; see [`capability-integrity.md`](capability-integrity.md).
