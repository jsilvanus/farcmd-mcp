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
