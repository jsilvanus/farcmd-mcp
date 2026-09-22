import Fastify from 'fastify';
import formbody from '@fastify/formbody';
import cookie from '@fastify/cookie';
import fastifyStatic from '@fastify/static';
import { join } from 'node:path';
import { hash } from '@node-rs/argon2';
import { randomBytes, randomUUID } from 'node:crypto';
import { FarcmdConnectorImpl } from './connector.js';
import { mountMcpHttp } from './mcp/http.js';
import { mountOAuthMetadata } from './oauth-metadata.js';
import { mountAuthorizationServer } from './oauth/authorization-server.js';
import { mountWebApi } from './web-api.js';
import { SqliteAuthStore, SqliteUserStore } from './storage/sqlite.js';

const port = Number(process.env.PORT ?? '5999');
const publicUrl = process.env.MCP_PUBLIC_URL ?? ('http://localhost:' + port);
const secretText = process.env.JWT_SECRET;
const defaultUserPassword = process.env.MCP_DEFAULT_USER_PASSWORD;

if (!Number.isInteger(port) || port <= 0) throw new Error('Invalid PORT');
if (!secretText) throw new Error('JWT_SECRET is required');
if (!defaultUserPassword) throw new Error('MCP_DEFAULT_USER_PASSWORD is required');

const secret = Buffer.from(secretText, 'base64');
if (secret.length < 32) throw new Error('JWT_SECRET must decode to at least 32 bytes');

const storagePath = process.env.STORAGE_PATH ?? './data/app.sqlite';
const store = new SqliteAuthStore(storagePath);
const users = new SqliteUserStore(store.getDatabase());
const defaultUserId = process.env.MCP_DEFAULT_USER_ID ?? randomUUID();
const defaultUserEmail = process.env.MCP_DEFAULT_USER_EMAIL ?? 'demo@example.com';

if (!users.getUser(defaultUserId)) {
  users.createUser({
    id: defaultUserId,
    name: 'Default User',
    email: defaultUserEmail,
    passwordHash: await hash(defaultUserPassword, { algorithm: 2 }),
    createdAt: Date.now(),
  });
}

const app = Fastify({ logger:true });
await app.register(formbody);
await app.register(cookie);
await mountWebApi(app, users, store);
if (process.env.NODE_ENV === 'production') {
  await app.register(fastifyStatic, { root: join(process.cwd(), 'dist/web'), prefix: '/' });
  app.get('/', async (_request, reply) => reply.sendFile('index.html'));
}

await mountOAuthMetadata(app, publicUrl);
await mountAuthorizationServer(app, publicUrl, publicUrl + '/mcp', secret, store, users);
await mountMcpHttp(app, {
  connector:new FarcmdConnectorImpl(),
  publicUrl,
  jwtSecret:secret,
  resource:publicUrl + '/mcp',
});

app.get('/health', async () => ({ok:true}));
app.get('/', async () => ({name:'farcmd-mcp',version:'0.1.0',mcp:'/mcp'}));

await app.listen({host:process.env.HOST ?? '0.0.0.0',port});
