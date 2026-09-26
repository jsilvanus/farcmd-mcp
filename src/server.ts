import Fastify, { type FastifyHttpOptions } from 'fastify';
import type { Server } from 'node:http';
import formbody from '@fastify/formbody';
import cookie from '@fastify/cookie';
import fastifyStatic from '@fastify/static';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { FarcmdConnectorImpl } from './connector.js';
import { mountMcpHttp } from './mcp/http.js';
import { mountOAuthMetadata } from './oauth-metadata.js';
import { mountAuthorizationServer } from './oauth/authorization-server.js';
import { mountWebApi } from './web-api.js';
import { SqliteAuthStore, SqliteUserStore } from './storage/sqlite.js';
import { isActiveUser } from './storage/interface.js';
import { auditRetentionMs } from './audit.js';
import { SqliteExecutionHistoryStore, executionRetentionMs } from './execution-history.js';
import { parseTrustProxy, productionConfigProblems } from './config.js';
import { executionLimits } from './limits.js';
import { contentSecurityPolicy } from './csp.js';
import { masterKey } from './crypto-at-rest.js';
import { hashPassword } from './login-rate-limit.js';
import { VERSION } from './version.js';

const problems=productionConfigProblems(process.env);
if(problems.length)throw new Error('Refusing to start with an unsafe production configuration:\n- '+problems.join('\n- '));
executionLimits(); // validates FARCMD_SSH_MAX_* and FARCMD_MCP_EXECUTIONS_PER_MINUTE at startup
const port=Number(process.env.PORT??'5999');
const publicUrl=process.env.MCP_PUBLIC_URL??('http://localhost:'+port);
const secretText=process.env.JWT_SECRET;
const defaultUserPassword=process.env.MCP_DEFAULT_USER_PASSWORD;
masterKey(); // validates FARCMD_ENCRYPTION_KEY at startup
if(!Number.isInteger(port)||port<=0)throw new Error('Invalid PORT');
if(!secretText)throw new Error('JWT_SECRET is required');
const secret=Buffer.from(secretText,'base64');if(secret.length<32)throw new Error('JWT_SECRET must decode to at least 32 bytes');
const storagePath=process.env.STORAGE_PATH??'./data/app.sqlite';
const store=new SqliteAuthStore(storagePath);
const users=new SqliteUserStore(store.getDatabase());
const defaultUserEmail=process.env.MCP_DEFAULT_USER_EMAIL??'demo@example.com';
const existingDefault=users.getUserByEmail(defaultUserEmail);
if(!existingDefault&&defaultUserPassword){users.createUser({id:process.env.MCP_DEFAULT_USER_ID??randomUUID(),name:'Default User',email:defaultUserEmail,passwordHash:await hashPassword(defaultUserPassword),createdAt:Date.now()});}
// Audit log retention (FARCMD_AUDIT_RETENTION_DAYS, default 365, 0 = keep forever): prune at start and daily.
const retentionMs=auditRetentionMs();
if(retentionMs>0){store.cleanupSecurityEvents(retentionMs);setInterval(()=>store.cleanupSecurityEvents(retentionMs),86_400_000).unref();}
// Execution history retention (FARCMD_EXECUTION_RETENTION_DAYS, default 365, 0 = keep forever): runs and their output, pruned at start and daily.
const executionRetention=executionRetentionMs();
if(executionRetention>0){const history=new SqliteExecutionHistoryStore(store.getDatabase());history.prune(executionRetention);setInterval(()=>history.prune(executionRetention),86_400_000).unref();}
const options:FastifyHttpOptions<Server>={logger:true,bodyLimit:256*1024,trustProxy:parseTrustProxy(process.env.FARCMD_TRUST_PROXY)};
const app=Fastify(options);
const production=process.env.NODE_ENV==='production';
const defaultCsp=contentSecurityPolicy();
app.addHook('onSend',async(_request,reply,payload)=>{reply.header('X-Content-Type-Options','nosniff').header('X-Frame-Options','DENY').header('Referrer-Policy','no-referrer');if(production){reply.header('Strict-Transport-Security','max-age=31536000; includeSubDomains');if(!reply.hasHeader('Content-Security-Policy'))reply.header('Content-Security-Policy',defaultCsp);}return payload;});
await app.register(formbody);await app.register(cookie);await mountWebApi(app,users,store,publicUrl);
if(production)await app.register(fastifyStatic,{root:fileURLToPath(new URL('./web/',import.meta.url)),prefix:'/'});
await mountOAuthMetadata(app,publicUrl);
await mountAuthorizationServer(app,publicUrl,publicUrl+'/mcp',secret,store,users);
await mountMcpHttp(app,{connector:new FarcmdConnectorImpl(store.getDatabase(),publicUrl),publicUrl,jwtSecret:secret,resource:publicUrl+'/mcp',isUserActive:id=>isActiveUser(users.getUser(id))});
app.get('/health',{logLevel:'silent'},async()=>({ok:true}));
app.get('/',async(_request,reply)=>{if(production)return reply.sendFile('index.html');return {name:'farcmd-mcp',version:VERSION,mcp:'/mcp',web:'/'};});
await app.listen({host:process.env.HOST??'0.0.0.0',port});
