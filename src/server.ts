import Fastify from 'fastify';
import formbody from '@fastify/formbody';
import cookie from '@fastify/cookie';
import fastifyStatic from '@fastify/static';
import { join } from 'node:path';
import { hash } from '@node-rs/argon2';
import { randomUUID } from 'node:crypto';
import { FarcmdConnectorImpl } from './connector.js';
import { mountMcpHttp } from './mcp/http.js';
import { mountOAuthMetadata } from './oauth-metadata.js';
import { mountAuthorizationServer } from './oauth/authorization-server.js';
import { mountWebApi } from './web-api.js';
import { SqliteAuthStore, SqliteUserStore } from './storage/sqlite.js';

const port=Number(process.env.PORT??'5999');
const publicUrl=process.env.MCP_PUBLIC_URL??('http://localhost:'+port);
const secretText=process.env.JWT_SECRET;
const defaultUserPassword=process.env.MCP_DEFAULT_USER_PASSWORD;
if(!process.env.FARCMD_ENCRYPTION_KEY)throw new Error('FARCMD_ENCRYPTION_KEY is required');
if(process.env.FARCMD_ENCRYPTION_KEY){const key=Buffer.from(process.env.FARCMD_ENCRYPTION_KEY,'base64');if(key.length!==32)throw new Error('FARCMD_ENCRYPTION_KEY must decode to exactly 32 bytes');}
if(!Number.isInteger(port)||port<=0)throw new Error('Invalid PORT');
if(!secretText)throw new Error('JWT_SECRET is required');
const secret=Buffer.from(secretText,'base64');if(secret.length<32)throw new Error('JWT_SECRET must decode to at least 32 bytes');
const storagePath=process.env.STORAGE_PATH??'./data/app.sqlite';
const store=new SqliteAuthStore(storagePath);
const users=new SqliteUserStore(store.getDatabase());
const defaultUserEmail=process.env.MCP_DEFAULT_USER_EMAIL??'demo@example.com';
const existingDefault=users.getUserByEmail(defaultUserEmail);
if(!existingDefault&&defaultUserPassword){users.createUser({id:process.env.MCP_DEFAULT_USER_ID??randomUUID(),name:'Default User',email:defaultUserEmail,passwordHash:await hash(defaultUserPassword,{algorithm:2}),createdAt:Date.now()});}
const app=Fastify({logger:true,bodyLimit:256*1024});
app.addHook('onSend',async(_request,reply,payload)=>{reply.header('X-Content-Type-Options','nosniff').header('X-Frame-Options','DENY').header('Referrer-Policy','no-referrer');if(process.env.NODE_ENV==='production')reply.header('Strict-Transport-Security','max-age=31536000; includeSubDomains');if(process.env.NODE_ENV==='production')reply.header('Content-Security-Policy',\"default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'\");return payload;});
await app.register(formbody);await app.register(cookie);await mountWebApi(app,users,store);
if(process.env.NODE_ENV==='production')await app.register(fastifyStatic,{root:join(process.cwd(),'dist/web'),prefix:'/'});
await mountOAuthMetadata(app,publicUrl);
await mountAuthorizationServer(app,publicUrl,publicUrl+'/mcp',secret,store,users);
await mountMcpHttp(app,{connector:new FarcmdConnectorImpl(store.getDatabase(),publicUrl),publicUrl,jwtSecret:secret,resource:publicUrl+'/mcp'});
app.get('/health',async()=>({ok:true}));
app.get('/',async(_request,reply)=>{if(process.env.NODE_ENV==='production')return reply.sendFile('index.html');return {name:'farcmd-mcp',version:'0.2.0',mcp:'/mcp',web:'/'};});
await app.listen({host:process.env.HOST??'0.0.0.0',port});
