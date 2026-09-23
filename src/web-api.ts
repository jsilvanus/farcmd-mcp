import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { hash, verify } from '@node-rs/argon2';
import { randomToken } from './oauth/pkce.js';
import type { UserStore, WebSessionStore } from './storage/interface.js';
import { WebSessionService } from './web-session.js';
import { SqliteSshStore } from './storage/ssh.js';
import { decryptSecret, encryptSecret } from './crypto-at-rest.js';
import { executeSshCommand, inspectPrivateKey, testSshConnection } from './ssh.js';
import { getSshPassphrase, lockSshKey, unlockSshKey } from './ssh-key-cache.js';
import { utils } from 'ssh2';
import { SqliteCommandInstallationStore, SqliteRemoteCapabilityLedgerStore } from './storage/command-installations.js';
import { buildCommandRestrictedAuthorizedKey, buildFarcmdScript, farcmdScriptPath, installCommandCapability, removeCommandCapability, sha256Hex } from './ssh.js';
import { SqliteCommandStore, type CommandLevel, hashCommandContent } from './command-registry.js';
import { SqliteExecutionHistoryStore } from './execution-history.js';
import { FarcmdConnectorImpl } from './connector.js';
import { SqliteExecutionStore } from './execution.js';
import { isCommandLevel } from './command-levels.js';

const attempts=new Map<string,{count:number;reset:number}>();
const MAX_ATTEMPTS=8;
const WINDOW=15*60_000;
const confirmationAttempts=new Map<string,{count:number;reset:number}>();
function confirmationRateLimit(key:string):boolean{return rateLimitMap(confirmationAttempts,key,5,15*60_000);}
function rateLimitMap(map:Map<string,{count:number;reset:number}>,key:string,max:number,window:number):boolean{const now=Date.now();const current=map.get(key);if(!current||current.reset<=now){map.set(key,{count:1,reset:now+window});return true;}current.count++;return current.count<=max;}

function rateLimit(key:string): boolean {
  const now=Date.now(); const current=attempts.get(key);
  if (!current || current.reset<=now) { attempts.set(key,{count:1,reset:now+WINDOW}); return true; }
  current.count++;
  return current.count<=MAX_ATTEMPTS;
}
function cleanEmail(email:string): string { return email.trim().toLowerCase(); }
function publicUser(user:{id:string;name:string;email?:string;createdAt:number}) {
  return {id:user.id,name:user.name,email:user.email,createdAt:user.createdAt};
}
function cookieOptions() {
  return {httpOnly:true,secure:process.env.NODE_ENV==='production',sameSite:'lax' as const,path:'/',maxAge:7*24*60*60};
}
function checkMutationOrigin(request:FastifyRequest): boolean {
  const origin=request.headers.origin;
  if (!origin) return true;
  const expected=process.env.MCP_PUBLIC_URL ?? `http://localhost:${process.env.PORT ?? '5999'}`;
  try { return new URL(origin).origin===new URL(expected).origin; } catch { return false; }
}
function sessionFrom(request:FastifyRequest, sessions:WebSessionService) {
  const token=request.cookies.farcmd_session;
  return token ? sessions.get(token) : undefined;
}
async function requireUser(request:FastifyRequest, reply:FastifyReply, users:UserStore, sessions:WebSessionService) {
  const session=sessionFrom(request,sessions);
  if (!session) { reply.code(401).send({error:'Authentication required'}); return undefined; }
  const user=users.getUser(session.userId);
  if (!user) { sessions.delete(session.token); reply.clearCookie('farcmd_session',{path:'/'}); reply.code(401).send({error:'Authentication required'}); return undefined; }
  return user;
}

export async function mountWebApi(app:FastifyInstance, users:UserStore, sessionStore:WebSessionStore): Promise<void> {
  app.addHook('preHandler', async (request,reply) => {
    if (['POST','PATCH','PUT','DELETE'].includes(request.method) && request.url.startsWith('/api/') && !checkMutationOrigin(request)) {
      return reply.code(403).send({error:'Invalid request origin'});
    }
  });
  const sessions=new WebSessionService(sessionStore);
  const sshDb=(sessionStore as any).getDatabase?.();
  if (!sshDb) throw new Error('Web session store must expose the application database');
  const ssh=new SqliteSshStore(sshDb);
  const commands=new SqliteCommandStore(sshDb);
  const installations=new SqliteCommandInstallationStore(sshDb);
  const capabilityLedger=new SqliteRemoteCapabilityLedgerStore(sshDb);
  const executionHistory=new SqliteExecutionHistoryStore(sshDb);
  const connector=new FarcmdConnectorImpl(sshDb,process.env.MCP_PUBLIC_URL ?? `http://localhost:${process.env.PORT ?? '5999'}`);
  app.get('/api/ssh/keys',async (request,reply)=>{
    const user=await requireUser(request,reply,users,sessions); if(!user)return;
    return {keys:ssh.listKeys(user.id).map(k=>{const privateKey=decryptSecret(k.encryptedPrivateKey,'ssh-key:'+user.id+':'+k.id);const inspected=inspectPrivateKey(privateKey);const passphraseRequired=inspected.encrypted;return {id:k.id,name:k.name,fingerprint:k.fingerprint,publicKey:k.publicKey,createdAt:k.createdAt,updatedAt:k.updatedAt,passphraseRequired,locked:passphraseRequired&&getSshPassphrase(user.id,k.id)===undefined};})};
  });
  app.post('/api/ssh/keys/generate',async(request,reply)=>{const user=await requireUser(request,reply,users,sessions);if(!user)return;const b=request.body as Record<string,unknown>;const name=typeof b.name==='string'?b.name.trim():'';const passphrase=typeof b.passphrase==='string'?b.passphrase:'';if(name.length<1||name.length>120||passphrase.length>1024)return reply.code(400).send({error:'Invalid master key data'});const generated=utils.generateKeyPairSync('ed25519',{comment:'farcmd-master:'+name,...(passphrase?{passphrase,cipher:'aes256-cbc'}:{})});const privateKey=String(generated.private);const publicKey=String(generated.public).trim();const inspected=inspectPrivateKey(privateKey,passphrase||undefined);if(!inspected.valid||!inspected.fingerprint)return reply.code(500).send({error:'Generated master key could not be validated.'});const id=crypto.randomUUID();const now=Date.now();ssh.createKey({id,userId:user.id,name,encryptedPrivateKey:encryptSecret(privateKey,'ssh-key:'+user.id+':'+id),fingerprint:inspected.fingerprint,publicKey,createdAt:now,updatedAt:now});return reply.code(201).send({key:{id,name,fingerprint:inspected.fingerprint,generated:true,passphraseRequired:!!passphrase,publicKey}});});
  app.post('/api/ssh/keys',async (request,reply)=>{
    const user=await requireUser(request,reply,users,sessions); if(!user)return;
    const b=request.body as Record<string,unknown>; const name=typeof b.name==='string'?b.name.trim():''; const privateKey=typeof b.privateKey==='string'?b.privateKey:'';
    if(name.length<1||name.length>120||privateKey.length<64||privateKey.length>100000) return reply.code(400).send({error:'Invalid SSH key data'});
    const inspected=inspectPrivateKey(privateKey);
    if(!inspected.valid) return reply.code(400).send({error:'The uploaded value is not a supported SSH private key'});
    const id=crypto.randomUUID(); const now=Date.now(); const encryptedPrivateKey=encryptSecret(privateKey,'ssh-key:'+user.id+':'+id);
    ssh.createKey({id,userId:user.id,name,encryptedPrivateKey,...(inspected.fingerprint?{fingerprint:inspected.fingerprint}:{}),createdAt:now,updatedAt:now});
    return reply.code(201).send({key:{id,name,fingerprint:inspected.fingerprint,encrypted:true,passphraseRequired:inspected.encrypted}});
  });
  app.patch('/api/ssh/keys/:id',async (request,reply)=>{
    const user=await requireUser(request,reply,users,sessions); if(!user)return; const id=(request.params as {id:string}).id; const current=ssh.getKey(user.id,id); if(!current)return reply.code(404).send({error:'SSH key not found'}); const b=request.body as Record<string,unknown>;
    const name=typeof b.name==='string'?b.name.trim():current.name; const privateKey=typeof b.privateKey==='string'?b.privateKey:undefined;
    if(!name||name.length>120)return reply.code(400).send({error:'Invalid key name'});
    let encryptedPrivateKey=current.encryptedPrivateKey; let fingerprint=current.fingerprint;
    if(privateKey!==undefined){ const inspected=inspectPrivateKey(privateKey); if(!inspected.valid)return reply.code(400).send({error:'The uploaded value is not a supported SSH private key'}); encryptedPrivateKey=encryptSecret(privateKey,'ssh-key:'+user.id+':'+id); fingerprint=inspected.fingerprint; lockSshKey(user.id,id); }
    ssh.updateKey({...current,name,encryptedPrivateKey,...(fingerprint ? {fingerprint} : {}),updatedAt:Date.now()}); return {key:ssh.getKey(user.id,id)};
  });
  app.post('/api/ssh/keys/:id/unlock',async (request,reply)=>{
    const user=await requireUser(request,reply,users,sessions); if(!user)return;
    const key=ssh.getKey(user.id,(request.params as {id:string}).id); if(!key)return reply.code(404).send({error:'SSH key not found'});
    const b=request.body as Record<string,unknown>; const passphrase=typeof b.passphrase==='string'?b.passphrase:'';
    try { const privateKey=decryptSecret(key.encryptedPrivateKey,'ssh-key:'+user.id+':'+key.id); unlockSshKey(user.id,key.id,privateKey,passphrase); return {ok:true,expiresInSeconds:900}; }
    catch { return reply.code(400).send({error:'Invalid SSH key or passphrase'}); }
  });
  app.post('/api/ssh/keys/:id/lock',async (request,reply)=>{ const user=await requireUser(request,reply,users,sessions); if(!user)return; lockSshKey(user.id,(request.params as {id:string}).id); return {ok:true}; });
  app.delete('/api/ssh/keys/:id',async (request,reply)=>{ const user=await requireUser(request,reply,users,sessions); if(!user)return; const id=(request.params as {id:string}).id; if(!ssh.getKey(user.id,id))return reply.code(404).send({error:'SSH key not found'}); lockSshKey(user.id,id); ssh.deleteKey(user.id,id); return {ok:true}; });
  app.get('/api/ssh/targets',async (request,reply)=>{ const user=await requireUser(request,reply,users,sessions); if(!user)return; return {targets:ssh.listTargets(user.id)}; });
  app.post('/api/ssh/targets',async (request,reply)=>{
    const user=await requireUser(request,reply,users,sessions); if(!user)return; const b=request.body as Record<string,unknown>;
    const name=typeof b.name==='string'?b.name.trim():''; const hostname=typeof b.hostname==='string'?b.hostname.trim():''; const username=typeof b.username==='string'?b.username.trim():''; const port=typeof b.port==='number'?b.port:Number(b.port); const sshKeyId=typeof b.sshKeyId==='string'?b.sshKeyId:'';
    if(!name||name.length>120||!hostname||hostname.length>253||!username||username.length>255||!Number.isInteger(port)||port<1||port>65535||!ssh.getKey(user.id,sshKeyId)) return reply.code(400).send({error:'Invalid SSH target data'});
    const id=crypto.randomUUID(),now=Date.now(); ssh.createTarget({id,userId:user.id,name,hostname,port,username,sshKeyId,enabled:true,createdAt:now,updatedAt:now}); return reply.code(201).send({target:ssh.getTarget(user.id,id)});
  });
  app.patch('/api/ssh/targets/:id',async (request,reply)=>{
    const user=await requireUser(request,reply,users,sessions); if(!user)return; const id=(request.params as {id:string}).id; const current=ssh.getTarget(user.id,id); if(!current)return reply.code(404).send({error:'SSH target not found'}); const b=request.body as Record<string,unknown>;
    const base={...current,name:typeof b.name==='string'?b.name.trim():current.name,hostname:typeof b.hostname==='string'?b.hostname.trim():current.hostname,username:typeof b.username==='string'?b.username.trim():current.username,port:b.port===undefined?current.port:Number(b.port),sshKeyId:typeof b.sshKeyId==='string'?b.sshKeyId:current.sshKeyId,enabled:typeof b.enabled==='boolean'?b.enabled:current.enabled,updatedAt:Date.now()}; const next = b.hostFingerprint===null ? base : {...base,...(typeof b.hostFingerprint==='string'?{hostFingerprint:b.hostFingerprint.trim()}:current.hostFingerprint?{hostFingerprint:current.hostFingerprint}:{})};
    if(!next.name||!next.hostname||!next.username||!Number.isInteger(next.port)||next.port<1||next.port>65535||!ssh.getKey(user.id,next.sshKeyId)) return reply.code(400).send({error:'Invalid SSH target data'}); ssh.updateTarget(next); return {target:ssh.getTarget(user.id,id)};
  });
  app.delete('/api/ssh/targets/:id',async (request,reply)=>{ const user=await requireUser(request,reply,users,sessions); if(!user)return; const id=(request.params as {id:string}).id; if(!ssh.getTarget(user.id,id))return reply.code(404).send({error:'SSH target not found'}); if(installations.list(user.id).some(k=>k.targetId===id))return reply.code(409).send({error:'This target has installed command capabilities. Remove those capabilities before deleting the target.'}); ssh.deleteTarget(user.id,id); return {ok:true}; });
  app.post('/api/ssh/targets/:id/test',async (request,reply)=>{
    const user=await requireUser(request,reply,users,sessions); if(!user)return; const id=(request.params as {id:string}).id; const target=ssh.getTarget(user.id,id); if(!target)return reply.code(404).send({error:'SSH target not found'}); const key=ssh.getKey(user.id,target.sshKeyId); if(!key)return reply.code(400).send({error:'SSH key not found'});
    const passphrase=getSshPassphrase(user.id,key.id); let privateKey:string; try { privateKey=decryptSecret(key.encryptedPrivateKey,'ssh-key:'+user.id+':'+key.id); } catch { return reply.code(500).send({error:'Unable to decrypt SSH key'}); }
    const result=await testSshConnection({hostname:target.hostname,port:target.port,username:target.username,...(target.hostFingerprint?{hostFingerprint:target.hostFingerprint}: {})},{privateKey,...(passphrase!==undefined?{passphrase}:{})}); return result;
  });
  app.get('/api/commands',async(request,reply)=>{const user=await requireUser(request,reply,users,sessions);if(!user)return;return {commands:commands.list(user.id).map(c=>({...c,hasExecutionPassword:c.level===5?commands.hasExecutionPassword(user.id,c.id):undefined,commandKey:installations.get(user.id,c.id)?.installedAt?{id:installations.get(user.id,c.id)!.id,fingerprint:installations.get(user.id,c.id)!.fingerprint,installedAt:installations.get(user.id,c.id)!.installedAt,remoteScriptPath:installations.get(user.id,c.id)!.remoteScriptPath}:undefined}))};});
  app.get('/api/ssh/targets/:id/capability-ledger',async(request,reply)=>{const user=await requireUser(request,reply,users,sessions);if(!user)return;const id=(request.params as {id:string}).id;if(!ssh.getTarget(user.id,id))return reply.code(404).send({error:'SSH target not found'});return {entries:capabilityLedger.list(user.id).filter(e=>e.targetId===id)};});
  app.post('/api/ssh/targets/:id/capability-ledger/cleanup',async(request,reply)=>{const user=await requireUser(request,reply,users,sessions);if(!user)return;const id=(request.params as {id:string}).id;const target=ssh.getTarget(user.id,id);if(!target)return reply.code(404).send({error:'SSH target not found'});if(!target.enabled||!target.hostFingerprint)return reply.code(400).send({error:'SSH target must be enabled and have a pinned host fingerprint.'});const master=ssh.getKey(user.id,target.sshKeyId);if(!master)return reply.code(400).send({error:'SSH master key is missing.'});const privateKey=decryptSecret(master.encryptedPrivateKey,'ssh-key:'+user.id+':'+master.id);const passphrase=getSshPassphrase(user.id,master.id);const inspected=inspectPrivateKey(privateKey,passphrase);if(!inspected.valid)return reply.code(409).send({error:inspected.encrypted&&!passphrase?'SSH master key is locked.':'Stored SSH master key is invalid or the unlock passphrase is incorrect.'});const pending=capabilityLedger.pendingForTarget(user.id,id);let removed=0;for(const entry of pending){try{await removeCommandCapability({hostname:target.hostname,port:target.port,username:target.username,hostFingerprint:target.hostFingerprint},{privateKey,...(passphrase!==undefined?{passphrase}:{} )},entry.authorizedKeyLine,entry.remoteScriptPath);capabilityLedger.markAttempt(user.id,entry.id);removed++;}catch(error){capabilityLedger.markAttempt(user.id,entry.id,error instanceof Error?error.message:'Remote removal failed.');}}return {removed,remaining:capabilityLedger.pendingForTarget(user.id,id).length};});
  app.post('/api/commands',async(request,reply)=>{const user=await requireUser(request,reply,users,sessions);if(!user)return;const b=request.body as Record<string,unknown>;const name=typeof b.name==='string'?b.name.trim():'';const description=typeof b.description==='string'?b.description.trim():'';const type=b.type==='bash_script'?'bash_script':'shell';const content=typeof b.content==='string'?b.content:(typeof b.shellCommand==='string'?b.shellCommand:'');const normalized=type==='shell'?content.trim():content;const targetId=typeof b.targetId==='string'?b.targetId:'';const level=typeof b.level==='number'?b.level:Number(b.level);if(!name||name.length>120||description.length>2000||!normalized||normalized.length>100000||!isCommandLevel(level)||!ssh.getTarget(user.id,targetId)||(type==='shell'&&/\\r|\\n/.test(normalized)))return reply.code(400).send({error:'Invalid command data'});const id=crypto.randomUUID(),now=Date.now();commands.create({id,userId:user.id,targetId,name,description,type,content:normalized,level,enabled:true,createdAt:now,updatedAt:now});return reply.code(201).send({command:commands.get(user.id,id)});});
  app.patch('/api/commands/:id',async(request,reply)=>{const user=await requireUser(request,reply,users,sessions);if(!user)return;const id=(request.params as {id:string}).id;const cur=commands.get(user.id,id);if(!cur)return reply.code(404).send({error:'Command not found'});const b=request.body as Record<string,unknown>;const nextType=b.type===undefined?cur.type:(b.type==='bash_script'?'bash_script':b.type);const nextContent=typeof b.content==='string'?b.content:(typeof b.shellCommand==='string'?b.shellCommand:cur.content);const next={...cur,name:typeof b.name==='string'?b.name.trim():cur.name,description:typeof b.description==='string'?b.description.trim():cur.description,type:nextType as 'shell'|'bash_script',content:nextType==='shell'?nextContent.trim():nextContent,targetId:typeof b.targetId==='string'?b.targetId:cur.targetId,level:b.level===undefined?cur.level:(typeof b.level==='number'?b.level:Number(b.level)),enabled:typeof b.enabled==='boolean'?b.enabled:cur.enabled,updatedAt:Date.now()};if(!next.name||next.name.length>120||next.description.length>2000||!next.content||next.content.length>100000||!isCommandLevel(next.level)||!ssh.getTarget(user.id,next.targetId)||(next.type==='shell'&&/\\r|\\n/.test(next.content)))return reply.code(400).send({error:'Invalid command data'});const installation=installations.get(user.id,id);const capabilityChanged=!!installation&&(next.content!==cur.content||next.type!==cur.type||next.targetId!==cur.targetId);if(capabilityChanged)return reply.code(409).send({error:'This command has an installed SSH capability. Remove or replace that capability before changing its executable content or target.'});if(cur.level===5&&(next.level!==5||next.content!==cur.content||next.targetId!==cur.targetId))commands.clearExecutionPassword(user.id,id);commands.update(next);return {command:commands.get(user.id,id)};});
  app.delete('/api/commands/:id',async(request,reply)=>{const user=await requireUser(request,reply,users,sessions);if(!user)return;const id=(request.params as {id:string}).id;const command=commands.get(user.id,id);if(!command)return reply.code(404).send({error:'Command not found'});const installation=installations.get(user.id,id);if(installation){const target=ssh.getTarget(user.id,installation.targetId);const master=target?ssh.getKey(user.id,installation.masterKeyId):undefined;let removed=false;if(target&&target.enabled&&target.hostFingerprint&&master){try{const privateKey=decryptSecret(master.encryptedPrivateKey,'ssh-key:'+user.id+':'+master.id);const passphrase=getSshPassphrase(user.id,master.id);const inspected=inspectPrivateKey(privateKey,passphrase);if(inspected.valid){await removeCommandCapability({hostname:target.hostname,port:target.port,username:target.username,hostFingerprint:target.hostFingerprint},{privateKey,...(passphrase!==undefined?{passphrase}:{} )},installation.authorizedKeyLine,installation.remoteScriptPath);removed=true;}}catch{}}if(!removed)capabilityLedger.createPending({id:crypto.randomUUID(),userId:user.id,targetId:installation.targetId,commandId:id,publicKey:installation.publicKey,fingerprint:installation.fingerprint,authorizedKeyLine:installation.authorizedKeyLine,remoteScriptPath:installation.remoteScriptPath,createdAt:Date.now()});installations.delete(user.id,installation.id);return {ok:true,remoteCleanupPending:!!installation&&!removed};}commands.delete(user.id,id);return {ok:true,remoteCleanupPending:false};});
  app.get('/api/commands/:id/key',async(request,reply)=>{const user=await requireUser(request,reply,users,sessions);if(!user)return;const id=(request.params as {id:string}).id;const command=commands.get(user.id,id);if(!command)return reply.code(404).send({error:'Command not found'});const key=installations.get(user.id,id);return {key:key?{id:key.id,fingerprint:key.fingerprint,masterKeyId:key.masterKeyId,installedAt:key.installedAt,remoteScriptPath:key.remoteScriptPath}:undefined};});
  app.post('/api/commands/:id/key',async(request,reply)=>{const user=await requireUser(request,reply,users,sessions);if(!user)return;const id=(request.params as {id:string}).id;const command=commands.get(user.id,id);if(!command)return reply.code(404).send({error:'Command not found'});const existing=installations.get(user.id,id);if(existing)return reply.code(409).send({error:'This command already has an installed SSH capability.'});const target=ssh.getTarget(user.id,command.targetId);if(!target||!target.enabled)return reply.code(400).send({error:'SSH target is unavailable.'});if(!target.hostFingerprint)return reply.code(400).send({error:'Pin the SSH host fingerprint before creating a command capability.'});const master=ssh.getKey(user.id,target.sshKeyId);if(!master)return reply.code(400).send({error:'SSH master key is missing.'});const masterPrivateKey=decryptSecret(master.encryptedPrivateKey,'ssh-key:'+user.id+':'+master.id);const masterPassphrase=getSshPassphrase(user.id,master.id);const inspected=inspectPrivateKey(masterPrivateKey,masterPassphrase);if(!inspected.valid){if(inspected.encrypted&&!masterPassphrase)return reply.code(409).send({error:'SSH master key is locked. Unlock it in the farcmd web UI first.'});return reply.code(400).send({error:'Stored SSH master key is invalid or the unlock passphrase is incorrect.'});}const generated=utils.generateKeyPairSync('ed25519',{comment:'farcmd:'+command.id});const publicKey=String(generated.public).trim();const privateKey=String(generated.private);const fingerprint=inspectPrivateKey(privateKey).fingerprint;if(!fingerprint)return reply.code(500).send({error:'Could not fingerprint generated command key.'});const publicUrl=process.env.MCP_PUBLIC_URL ?? ('http://localhost:'+(process.env.PORT ?? '5999'));const scriptPath=farcmdScriptPath(publicUrl,command.id);const script=buildFarcmdScript(publicUrl,command.id,command.type,command.content);const authorizedKey=buildCommandRestrictedAuthorizedKey(publicKey,scriptPath);try{await installCommandCapability({hostname:target.hostname,port:target.port,username:target.username,hostFingerprint:target.hostFingerprint},{privateKey:masterPrivateKey,...(masterPassphrase!==undefined?{passphrase:masterPassphrase}:{} )},authorizedKey,scriptPath,script);}catch(error){return reply.code(502).send({error:error instanceof Error?error.message:'Failed to install command capability on target'});}const keyId=crypto.randomUUID();const now=Date.now();installations.create({id:keyId,userId:user.id,commandId:id,targetId:target.id,masterKeyId:master.id,encryptedPrivateKey:encryptSecret(privateKey,'command-installation:'+user.id+':'+keyId),publicKey,fingerprint,remoteScriptPath:scriptPath,authorizedKeyLine:authorizedKey,scriptContent:script,commandSha256:hashCommandContent(command.type,command.content),scriptSha256:sha256Hex(script),authorizedKeySha256:sha256Hex(authorizedKey),installedAt:now,createdAt:now,updatedAt:now});return reply.code(201).send({key:{id:keyId,fingerprint,installedAt:now,remoteScriptPath:scriptPath}});});
  app.delete('/api/commands/:id/key',async(request,reply)=>{const user=await requireUser(request,reply,users,sessions);if(!user)return;const id=(request.params as {id:string}).id;const command=commands.get(user.id,id);if(!command)return reply.code(404).send({error:'Command not found'});const installation=installations.get(user.id,id);if(!installation)return reply.code(404).send({error:'Installed SSH capability not found'});const target=ssh.getTarget(user.id,installation.targetId);const master=target?ssh.getKey(user.id,installation.masterKeyId):undefined;let removed=false;let errorMessage:string|undefined;if(target&&target.enabled&&target.hostFingerprint&&master){try{const masterPrivateKey=decryptSecret(master.encryptedPrivateKey,'ssh-key:'+user.id+':'+master.id);const masterPassphrase=getSshPassphrase(user.id,master.id);const inspected=inspectPrivateKey(masterPrivateKey,masterPassphrase);if(inspected.valid){await removeCommandCapability({hostname:target.hostname,port:target.port,username:target.username,hostFingerprint:target.hostFingerprint},{privateKey:masterPrivateKey,...(masterPassphrase!==undefined?{passphrase:masterPassphrase}:{} )},installation.authorizedKeyLine,installation.remoteScriptPath);removed=true;}else errorMessage=inspected.encrypted&&!masterPassphrase?'Master key is locked.':'Master key is invalid.';}catch(error){errorMessage=error instanceof Error?error.message:'Remote removal failed.';}}else errorMessage='No usable master key is currently available.';if(!removed)capabilityLedger.createPending({id:crypto.randomUUID(),userId:user.id,targetId:installation.targetId,commandId:id,publicKey:installation.publicKey,fingerprint:installation.fingerprint,authorizedKeyLine:installation.authorizedKeyLine,remoteScriptPath:installation.remoteScriptPath,createdAt:Date.now()});installations.delete(user.id,installation.id);return {ok:true,removed,remoteCleanupPending:!removed,error:errorMessage};});
  app.post('/api/commands/:id/execution-password',async(request,reply)=>{const user=await requireUser(request,reply,users,sessions);if(!user)return;const id=(request.params as {id:string}).id;const command=commands.get(user.id,id);if(!command)return reply.code(404).send({error:'Command not found'});if(command.level!==5)return reply.code(400).send({error:'Only level 5 commands have execution passwords'});const b=request.body as Record<string,unknown>;const password=typeof b.password==='string'?b.password:'';if(password.length<12||password.length>1024)return reply.code(400).send({error:'Execution password must be 12-1024 characters'});commands.setExecutionPassword(user.id,id,await hash(password,{algorithm:2}));return {ok:true};});
  app.get('/api/history/command-counts',async(request,reply)=>{const user=await requireUser(request,reply,users,sessions);if(!user)return;return {counts:executionHistory.successfulCounts(user.id)};});
  app.get('/api/history/executions',async(request,reply)=>{
    const user=await requireUser(request,reply,users,sessions);if(!user)return;
    const q=request.query as Record<string,string|undefined>;
    const level=q.level?Number(q.level):undefined;
    const rows=executionHistory.list(user.id,{clientId:q.clientId,commandId:q.commandId,level:isCommandLevel(level)?level:undefined,status:q.status as any,search:q.search,limit:q.limit?Number(q.limit):50,offset:q.offset?Number(q.offset):0});
    return {executions:rows,total:executionHistory.count(user.id)};
  });
  app.get('/api/history/shell',async(request,reply)=>{
    const user=await requireUser(request,reply,users,sessions);if(!user)return;
    const q=request.query as Record<string,string|undefined>; const targetId=q.targetId;
    if(!targetId)return reply.code(400).send({error:'targetId is required'});
    const target=ssh.getTarget(user.id,targetId);if(!target)return reply.code(404).send({error:'SSH target not found'});
    const key=ssh.getKey(user.id,target.sshKeyId);if(!key)return reply.code(404).send({error:'SSH key not found'});
    const passphrase=getSshPassphrase(user.id,key.id);let privateKey:string;
    try{privateKey=decryptSecret(key.encryptedPrivateKey,'ssh-key:'+user.id+':'+key.id);}catch{return reply.code(500).send({error:'Unable to decrypt SSH key'});}
    const command="printf '\\n--- .bash_history ---\\n'; tail -n 500 ~/.bash_history 2>/dev/null; printf '\\n--- .zsh_history ---\\n'; tail -n 500 ~/.zsh_history 2>/dev/null";
    if(!target.enabled)return reply.code(400).send({error:'SSH target is disabled'});
    if(!target.hostFingerprint)return reply.code(400).send({error:'SSH target has no pinned host fingerprint'});
    const result=await executeSshCommand({hostname:target.hostname,port:target.port,username:target.username,...(target.hostFingerprint?{hostFingerprint:target.hostFingerprint}: {})},{privateKey,...(passphrase!==undefined?{passphrase}:{})},command,15000);
    const redacted=result.stdout.replace(/(?:password|passwd|token|secret|api[_-]?key)\s*[=:]\s*[^\s]+/gi,'$1=[REDACTED]').replace(/(https?:\/\/[^\s:@]+:)[^\s@]+@/gi,'$1[REDACTED]@');
    return {target:{id:target.id,name:target.name},stdout:redacted,stderr:result.stderr,exitCode:result.exitCode,durationMs:result.durationMs,warning:'Remote shell history is human-only and may contain sensitive or unrelated commands. It is not MCP execution history.'};
  });
  app.get('/api/confirm/:token',async(request,reply)=>{const user=await requireUser(request,reply,users,sessions);if(!user)return;const token=(request.params as {token:string}).token;const pending=(new SqliteExecutionStore(sshDb)).get(token);if(!pending||pending.userId!==user.id)return reply.code(404).send({error:'Confirmation request not found or expired'});const command=commands.get(user.id,pending.commandId);if(!command)return reply.code(404).send({error:'Command no longer exists'});const grant=(sessionStore as any).getOAuthGrant(user.id,pending.clientId);return {command:{id:command.id,name:command.name,description:command.description,level:command.level,confirmation:pending.level===4?'human':'password'},clientId:pending.clientId,clientName:grant?.clientName??pending.clientId,expiresAt:pending.expiresAt};});
  app.post('/api/confirm/:token',async(request,reply)=>{const token=(request.params as {token:string}).token;if(!confirmationRateLimit('confirm:'+request.ip+':'+token))return reply.code(429).send({error:'Too many confirmation attempts. Try again later.'});const user=await requireUser(request,reply,users,sessions);if(!user)return;const b=request.body as Record<string,unknown>;try{return await connector.approvePending(user.id,(request.params as {token:string}).token,typeof b.password==='string'?b.password:undefined);}catch(error){return reply.code(400).send({error:error instanceof Error?error.message:String(error)});}});
  app.get('/api/oauth/grants',async(request,reply)=>{const user=await requireUser(request,reply,users,sessions);if(!user)return;return {grants:(sessionStore as any).listOAuthGrants(user.id).map((g:any)=>({...g,revoked:!!g.revokedAt}))};});
  app.patch('/api/oauth/grants/:clientId',async(request,reply)=>{const user=await requireUser(request,reply,users,sessions);if(!user)return;const clientId=decodeURIComponent((request.params as {clientId:string}).clientId);const b=request.body as Record<string,unknown>;const raw=Array.isArray(b.visibleLevels)?b.visibleLevels:[];const allowed=raw.map(v=>typeof v==='number'?v:Number(v)).filter(isCommandLevel) as CommandLevel[];const permanent5=Boolean(b.level5PermanentlyHidden);try{(sessionStore as any).updateOAuthGrant(user.id,clientId,allowed,permanent5);return {grant:(sessionStore as any).getOAuthGrant(user.id,clientId)};}catch(error){return reply.code(400).send({error:error instanceof Error?error.message:String(error)});}});
  app.post('/api/oauth/grants/:clientId/revoke',async(request,reply)=>{const user=await requireUser(request,reply,users,sessions);if(!user)return;const clientId=decodeURIComponent((request.params as {clientId:string}).clientId);if(!(sessionStore as any).getOAuthGrant(user.id,clientId))return reply.code(404).send({error:'OAuth source not found'});(sessionStore as any).revokeOAuthGrant(user.id,clientId);return {ok:true};});
  app.get('/api/auth/session',async (request,reply)=>{
    const user=await requireUser(request,reply,users,sessions); if(!user)return;
    return {user:publicUser(user)};
  });
  app.post('/api/auth/login',async (request,reply)=>{
    const ip=request.ip; if(!rateLimit(ip)) return reply.code(429).send({error:'Too many login attempts. Try again later.'});
    const b=request.body as Record<string,unknown>;
    const email=typeof b.email==='string'?cleanEmail(b.email):'';
    const password=typeof b.password==='string'?b.password:'';
    const user=users.getUserByEmail(email);
    if(!user?.passwordHash || !(await verify(user.passwordHash,password))) return reply.code(401).send({error:'Invalid email or password'});
    const token=sessions.create(user.id);
    reply.setCookie('farcmd_session',token,cookieOptions());
    return {user:publicUser(user)};
  });
  app.post('/api/auth/logout',async (request,reply)=>{
    const token=request.cookies.farcmd_session; if(token)sessions.delete(token);
    reply.clearCookie('farcmd_session',{path:'/'});
    return {ok:true};
  });
  app.post('/api/auth/register',async (request,reply)=>{
    const ip=request.ip; if(!rateLimit('register:'+ip)) return reply.code(429).send({error:'Too many attempts. Try again later.'});
    const b=request.body as Record<string,unknown>;
    const name=typeof b.name==='string'?b.name.trim():'';
    const email=typeof b.email==='string'?cleanEmail(b.email):'';
    const password=typeof b.password==='string'?b.password:'';
    if(name.length<1||name.length>120) return reply.code(400).send({error:'Invalid name'});
    if(!/^\\S+@\\S+\\.\\S+$/.test(email)||email.length>320) return reply.code(400).send({error:'Invalid email'});
    if(password.length<12||password.length>1024) return reply.code(400).send({error:'Password must be 12-1024 characters'});
    if(users.getUserByEmail(email)) return reply.code(409).send({error:'An account with that email already exists'});
    const user={id:crypto.randomUUID(),name,email,passwordHash:await hash(password,{algorithm:2}),createdAt:Date.now()};
    users.createUser(user);
    const token=sessions.create(user.id); reply.setCookie('farcmd_session',token,cookieOptions());
    return reply.code(201).send({user:publicUser(user)});
  });
  app.patch('/api/account',async (request,reply)=>{
    const user=await requireUser(request,reply,users,sessions); if(!user)return;
    const b=request.body as Record<string,unknown>;
    const name=typeof b.name==='string'?b.name.trim():user.name;
    const email=typeof b.email==='string'?cleanEmail(b.email):(user.email??'');
    if(name.length<1||name.length>120||!/^\\S+@\\S+\\.\\S+$/.test(email)) return reply.code(400).send({error:'Invalid account data'});
    const other=users.getUserByEmail(email);
    if(other&&other.id!==user.id) return reply.code(409).send({error:'That email is already in use'});
    users.updateUser(user.id,name,email);
    return {user:publicUser(users.getUser(user.id)!)};
  });
}
