import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { hash } from '@node-rs/argon2';
import { loginRateLimit, rateLimit, verifyPassword } from './login-rate-limit.js';
import { randomToken } from './oauth/pkce.js';
import { isActiveUser, type UserStore, type WebSessionStore } from './storage/interface.js';
import { SqliteSettingsStore } from './storage/settings.js';
import { McpAccessPolicy } from './mcp-access.js';
import { WebSessionService } from './web-session.js';
import { SqliteSshStore } from './storage/ssh.js';
import { decryptSecret, encryptSecret } from './crypto-at-rest.js';
import { executeSshCommand, inspectPrivateKey, testSshConnection } from './ssh.js';
import { getSshPassphrase, lockSshKey, unlockSshKey } from './ssh-key-cache.js';
import ssh2 from 'ssh2';
const { utils }=ssh2;
import { SqliteCommandInstallationStore, SqliteRemoteCapabilityLedgerStore } from './storage/command-installations.js';
import { buildCommandRestrictedAuthorizedKey, buildFarcmdScript, executeAsMaster, farcmdScriptPath, installCommandCapability, removeCommandCapability, sha256Hex, type SshKeyMaterial } from './ssh.js';
import { SqliteVerificationAuthorityStore, verificationKeyAad, verificationSecretAad, type VerificationAuthorityRecord } from './storage/verification-authorities.js';
import { generateVerificationSecret, isSafeTargetUsername, rootInstallInvocation, renderSudoers, renderVerifierInstallScript, renderVerifierUninstallScript, verificationForcedCommand, verificationKeyComment, verifierPrivilegeFor } from './verification.js';
import { CapabilityVerificationService, type TargetVerificationResult } from './capability-verification.js';
import type { SshTargetRecord } from './storage/ssh.js';
import { SqliteCommandStore, type CommandLevel, type CommandRecord, hashCommandContent } from './command-registry.js';
import { SqliteExecutionHistoryStore } from './execution-history.js';
import { FarcmdConnectorImpl, type CommandExecution } from './connector.js';
import { LimitExceeded } from './limits.js';
import { SqliteExecutionStore } from './execution.js';
import { isCommandLevel } from './command-levels.js';
import { AuditLog, type AuditOutcome } from './audit.js';
import { createHash } from 'node:crypto';
import { hashToken } from './oauth/tokens.js';

const confirmationAttempts=new Map<string,{count:number;reset:number}>();
function confirmationRateLimit(key:string):boolean{return rateLimit(key,5,15*60_000,confirmationAttempts);}
function cleanEmail(email:string): string { return email.trim().toLowerCase(); }
function publicUser(user:{id:string;name:string;email?:string;createdAt:number}) {
  return {id:user.id,name:user.name,email:user.email,createdAt:user.createdAt};
}
function cookieOptions() {
  return {httpOnly:true,secure:process.env.NODE_ENV==='production',sameSite:'lax' as const,path:'/',maxAge:7*24*60*60};
}
/** Header the web UI sends on every API call. A cross-site page cannot set it without a CORS preflight, which farcmd never grants. */
export const CSRF_HEADER='x-farcmd-request';
/**
 * CSRF defence for state-changing API calls, in depth: the custom header (required), Fetch Metadata
 * (a browser-reported cross-site or sibling-subdomain request is refused) and Origin (when sent it
 * must be the public origin). The session cookie is also SameSite=Lax.
 */
function checkMutationOrigin(request:FastifyRequest): string|undefined {
  if (request.headers[CSRF_HEADER]!=='1') return 'Missing '+CSRF_HEADER+' header';
  const site=request.headers['sec-fetch-site'];
  if (site!==undefined && site!=='same-origin' && site!=='none') return 'Cross-site request refused';
  const origin=request.headers.origin;
  if (!origin) return undefined;
  const expected=process.env.MCP_PUBLIC_URL ?? `http://localhost:${process.env.PORT ?? '5999'}`;
  try { return new URL(origin).origin===new URL(expected).origin ? undefined : 'Invalid request origin'; } catch { return 'Invalid request origin'; }
}
function sessionFrom(request:FastifyRequest, sessions:WebSessionService) {
  const token=request.cookies.farcmd_session;
  return token ? sessions.get(token) : undefined;
}
/** Output of level 4/5 runs reaches the approver only when the command allows it; levels 1-3 always show it. */
function forApprover(r:CommandExecution,command:CommandRecord|undefined){
  if(r.level<=3||command?.showOutputOnApproval)return r;
  const {stdout:_stdout,stderr:_stderr,...rest}=r; return {...rest,outputHidden:true};
}
async function requireUser(request:FastifyRequest, reply:FastifyReply, users:UserStore, sessions:WebSessionService) {
  const session=sessionFrom(request,sessions);
  if (!session) { reply.code(401).send({error:'Authentication required'}); return undefined; }
  const user=users.getUser(session.userId);
  if (!isActiveUser(user)) { sessions.delete(session.token); reply.clearCookie('farcmd_session',{path:'/'}); reply.code(401).send({error:user?'This account is disabled.':'Authentication required'}); return undefined; }
  return user;
}

declare module 'fastify' { interface FastifyRequest { auditUserId?:string|undefined; auditError?:string|undefined; } }

/** Audited web API routes: "<METHOD> <route pattern>" -> [event, target type]. Every mutating /api/ route must be listed. */
export const AUDITED_ROUTES:Record<string,[string,string|undefined]>={
  'POST /api/auth/login':['auth.login','user'],'POST /api/auth/logout':['auth.logout','user'],'POST /api/auth/register':['auth.register','user'],'PATCH /api/account':['account.update','user'],'POST /api/account/password':['account.password_change','user'],
  'POST /api/ssh/keys/generate':['ssh_key.generate','ssh_key'],'POST /api/ssh/keys':['ssh_key.upload','ssh_key'],'PATCH /api/ssh/keys/:id':['ssh_key.update','ssh_key'],
  'POST /api/ssh/keys/:id/unlock':['ssh_key.unlock','ssh_key'],'POST /api/ssh/keys/:id/lock':['ssh_key.lock','ssh_key'],'DELETE /api/ssh/keys/:id':['ssh_key.delete','ssh_key'],
  'POST /api/ssh/targets':['ssh_target.create','ssh_target'],'PATCH /api/ssh/targets/:id':['ssh_target.update','ssh_target'],'DELETE /api/ssh/targets/:id':['ssh_target.delete','ssh_target'],
  'POST /api/ssh/targets/:id/test':['ssh_target.test','ssh_target'],'POST /api/ssh/targets/:id/capability-ledger/cleanup':['capability.cleanup','ssh_target'],
  'POST /api/ssh/targets/:id/verifier':['verifier.install','ssh_target'],'POST /api/ssh/targets/:id/verifier/manual':['verifier.manual_script','ssh_target'],
  'POST /api/ssh/targets/:id/verifier/verify':['verifier.verify','ssh_target'],'DELETE /api/ssh/targets/:id/verifier':['verifier.remove','ssh_target'],
  'POST /api/commands':['command.create','command'],'PATCH /api/commands/:id':['command.update','command'],'DELETE /api/commands/:id':['command.delete','command'],
  'POST /api/commands/:id/key':['capability.install','command'],'DELETE /api/commands/:id/key':['capability.remove','command'],
  'POST /api/commands/:id/execution-password':['command.level5_password_set','command'],'POST /api/commands/:id/run':['command.web_run','command'],'POST /api/confirm/:token':['command.confirmation',undefined],
  'PATCH /api/oauth/grants/:clientId':['oauth_grant.update','oauth_client'],'POST /api/oauth/grants/:clientId/revoke':['oauth_grant.revoke','oauth_client'],
  'GET /api/history/shell':['shell_history.read','ssh_target'],'PUT /api/mcp-access':['mcp_access.update','user'],
};
/** Non-secret request fields worth keeping in the audit trail (values). Everything else is reduced to its key name. */
const AUDITED_FIELDS=new Set(['name','description','hostname','port','username','sshKeyId','hostFingerprint','enabled','level','type','targetId','visibleLevels','level5PermanentlyHidden','installUsername','installKeyId','email','showOutputOnApproval','confirmed']);
function auditDetails(body:unknown,query:unknown):Record<string,unknown>{
  const details:Record<string,unknown>={};
  if(body&&typeof body==='object'&&!Array.isArray(body)){
    const b=body as Record<string,unknown>; const fields=Object.keys(b).filter(k=>b[k]!==undefined);
    if(fields.length)details.fields=fields;
    for(const k of fields)if(AUDITED_FIELDS.has(k))details[k]=b[k];
    const content=typeof b.content==='string'?b.content:typeof b.shellCommand==='string'?b.shellCommand:undefined;
    if(content!==undefined)details.contentSha256=createHash('sha256').update(content,'utf8').digest('hex');
  }
  if(query&&typeof query==='object'&&typeof (query as any).targetId==='string')details.targetId=(query as any).targetId;
  return details;
}

export async function mountWebApi(app:FastifyInstance, users:UserStore, sessionStore:WebSessionStore): Promise<void> {
  app.addHook('preHandler', async (request,reply) => {
    if (['POST','PATCH','PUT','DELETE'].includes(request.method) && request.url.startsWith('/api/')) {
      const refused=checkMutationOrigin(request);
      if (refused) return reply.code(403).send({error:refused});
    }
  });
  const sessions=new WebSessionService(sessionStore);
  const sshDb=(sessionStore as any).getDatabase?.();
  if (!sshDb) throw new Error('Web session store must expose the application database');
  const audit=new AuditLog(sshDb);
  const settings=new SqliteSettingsStore(sshDb);
  const mcpAccess=new McpAccessPolicy(sshDb);
  app.get('/api/auth/config',async()=>({registrationEnabled:settings.registrationEnabled()}));
  // Audit trail for every state-changing (and sensitive read) web API call. The acting user is resolved
  // from the session before the handler runs, so logout and account deletion are attributed correctly.
  app.addHook('onRequest',async request=>{const token=request.cookies?.farcmd_session;request.auditUserId=token?sessions.get(token)?.userId:undefined;});
  app.addHook('onSend',async(request,reply,payload)=>{
    if(reply.statusCode>=400&&typeof payload==='string'){try{const e=JSON.parse(payload).error;if(typeof e==='string')request.auditError=e.slice(0,300);}catch{}}
    return payload;
  });
  app.addHook('onResponse',async(request,reply)=>{
    const route=AUDITED_ROUTES[request.method+' '+(request.routeOptions.url??'')]; if(!route)return;
    const [event,targetType]=route; const params=(request.params??{}) as Record<string,string>;
    if(!request.auditUserId&&!event.startsWith('auth.'))return; // unauthenticated calls are rejected before doing anything
    const outcome:AuditOutcome=reply.statusCode<400?'success':'failure';
    const targetId=targetType==='user'?request.auditUserId:(params.id??(params.clientId?decodeURIComponent(params.clientId):undefined)??(request.query as any)?.targetId);
    audit.record({event,actor:'web',outcome,userId:request.auditUserId,ip:request.ip,targetType,targetId,details:{...auditDetails(request.body,request.query),status:reply.statusCode,...(request.auditError?{error:request.auditError}:{})}});
  });
  const ssh=new SqliteSshStore(sshDb);
  const commands=new SqliteCommandStore(sshDb);
  const installations=new SqliteCommandInstallationStore(sshDb);
  const capabilityLedger=new SqliteRemoteCapabilityLedgerStore(sshDb);
  const executionHistory=new SqliteExecutionHistoryStore(sshDb);
  const connector=new FarcmdConnectorImpl(sshDb,process.env.MCP_PUBLIC_URL ?? `http://localhost:${process.env.PORT ?? '5999'}`);
  const verifiers=new SqliteVerificationAuthorityStore(sshDb);
  const verification=new CapabilityVerificationService(sshDb,process.env.MCP_PUBLIC_URL ?? `http://localhost:${process.env.PORT ?? '5999'}`);
  /** Decrypt and, if needed, unlock-check a master key. Master keys are provisioning authority only. */
  const unlockedMaster=(userId:string,keyId:string):{key:SshKeyMaterial}|{error:string;status:number}=>{
    const master=ssh.getKey(userId,keyId); if(!master)return {error:'SSH master key is missing; provisioning authority is unavailable.',status:400};
    let privateKey:string; try{privateKey=decryptSecret(master.encryptedPrivateKey,'ssh-key:'+userId+':'+master.id);}catch{return {error:'Unable to decrypt the SSH master key.',status:500};}
    const passphrase=getSshPassphrase(userId,master.id); const inspected=inspectPrivateKey(privateKey,passphrase);
    if(!inspected.valid)return inspected.encrypted&&!passphrase?{error:'SSH master key is locked. Unlock it in the farcmd web UI first.',status:409}:{error:'Stored SSH master key is invalid or the unlock passphrase is incorrect.',status:400};
    return {key:{privateKey,...(passphrase!==undefined?{passphrase}:{})}};
  };
  const targetConfig=(t:SshTargetRecord)=>({hostname:t.hostname,port:t.port,username:t.username,...(t.hostFingerprint?{hostFingerprint:t.hostFingerprint}:{})});
  const verifierStatus=(v:VerificationAuthorityRecord|undefined)=>v?{id:v.id,status:v.status,privilege:v.privilege,fingerprint:v.fingerprint,installedAt:v.installedAt,lastVerifiedAt:v.lastVerifiedAt,lastError:v.lastError,pythonPath:v.pythonPath}:{status:'unavailable' as const};
  const verificationSummary=(userId:string,result:TargetVerificationResult)=>{
    const names=new Map(commands.list(userId).map(c=>[c.id,c.name]));
    return {ok:result.ok,...(result.error?{error:result.error}:{}),problems:(result.evaluation?.problems??[]).map(p=>({...p,...(p.commandId?{commandName:names.get(p.commandId)}:{})})),...(result.report?{sshd:result.report.sshd.state,authorizedKeysCommand:result.report.sshd.authorizedKeysCommand}:{})};
  };
  /** Generate a fresh verification key + secret for a target (reusing the verifier ID on repair). */
  const prepareVerifier=(userId:string,target:SshTargetRecord)=>{
    const existing=verifiers.getForTarget(userId,target.id);
    const id=existing?.id??crypto.randomUUID(); const privilege=verifierPrivilegeFor(target.username);
    const generated=utils.generateKeyPairSync('ed25519',{comment:verificationKeyComment(id)});
    const publicKey=String(generated.public).trim(); const privateKey=String(generated.private);
    const fingerprint=inspectPrivateKey(privateKey).fingerprint; if(!fingerprint)throw new Error('Could not fingerprint the generated verification key.');
    const secret=generateVerificationSecret();
    const authorizedKeyLine=buildCommandRestrictedAuthorizedKey(publicKey,verificationForcedCommand(id,privilege));
    const script=renderVerifierInstallScript({id,username:target.username,privilege,secret,authorizedKeyLine});
    const now=Date.now();
    const record:VerificationAuthorityRecord={id,userId,targetId:target.id,username:target.username,privilege,encryptedPrivateKey:encryptSecret(privateKey,verificationKeyAad(userId,id)),publicKey,fingerprint,encryptedSecret:encryptSecret(secret.toString('hex'),verificationSecretAad(userId,id)),authorizedKeyLine,authorizedKeySha256:sha256Hex(authorizedKeyLine),...(privilege==='sudo'?{sudoersSha256:sha256Hex(renderSudoers(id,target.username))}:{}),status:'pending',createdAt:existing?.createdAt??now,updatedAt:now};
    secret.fill(0);
    return {record,script};
  };
  /** Optional sudo password for automatic install/removal. Never stored or logged; used for this request only. */
  const sudoPasswordFrom=(request:FastifyRequest):string|undefined|null=>{
    const b=(request.body??{}) as Record<string,unknown>; const v=b.sudoPassword;
    if(v===undefined||v===null||v==='')return undefined;
    return typeof v==='string'&&v.length<=1024&&!/[\r\n\0]/.test(v)?v:null;
  };
  /**
   * SSH access used to obtain root for automatic verifier install/removal. It may be a different account on
   * the same host (e.g. an admin account with sudo) than the target's command account, with any of the
   * user's stored master keys; the host key is the target's pinned fingerprint. Defaults to the target's
   * own account and master key. The verifier is always installed for, and measures, target.username.
   */
  const installAccess=(request:FastifyRequest,userId:string,target:SshTargetRecord):{config:ReturnType<typeof targetConfig>;key:SshKeyMaterial;root:{command:string;stdinPrefix:string}}|{error:string;status:number}=>{
    const b=(request.body??{}) as Record<string,unknown>;
    const username=typeof b.installUsername==='string'&&b.installUsername.trim()?b.installUsername.trim():target.username;
    if(!isSafeTargetUsername(username))return {error:'Invalid install account name.',status:400};
    const keyId=typeof b.installKeyId==='string'&&b.installKeyId?b.installKeyId:target.sshKeyId;
    const sudoPassword=sudoPasswordFrom(request); if(sudoPassword===null)return {error:'Invalid sudo password.',status:400};
    if(!target.enabled||!target.hostFingerprint)return {error:'SSH target must be enabled and have a pinned host fingerprint.',status:400};
    const master=unlockedMaster(userId,keyId); if('error' in master)return master;
    return {config:{...targetConfig(target),username},key:master.key,root:rootInstallInvocation(verifierPrivilegeFor(username),sudoPassword)};
  };
  const verifierTarget=async(request:FastifyRequest,reply:FastifyReply)=>{
    const user=await requireUser(request,reply,users,sessions); if(!user)return undefined;
    const target=ssh.getTarget(user.id,(request.params as {id:string}).id); if(!target){reply.code(404).send({error:'SSH target not found'});return undefined;}
    return {user,target};
  };
  app.get('/api/ssh/targets/:id/verifier',async(request,reply)=>{const ctx=await verifierTarget(request,reply);if(!ctx)return;return {verifier:verifierStatus(verifiers.getForTarget(ctx.user.id,ctx.target.id))};});
  // Automatic install/repair: needs a master key and root on the target through the chosen SSH account (root, sudo password or passwordless sudo).
  app.post('/api/ssh/targets/:id/verifier',async(request,reply)=>{
    const ctx=await verifierTarget(request,reply);if(!ctx)return; const {user,target}=ctx;
    if(!isSafeTargetUsername(target.username))return reply.code(400).send({error:'The target account name is not supported by the verifier.'});
    const access=installAccess(request,user.id,target); if('error' in access)return reply.code(access.status).send({error:access.error+(access.status===400&&/master key/.test(access.error)?' Use the manual root install script instead.':'')});
    const {record,script}=prepareVerifier(user.id,target);
    try{await executeAsMaster(access.config,access.key,access.root.command,access.root.stdinPrefix+script);}
    catch(error){return reply.code(502).send({error:'Verifier installation failed: '+(error instanceof Error?error.message:String(error))+' (automatic installation needs root on the target through the chosen SSH account: the root account, that account\'s sudo password, or passwordless sudo; otherwise use the manual root install script).'});}
    verifiers.upsert({...record,installedAt:Date.now()});
    const result=await verification.verifyTarget(user.id,target);
    return reply.code(201).send({verifier:verifierStatus(verifiers.getForTarget(user.id,target.id)),verification:verificationSummary(user.id,result)});
  });
  // Manual install/repair: works without any master key. The script contains the verification secret and is shown once.
  app.post('/api/ssh/targets/:id/verifier/manual',async(request,reply)=>{
    const ctx=await verifierTarget(request,reply);if(!ctx)return; const {user,target}=ctx;
    if(!isSafeTargetUsername(target.username))return reply.code(400).send({error:'The target account name is not supported by the verifier.'});
    const {record,script}=prepareVerifier(user.id,target);
    verifiers.upsert(record);
    return reply.code(201).send({verifier:verifierStatus(verifiers.getForTarget(user.id,target.id)),installScript:script});
  });
  app.post('/api/ssh/targets/:id/verifier/verify',async(request,reply)=>{
    const ctx=await verifierTarget(request,reply);if(!ctx)return; const {user,target}=ctx;
    if(!target.enabled||!target.hostFingerprint)return reply.code(400).send({error:'SSH target must be enabled and have a pinned host fingerprint.'});
    const result=await verification.verifyTarget(user.id,target);
    return {verifier:verifierStatus(verifiers.getForTarget(user.id,target.id)),verification:verificationSummary(user.id,result)};
  });
  app.delete('/api/ssh/targets/:id/verifier',async(request,reply)=>{
    const ctx=await verifierTarget(request,reply);if(!ctx)return; const {user,target}=ctx;
    const v=verifiers.getForTarget(user.id,target.id); if(!v)return reply.code(404).send({error:'No verification authority for this target.'});
    const uninstallScript=renderVerifierUninstallScript(v.id,v.username);
    const master=installAccess(request,user.id,target);
    if('error' in master&&/^Invalid/.test(master.error))return reply.code(400).send({error:master.error});
    let removed=false; let errorMessage:string|undefined;
    if('key' in master){try{await executeAsMaster(master.config,master.key,master.root.command,master.root.stdinPrefix+uninstallScript);removed=true;}catch(error){errorMessage=error instanceof Error?error.message:'Remote removal failed.';}}
    else errorMessage=master.error;
    verifiers.delete(user.id,v.id);
    return {ok:true,removed,...(errorMessage?{error:errorMessage}:{}),...(removed?{}:{uninstallScript})};
  });
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
  app.get('/api/ssh/targets',async (request,reply)=>{ const user=await requireUser(request,reply,users,sessions); if(!user)return; return {targets:ssh.listTargets(user.id).map(t=>({...t,verifier:verifierStatus(verifiers.getForTarget(user.id,t.id))}))}; });
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
  app.delete('/api/ssh/targets/:id',async (request,reply)=>{ const user=await requireUser(request,reply,users,sessions); if(!user)return; const id=(request.params as {id:string}).id; if(!ssh.getTarget(user.id,id))return reply.code(404).send({error:'SSH target not found'}); if(installations.list(user.id).some(k=>k.targetId===id))return reply.code(409).send({error:'This target has installed command capabilities. Remove those capabilities before deleting the target.'});if(verifiers.getForTarget(user.id,id))return reply.code(409).send({error:'This target has a verification authority. Remove it before deleting the target.'}); ssh.deleteTarget(user.id,id); return {ok:true}; });
  app.post('/api/ssh/targets/:id/test',async (request,reply)=>{
    const user=await requireUser(request,reply,users,sessions); if(!user)return; const id=(request.params as {id:string}).id; const target=ssh.getTarget(user.id,id); if(!target)return reply.code(404).send({error:'SSH target not found'}); const key=ssh.getKey(user.id,target.sshKeyId); if(!key)return reply.code(400).send({error:'SSH key not found'});
    const passphrase=getSshPassphrase(user.id,key.id); let privateKey:string; try { privateKey=decryptSecret(key.encryptedPrivateKey,'ssh-key:'+user.id+':'+key.id); } catch { return reply.code(500).send({error:'Unable to decrypt SSH key'}); }
    const result=await testSshConnection({hostname:target.hostname,port:target.port,username:target.username,...(target.hostFingerprint?{hostFingerprint:target.hostFingerprint}: {})},{privateKey,...(passphrase!==undefined?{passphrase}:{})}); return result;
  });
  app.get('/api/commands',async(request,reply)=>{const user=await requireUser(request,reply,users,sessions);if(!user)return;return {commands:commands.list(user.id).map(c=>({...c,hasExecutionPassword:c.level===5?commands.hasExecutionPassword(user.id,c.id):undefined,commandKey:installations.get(user.id,c.id)?.installedAt?{id:installations.get(user.id,c.id)!.id,fingerprint:installations.get(user.id,c.id)!.fingerprint,installedAt:installations.get(user.id,c.id)!.installedAt,remoteScriptPath:installations.get(user.id,c.id)!.remoteScriptPath}:undefined,integrityVerification:c.level>=3?(verifiers.getForTarget(user.id,c.targetId)?.status??'unavailable'):'not-required'}))};});
  app.get('/api/ssh/targets/:id/capability-ledger',async(request,reply)=>{const user=await requireUser(request,reply,users,sessions);if(!user)return;const id=(request.params as {id:string}).id;if(!ssh.getTarget(user.id,id))return reply.code(404).send({error:'SSH target not found'});return {entries:capabilityLedger.list(user.id).filter(e=>e.targetId===id)};});
  app.post('/api/ssh/targets/:id/capability-ledger/cleanup',async(request,reply)=>{const user=await requireUser(request,reply,users,sessions);if(!user)return;const id=(request.params as {id:string}).id;const target=ssh.getTarget(user.id,id);if(!target)return reply.code(404).send({error:'SSH target not found'});if(!target.enabled||!target.hostFingerprint)return reply.code(400).send({error:'SSH target must be enabled and have a pinned host fingerprint.'});const master=ssh.getKey(user.id,target.sshKeyId);if(!master)return reply.code(400).send({error:'SSH master key is missing.'});const privateKey=decryptSecret(master.encryptedPrivateKey,'ssh-key:'+user.id+':'+master.id);const passphrase=getSshPassphrase(user.id,master.id);const inspected=inspectPrivateKey(privateKey,passphrase);if(!inspected.valid)return reply.code(409).send({error:inspected.encrypted&&!passphrase?'SSH master key is locked.':'Stored SSH master key is invalid or the unlock passphrase is incorrect.'});const pending=capabilityLedger.pendingForTarget(user.id,id);let removed=0;for(const entry of pending){try{await removeCommandCapability({hostname:target.hostname,port:target.port,username:target.username,hostFingerprint:target.hostFingerprint},{privateKey,...(passphrase!==undefined?{passphrase}:{} )},entry.authorizedKeyLine,entry.remoteScriptPath);capabilityLedger.markAttempt(user.id,entry.id);removed++;}catch(error){capabilityLedger.markAttempt(user.id,entry.id,error instanceof Error?error.message:'Remote removal failed.');}}return {removed,remaining:capabilityLedger.pendingForTarget(user.id,id).length};});
  app.post('/api/commands',async(request,reply)=>{const user=await requireUser(request,reply,users,sessions);if(!user)return;const b=request.body as Record<string,unknown>;const name=typeof b.name==='string'?b.name.trim():'';const description=typeof b.description==='string'?b.description.trim():'';const type=b.type==='bash_script'?'bash_script':'shell';const content=typeof b.content==='string'?b.content:(typeof b.shellCommand==='string'?b.shellCommand:'');const normalized=type==='shell'?content.trim():content;const targetId=typeof b.targetId==='string'?b.targetId:'';const level=typeof b.level==='number'?b.level:Number(b.level);if(!name||name.length>120||description.length>2000||!normalized||normalized.length>100000||!isCommandLevel(level)||!ssh.getTarget(user.id,targetId)||(type==='shell'&&/\r|\n/.test(normalized)))return reply.code(400).send({error:'Invalid command data'});const id=crypto.randomUUID(),now=Date.now();commands.create({id,userId:user.id,targetId,name,description,type,content:normalized,level,enabled:true,showOutputOnApproval:b.showOutputOnApproval===true,createdAt:now,updatedAt:now});return reply.code(201).send({command:commands.get(user.id,id)});});
  app.patch('/api/commands/:id',async(request,reply)=>{const user=await requireUser(request,reply,users,sessions);if(!user)return;const id=(request.params as {id:string}).id;const cur=commands.get(user.id,id);if(!cur)return reply.code(404).send({error:'Command not found'});const b=request.body as Record<string,unknown>;const nextType=b.type===undefined?cur.type:(b.type==='bash_script'?'bash_script':b.type);const nextContent=typeof b.content==='string'?b.content:(typeof b.shellCommand==='string'?b.shellCommand:cur.content);const next={...cur,name:typeof b.name==='string'?b.name.trim():cur.name,description:typeof b.description==='string'?b.description.trim():cur.description,type:nextType as 'shell'|'bash_script',content:nextType==='shell'?nextContent.trim():nextContent,targetId:typeof b.targetId==='string'?b.targetId:cur.targetId,level:b.level===undefined?cur.level:(typeof b.level==='number'?b.level:Number(b.level)),enabled:typeof b.enabled==='boolean'?b.enabled:cur.enabled,showOutputOnApproval:typeof b.showOutputOnApproval==='boolean'?b.showOutputOnApproval:!!cur.showOutputOnApproval,updatedAt:Date.now()};if(!next.name||next.name.length>120||next.description.length>2000||!next.content||next.content.length>100000||!isCommandLevel(next.level)||!ssh.getTarget(user.id,next.targetId)||(next.type==='shell'&&/\r|\n/.test(next.content)))return reply.code(400).send({error:'Invalid command data'});const installation=installations.get(user.id,id);const capabilityChanged=!!installation&&(next.content!==cur.content||next.type!==cur.type||next.targetId!==cur.targetId);if(capabilityChanged)return reply.code(409).send({error:'This command has an installed SSH capability. Remove or replace that capability before changing its executable content or target.'});const clearReasons=cur.level===5&&commands.hasExecutionPassword(user.id,id)?[...(next.level!==5?['level_changed']:[]),...(next.content!==cur.content?['content_changed']:[]),...(next.targetId!==cur.targetId?['target_changed']:[])]:[];if(clearReasons.length)commands.clearExecutionPassword(user.id,id);commands.update(next as CommandRecord);if(clearReasons.length)audit.record({event:'command.level5_password_cleared',actor:'web',outcome:'success',userId:user.id,ip:request.ip,targetType:'command',targetId:id,details:{reasons:clearReasons}});/* an automatic clear gets its own audit entry, not only the command.update */return {command:commands.get(user.id,id)};});
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
    const rows=executionHistory.list(user.id,{...(q.clientId?{clientId:q.clientId}:{}),...(q.commandId?{commandId:q.commandId}:{}),...(isCommandLevel(level)?{level}:{}),...(q.status?{status:q.status as any}:{}),...(q.search?{search:q.search}:{}),limit:q.limit?Number(q.limit):50,offset:q.offset?Number(q.offset):0});
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
  app.get('/api/confirm/:token',async(request,reply)=>{const user=await requireUser(request,reply,users,sessions);if(!user)return;const token=(request.params as {token:string}).token;const pending=(new SqliteExecutionStore(sshDb)).get(token);if(!pending||pending.userId!==user.id)return reply.code(404).send({error:'Confirmation request not found or expired'});if(pending.status!=='pending')return reply.code(409).send({error:'This request was already approved, declined or has expired.'});const command=commands.get(user.id,pending.commandId);if(!command)return reply.code(404).send({error:'Command no longer exists'});const grant=(sessionStore as any).getOAuthGrant(user.id,pending.clientId);return {command:{id:command.id,name:command.name,description:command.description,level:command.level,confirmation:pending.level===4?'human':'password',showOutputOnApproval:!!command.showOutputOnApproval},clientId:pending.clientId,clientName:grant?.clientName??pending.clientId,expiresAt:pending.expiresAt};});
  app.post('/api/confirm/:token',async(request,reply)=>{const token=(request.params as {token:string}).token;if(!confirmationRateLimit('confirm:'+request.ip+':'+token))return reply.code(429).send({error:'Too many confirmation attempts. Try again later.'});const user=await requireUser(request,reply,users,sessions);if(!user)return;const b=request.body as Record<string,unknown>;try{const pending=new SqliteExecutionStore(sshDb).get(token);const r=await connector.approvePending(user.id,token,typeof b.password==='string'?b.password:undefined);return forApprover(r,pending?commands.get(user.id,pending.commandId):undefined);}catch(error){return reply.code(400).send({error:error instanceof Error?error.message:String(error)});}});
  // Web Run. Levels 1-3 run at once and return their output; level 4 needs {confirmed:true} and level 5 the
  // execution password, and their output is returned only if the command allows it (showOutputOnApproval).
  app.post('/api/commands/:id/run',async(request,reply)=>{const user=await requireUser(request,reply,users,sessions);if(!user)return;const id=(request.params as {id:string}).id;const b=(request.body??{}) as Record<string,unknown>;
    try{const r=await connector.runFromWeb(user.id,id,{...(typeof b.password==='string'?{password:b.password}:{}),confirmed:b.confirmed===true});return forApprover(r,commands.get(user.id,id));}
    catch(error){const message=error instanceof Error?error.message:String(error);return reply.code(error instanceof LimitExceeded?429:400).send({error:message});}});
  app.get('/api/oauth/grants',async(request,reply)=>{const user=await requireUser(request,reply,users,sessions);if(!user)return;return {grants:(sessionStore as any).listOAuthGrants(user.id).map((g:any)=>({...g,revoked:!!g.revokedAt}))};});
  app.patch('/api/oauth/grants/:clientId',async(request,reply)=>{const user=await requireUser(request,reply,users,sessions);if(!user)return;const clientId=decodeURIComponent((request.params as {clientId:string}).clientId);const b=request.body as Record<string,unknown>;const raw=Array.isArray(b.visibleLevels)?b.visibleLevels:[];const allowed=raw.map(v=>typeof v==='number'?v:Number(v)).filter(isCommandLevel) as CommandLevel[];const permanent5=Boolean(b.level5PermanentlyHidden);try{(sessionStore as any).updateOAuthGrant(user.id,clientId,allowed,permanent5);return {grant:(sessionStore as any).getOAuthGrant(user.id,clientId)};}catch(error){return reply.code(400).send({error:error instanceof Error?error.message:String(error)});}});
  app.post('/api/oauth/grants/:clientId/revoke',async(request,reply)=>{const user=await requireUser(request,reply,users,sessions);if(!user)return;const clientId=decodeURIComponent((request.params as {clientId:string}).clientId);if(!(sessionStore as any).getOAuthGrant(user.id,clientId))return reply.code(404).send({error:'OAuth source not found'});(sessionStore as any).revokeOAuthGrant(user.id,clientId);return {ok:true};});
  app.get('/api/audit',async(request,reply)=>{
    const user=await requireUser(request,reply,users,sessions);if(!user)return;
    const q=request.query as Record<string,string|undefined>;
    const outcome=q.outcome==='success'||q.outcome==='failure'?q.outcome:undefined;
    return audit.list(user.id,{...(q.event?{event:q.event}:{}),...(outcome?{outcome}:{}),...(q.search?{search:q.search}:{}),limit:q.limit?Number(q.limit):100,offset:q.offset?Number(q.offset):0});
  });
  // User-scoped MCP kill switch: MCP tools refuse this user's clients; the server and the web UI keep running.
  app.get('/api/mcp-access',async(request,reply)=>{const user=await requireUser(request,reply,users,sessions);if(!user)return;return mcpAccess.status(user.id);});
  app.put('/api/mcp-access',async(request,reply)=>{const user=await requireUser(request,reply,users,sessions);if(!user)return;const b=request.body as Record<string,unknown>;if(typeof b.enabled!=='boolean')return reply.code(400).send({error:'enabled must be true or false'});mcpAccess.setUserEnabled(user.id,b.enabled);return mcpAccess.status(user.id);});
  app.get('/api/audit/verify',async(request,reply)=>{const user=await requireUser(request,reply,users,sessions);if(!user)return;return audit.verify();});
  app.get('/api/auth/session',async (request,reply)=>{
    const user=await requireUser(request,reply,users,sessions); if(!user)return;
    return {user:publicUser(user)};
  });
  app.post('/api/auth/login',async (request,reply)=>{
    const ip=request.ip; if(!loginRateLimit(ip)) return reply.code(429).send({error:'Too many login attempts. Try again later.'});
    const b=request.body as Record<string,unknown>;
    const email=typeof b.email==='string'?cleanEmail(b.email):'';
    const password=typeof b.password==='string'?b.password:'';
    const user=users.getUserByEmail(email);
    // Failed attempts are attributed to the targeted account (if it exists) so its owner can see them.
    request.auditUserId=user?.id;
    if(!(await verifyPassword(user?.passwordHash,password))) return reply.code(401).send({error:'Invalid email or password'});
    if(!isActiveUser(user)) return reply.code(403).send({error:'This account is disabled.'});
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
    // Self-service registration is off unless the operator enabled it (farcmd-admin registration enable).
    if(!settings.registrationEnabled()) return reply.code(403).send({error:'Registration is disabled. Ask the administrator for an account.'});
    const ip=request.ip; if(!rateLimit('register:'+ip)) return reply.code(429).send({error:'Too many attempts. Try again later.'});
    const b=request.body as Record<string,unknown>;
    const name=typeof b.name==='string'?b.name.trim():'';
    const email=typeof b.email==='string'?cleanEmail(b.email):'';
    const password=typeof b.password==='string'?b.password:'';
    if(name.length<1||name.length>120) return reply.code(400).send({error:'Invalid name'});
    if(!/^\S+@\S+\.\S+$/.test(email)||email.length>320) return reply.code(400).send({error:'Invalid email'});
    if(password.length<12||password.length>1024) return reply.code(400).send({error:'Password must be 12-1024 characters'});
    if(users.getUserByEmail(email)) return reply.code(409).send({error:'An account with that email already exists'});
    const user={id:crypto.randomUUID(),name,email,passwordHash:await hash(password,{algorithm:2}),createdAt:Date.now()};
    users.createUser(user); request.auditUserId=user.id;
    const token=sessions.create(user.id); reply.setCookie('farcmd_session',token,cookieOptions());
    return reply.code(201).send({user:publicUser(user)});
  });
  app.patch('/api/account',async (request,reply)=>{
    const user=await requireUser(request,reply,users,sessions); if(!user)return;
    const b=request.body as Record<string,unknown>;
    const name=typeof b.name==='string'?b.name.trim():user.name;
    const email=typeof b.email==='string'?cleanEmail(b.email):(user.email??'');
    if(name.length<1||name.length>120||!/^\S+@\S+\.\S+$/.test(email)) return reply.code(400).send({error:'Invalid account data'});
    const other=users.getUserByEmail(email);
    if(other&&other.id!==user.id) return reply.code(409).send({error:'That email is already in use'});
    users.updateUser(user.id,name,email);
    return {user:publicUser(users.getUser(user.id)!)};
  });
  // Self-service password change: needs the current password; ends every other web session and all OAuth refresh tokens.
  app.post('/api/account/password',async (request,reply)=>{
    const user=await requireUser(request,reply,users,sessions); if(!user)return;
    if(!rateLimit('password-change:'+user.id,5,15*60_000)) return reply.code(429).send({error:'Too many attempts. Try again later.'});
    const b=(request.body??{}) as Record<string,unknown>;
    const current=typeof b.currentPassword==='string'?b.currentPassword:''; const next=typeof b.newPassword==='string'?b.newPassword:'';
    if(!(await verifyPassword(user.passwordHash,current))) return reply.code(400).send({error:'The current password is incorrect.'});
    if(next.length<12||next.length>1024) return reply.code(400).send({error:'The new password must be 12-1024 characters.'});
    if(next===current) return reply.code(400).send({error:'Choose a password different from the current one.'});
    sshDb.prepare('UPDATE users SET password_hash=? WHERE id=?').run(await hash(next,{algorithm:2}),user.id);
    const keep=hashToken(request.cookies.farcmd_session??'');
    const sessionsEnded=Number(sshDb.prepare('DELETE FROM web_sessions WHERE user_id=? AND token<>?').run(user.id,keep).changes);
    const refreshTokensRevoked=Number(sshDb.prepare('DELETE FROM refresh_tokens WHERE subject=?').run(user.id).changes);
    sshDb.prepare('DELETE FROM authorization_codes WHERE subject=?').run(user.id);
    return {ok:true,sessionsEnded,refreshTokensRevoked};
  });
}
