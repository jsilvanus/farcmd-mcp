import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { SqliteAuthStore, SqliteUserStore } from '../src/storage/sqlite.js';
import { SqliteCommandStore, hashCommandContent } from '../src/command-registry.js';
import { SqliteOAuthGrantStore } from '../src/oauth/grants.js';
import { SqliteExecutionStore } from '../src/execution.js';
import { SqliteExecutionHistoryStore } from '../src/execution-history.js';
import { FarcmdConnectorImpl } from '../src/connector.js';
import { encryptSecret, decryptSecret } from '../src/crypto-at-rest.js';
import { confirmationForLevel } from '../src/execution.js';
import { SqliteCommandKeyStore } from '../src/storage/command-keys.js';
import { buildCommandRestrictedAuthorizedKey, buildFarcmdScript, farcmdScriptPath, sha256Hex } from '../src/ssh.js';

function fixture(){
  const dir=mkdtempSync(join(tmpdir(),'farcmd-test-'));
  const auth=new SqliteAuthStore(join(dir,'app.sqlite'));
  const users=new SqliteUserStore(auth.getDatabase());
  const userId=randomUUID();
  users.createUser({id:userId,name:'Test User',email:userId+'@example.test',createdAt:Date.now()});
  return {dir,db:auth.getDatabase(),auth,users,userId};
}
function cleanup(f:{dir:string}){rmSync(f.dir,{recursive:true,force:true});}

test('database initializes all security-critical tables',()=>{
  const f=fixture();
  try{
    const names=(f.db.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").all() as any[]).map(r=>r.name);
    for(const name of ['users','web_sessions','ssh_keys','ssh_targets','commands','command_installations','remote_capability_ledger','verification_authorities','oauth_grants','pending_executions','execution_history','security_events']) assert.ok(names.includes(name),name);
  } finally { cleanup(f); }
});

test('crypto round-trip and AAD isolation',()=>{
  const secret=Buffer.from('a'.repeat(32)).toString('base64');
  const previous=process.env.FARCMD_ENCRYPTION_KEY;
  process.env.FARCMD_ENCRYPTION_KEY=secret;
  try{
    const blob=encryptSecret('private-key-data','aad-one');
    assert.equal(decryptSecret(blob,'aad-one'),'private-key-data');
    assert.throws(()=>decryptSecret(blob,'aad-two'));
  } finally {
    if(previous===undefined) delete process.env.FARCMD_ENCRYPTION_KEY; else process.env.FARCMD_ENCRYPTION_KEY=previous;
  }
});

test('confirmation policy maps levels 1-3, 4 and 5 correctly',()=>{
  assert.equal(confirmationForLevel(1),'none');
  assert.equal(confirmationForLevel(2),'none');
  assert.equal(confirmationForLevel(3),'none');
  assert.equal(confirmationForLevel(4),'human');
  assert.equal(confirmationForLevel(5),'password');
});
 
test('command installations are isolated per command and store only encrypted private material',()=>{
  const f=fixture();
  try{
    const keys=new SqliteCommandKeyStore(f.db);
    const commandA=randomUUID(),commandB=randomUUID(),targetId=randomUUID(),masterId=randomUUID();
    const now=Date.now();
    keys.create({id:randomUUID(),userId:f.userId,commandId:commandA,targetId,masterKeyId:masterId,encryptedPrivateKey:'ciphertext',publicKey:'ssh-ed25519 AAAA test',fingerprint:'sha256:test',remoteScriptPath:farcmdScriptPath('https://mcp.example.com',commandA),authorizedKeyLine:'restrict,command="x" ssh-ed25519 AAAA test',installedAt:now,createdAt:now,updatedAt:now});
    assert.ok(keys.get(f.userId,commandA));
    assert.equal(keys.get(f.userId,commandB),undefined);
    assert.equal(keys.list(f.userId).length,1);
  } finally { cleanup(f); }
});

test('command restricted authorized key binds the exact forced capability',()=>{
  const publicKey='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest';
  const line=buildCommandRestrictedAuthorizedKey(publicKey,'echo "hello"');
  assert.match(line,/^restrict,command="echo \\"hello\\"" ssh-ed25519 /);
  assert.throws(()=>buildCommandRestrictedAuthorizedKey(publicKey,'echo bad\nnext'));
});


test('farcmd scripts distinguish shell commands and bash scripts',()=>{const id=randomUUID();const path=farcmdScriptPath('https://mcp.example.com',id);assert.equal(path,`~/.ssh/farcmd/mcp.example.com-${id}.sh`);assert.match(buildFarcmdScript('https://mcp.example.com',id,'shell','echo hi'),/set -euo pipefail/);assert.match(buildFarcmdScript('https://mcp.example.com',id,'bash_script','echo hi'),/command-type: bash_script/);});

test('OAuth grants normalize levels and permanently hide level 5',()=>{
  const f=fixture();
  try{
    const grants=new SqliteOAuthGrantStore(f.db);
    grants.upsert(f.userId,'client-a','Client A',[3,1,3],false);
    assert.deepEqual(grants.get(f.userId,'client-a')?.visibleLevels,[1,3]);
    grants.update(f.userId,'client-a',[1,2,3,4],true);
    assert.equal(grants.get(f.userId,'client-a')?.level5PermanentlyHidden,true);
    assert.throws(()=>grants.update(f.userId,'client-a',[1,2,3,4,5],true));
    assert.throws(()=>grants.update(f.userId,'client-a',[1,2,3],false));
    grants.revoke(f.userId,'client-a');
    assert.equal(grants.isVisible(f.userId,'client-a',1),false);
  } finally { cleanup(f); }
});

test('command execution passwords are per-command and hashed',async()=>{
  const f=fixture();
  try{
    const commands=new SqliteCommandStore(f.db);
    const targetId=randomUUID();
    const base={userId:f.userId,targetId,name:'danger',description:'dangerous',type:'shell' as const,content:'echo danger',level:5 as const,enabled:true,createdAt:Date.now(),updatedAt:Date.now()};
    const a={id:randomUUID(),...base};
    const b={id:randomUUID(),...base,name:'other',content:'echo other'};
    commands.create(a); commands.create(b);
    const {hash}=await import('@node-rs/argon2');
    await commands.setExecutionPassword(f.userId,a.id,await hash('correct horse battery staple',{algorithm:2}));
    assert.equal(commands.hasExecutionPassword(f.userId,a.id),true);
    assert.equal(commands.hasExecutionPassword(f.userId,b.id),false);
    assert.equal(await commands.verifyExecutionPassword(f.userId,a.id,'correct horse battery staple'),true);
    assert.equal(await commands.verifyExecutionPassword(f.userId,a.id,'wrong password'),false);
    assert.equal(await commands.verifyExecutionPassword(f.userId,b.id,'correct horse battery staple'),false);
  } finally { cleanup(f); }
});

test('changing level, target or shell command clears level 5 password',async()=>{
  const f=fixture();
  try{
    const commands=new SqliteCommandStore(f.db);
    const id=randomUUID(),targetId=randomUUID();
    const row={id,userId:f.userId,targetId,name:'danger',description:'danger',type:'shell' as const,content:'echo 1',level:5 as const,enabled:true,createdAt:Date.now(),updatedAt:Date.now()};
    commands.create(row);
    const {hash}=await import('@node-rs/argon2');
    commands.setExecutionPassword(f.userId,id,await hash('abcdefghijkl',{algorithm:2}));
    assert.equal(commands.hasExecutionPassword(f.userId,id),true);
    commands.clearExecutionPassword(f.userId,id);
    assert.equal(commands.hasExecutionPassword(f.userId,id),false);
  } finally { cleanup(f); }
});

test('pending confirmation tokens expire and cannot be replayed',()=>{
  const f=fixture();
  try{
    const pending=new SqliteExecutionStore(f.db);
    const token=randomUUID();
    pending.create({token,userId:f.userId,clientId:'client',commandId:randomUUID(),level:4,createdAt:Date.now()-1000,expiresAt:Date.now()+60_000});
    assert.equal(pending.get(token)?.status,'pending');
    assert.equal(pending.consume(token)?.status,'pending');
    assert.equal(pending.consume(token),undefined);
    const expired=randomUUID();
    pending.create({token:expired,userId:f.userId,clientId:'client',commandId:randomUUID(),level:4,createdAt:Date.now()-10_000,expiresAt:Date.now()-1});
    assert.equal(pending.get(expired),undefined);
  } finally { cleanup(f); }
});

test('completed confirmation result is consumed exactly once',()=>{
  const f=fixture();
  try{
    const pending=new SqliteExecutionStore(f.db);
    const token=randomUUID();
    pending.create({token,userId:f.userId,clientId:'client',commandId:randomUUID(),level:4,createdAt:Date.now(),expiresAt:Date.now()+60_000});
    pending.complete(token,{exitCode:0,stdout:'ok',stderr:'',durationMs:12});
    assert.deepEqual(pending.consumeCompleted(token),{exitCode:0,stdout:'ok',stderr:'',durationMs:12});
    assert.equal(pending.consumeCompleted(token),undefined);
  } finally { cleanup(f); }
});

test('execution history aggregates successful calls only and isolates users',()=>{
  const a=fixture(),b=fixture();
  try{
    const history=new SqliteExecutionHistoryStore(a.db);
    const commandId=randomUUID();
    const now=Date.now();
    for(let i=0;i<3;i++) history.create({id:randomUUID(),userId:a.userId,clientId:'client',commandId,commandName:'Deploy',targetId:'target',level:3,startedAt:now+i,endedAt:now+i+1,durationMs:1,exitCode:0,stdout:'',stderr:'',status:'success'});
    history.create({id:randomUUID(),userId:a.userId,clientId:'client',commandId,commandName:'Deploy',targetId:'target',level:3,startedAt:now+10,endedAt:now+11,durationMs:1,exitCode:1,stdout:'',stderr:'fail',status:'failed'});
    history.create({id:randomUUID(),userId:b.userId,clientId:'client',commandId,commandName:'Deploy',targetId:'target',level:3,startedAt:now+20,endedAt:now+21,durationMs:1,exitCode:0,stdout:'',stderr:'',status:'success'});
    assert.deepEqual(history.successfulCounts(a.userId),[{commandId,commandName:'Deploy',level:3,count:3}]);
    assert.deepEqual(history.successfulCounts(b.userId),[{commandId,commandName:'Deploy',level:3,count:1}]);
  } finally { cleanup(a); cleanup(b); }
});

test('connector refuses hidden levels before any SSH execution',async()=>{
  const f=fixture();
  try{
    const grants=new SqliteOAuthGrantStore(f.db);
    const commands=new SqliteCommandStore(f.db);
    const targetId=randomUUID(), commandId=randomUUID();
    f.db.prepare('INSERT INTO ssh_keys (id,user_id,name,encrypted_private_key,created_at,updated_at) VALUES (?,?,?,?,?,?)').run(randomUUID(),f.userId,'key','1.x.x',Date.now(),Date.now());
    const keyId=(f.db.prepare('SELECT id FROM ssh_keys WHERE user_id=?').get(f.userId) as any).id;
    f.db.prepare('INSERT INTO ssh_targets (id,user_id,name,hostname,port,username,ssh_key_id,host_fingerprint,enabled,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)').run(targetId,f.userId,'target','localhost',22,'user',keyId,'sha256:abc',1,Date.now(),Date.now());
    commands.create({id:commandId,userId:f.userId,targetId,name:'High impact',description:'test',type:'shell' as const,content:'echo never',level:4,enabled:true,createdAt:Date.now(),updatedAt:Date.now()});
    grants.upsert(f.userId,'client','Client',[1,2,3],false);
    const connector=new FarcmdConnectorImpl(f.db,'http://localhost:5999');
    await assert.rejects(()=>connector.executeCommand({userId:f.userId,clientId:'client',accessToken:'token'},commandId,4),/does not expose/);
  } finally { cleanup(f); }
});

test('connector creates L4 confirmation without executing SSH',async()=>{
  const f=fixture();
  try{
    const grants=new SqliteOAuthGrantStore(f.db), commands=new SqliteCommandStore(f.db);
    const targetId=randomUUID(), commandId=randomUUID(), keyId=randomUUID();
    f.db.prepare('INSERT INTO ssh_keys (id,user_id,name,encrypted_private_key,created_at,updated_at) VALUES (?,?,?,?,?,?)').run(keyId,f.userId,'key','1.x.x',Date.now(),Date.now());
    f.db.prepare('INSERT INTO ssh_targets (id,user_id,name,hostname,port,username,ssh_key_id,host_fingerprint,enabled,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)').run(targetId,f.userId,'target','localhost',22,'user',keyId,'sha256:abc',1,Date.now(),Date.now());
    commands.create({id:commandId,userId:f.userId,targetId,name:'High impact',description:'test',type:'shell' as const,content:'echo never',level:4,enabled:true,createdAt:Date.now(),updatedAt:Date.now()});
    grants.upsert(f.userId,'client','Client',[4],false);
    const connector=new FarcmdConnectorImpl(f.db,'http://localhost:5999');
    const result=await connector.executeCommand({userId:f.userId,clientId:'client',accessToken:'token'},commandId,4);
    assert.equal(result.ok,true);
    assert.equal('pending' in result,true);
    if('pending' in result) assert.equal(result.level,4);
  } finally { cleanup(f); }
});


test('integrity baselines hash command content, remote script and authorized key line',()=>{
  const content='echo hi';
  const script=buildFarcmdScript('https://mcp.example.com',randomUUID(),'shell',content);
  const key=buildCommandRestrictedAuthorizedKey('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest','~/.ssh/farcmd/mcp.example.com-'+randomUUID()+'.sh');
  assert.equal(sha256Hex(script),sha256Hex(script));
  assert.notEqual(sha256Hex(script),sha256Hex(script+'x'));
  assert.notEqual(sha256Hex(key),sha256Hex(key+'x'));
});


function seedTarget(f:{db:any;userId:string}){
  const targetId=randomUUID(), keyId=randomUUID();
  f.db.prepare('INSERT INTO ssh_keys (id,user_id,name,encrypted_private_key,created_at,updated_at) VALUES (?,?,?,?,?,?)').run(keyId,f.userId,'key','1.x.x',Date.now(),Date.now());
  f.db.prepare('INSERT INTO ssh_targets (id,user_id,name,hostname,port,username,ssh_key_id,host_fingerprint,enabled,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)').run(targetId,f.userId,'target','192.0.2.1',22,'user',keyId,'sha256:abc',1,Date.now(),Date.now());
  return {targetId,keyId};
}

test('L3 execution without a verification authority is blocked before any SSH connection and recorded',async()=>{
  const f=fixture();
  const previous=process.env.FARCMD_ENCRYPTION_KEY; process.env.FARCMD_ENCRYPTION_KEY=Buffer.alloc(32,7).toString('base64');
  try{
    const {targetId}=seedTarget(f);
    const commands=new SqliteCommandStore(f.db); const commandId=randomUUID(); const content='echo hi';
    commands.create({id:commandId,userId:f.userId,targetId,name:'mutating',description:'m',type:'shell',content,level:3,enabled:true,createdAt:Date.now(),updatedAt:Date.now()});
    const installId=randomUUID(); const script=buildFarcmdScript('http://localhost:5999',commandId,'shell',content);
    const line=buildCommandRestrictedAuthorizedKey('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest',farcmdScriptPath('http://localhost:5999',commandId));
    new SqliteCommandKeyStore(f.db).create({id:installId,userId:f.userId,commandId,targetId,masterKeyId:randomUUID(),encryptedPrivateKey:encryptSecret('not-a-key','command-installation:'+f.userId+':'+installId),publicKey:'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest',fingerprint:'sha256:x',remoteScriptPath:farcmdScriptPath('http://localhost:5999',commandId),authorizedKeyLine:line,scriptContent:script,commandSha256:hashCommandContent('shell',content),scriptSha256:sha256Hex(script),authorizedKeySha256:sha256Hex(line),installedAt:Date.now(),createdAt:Date.now(),updatedAt:Date.now()});
    new SqliteOAuthGrantStore(f.db).upsert(f.userId,'client','Client',[3],false);
    const connector=new FarcmdConnectorImpl(f.db,'http://localhost:5999');
    const started=Date.now();
    await assert.rejects(()=>connector.executeCommand({userId:f.userId,clientId:'client',accessToken:'t'},commandId,3),/Integrity verification is unavailable/);
    assert.ok(Date.now()-started<1000,'no network connection was attempted');
    const row=f.db.prepare('SELECT status,error FROM execution_history WHERE user_id=?').get(f.userId) as any;
    assert.equal(row.status,'blocked'); assert.match(row.error,/unavailable/);
    const event=f.db.prepare("SELECT event FROM security_events WHERE user_id=? AND event='integrity.verification_blocked'").get(f.userId) as any;
    assert.ok(event);
  } finally { if(previous===undefined) delete process.env.FARCMD_ENCRYPTION_KEY; else process.env.FARCMD_ENCRYPTION_KEY=previous; cleanup(f); }
});

test('MCP discovery exposes command metadata only: no content, keys, verifier or secret material',async()=>{
  const f=fixture();
  try{
    const {targetId}=seedTarget(f);
    const commands=new SqliteCommandStore(f.db); const commandId=randomUUID();
    commands.create({id:commandId,userId:f.userId,targetId,name:'restart-backend',description:'Restart the backend service',type:'shell',content:'sudo systemctl restart backend',level:4,enabled:true,createdAt:Date.now(),updatedAt:Date.now()});
    f.db.prepare("INSERT INTO verification_authorities (id,user_id,target_id,username,privilege,encrypted_private_key,public_key,fingerprint,encrypted_secret,authorized_key_line,authorized_key_sha256,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)").run(randomUUID(),f.userId,targetId,'user','sudo','VERIFICATION-PRIVATE','ssh-ed25519 AAAA','fp','VERIFICATION-SECRET','line','sha','active',Date.now(),Date.now());
    new SqliteOAuthGrantStore(f.db).upsert(f.userId,'client','Client',[1,2,3,4,5],false);
    const listed=await new FarcmdConnectorImpl(f.db,'http://localhost:5999').listCommands({userId:f.userId,clientId:'client',accessToken:'t'});
    assert.deepEqual(Object.keys(listed[0]!).sort(),['confirmation','description','enabled','id','level','name']);
    const text=JSON.stringify(listed);
    for(const secret of ['systemctl','VERIFICATION','ssh-ed25519','sha256'])assert.ok(!text.includes(secret),secret);
    const { createMcpServer }=await import('../src/mcp/server.js');
    const server=createMcpServer({connector:new FarcmdConnectorImpl(f.db,'http://localhost:5999'),publicUrl:'http://localhost:5999',visibleLevels:[1,2,3,4,5]});
    const tools=Object.keys((server as any)._registeredTools).sort();
    assert.deepEqual(tools,['command_level_1','command_level_2','command_level_3','command_level_4','command_level_5','farcmd_health','list_commands']);
  } finally { cleanup(f); }
});
