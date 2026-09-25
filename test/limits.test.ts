import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import { SqliteAuthStore } from '../src/storage/sqlite.js';
import { SqliteOAuthGrantStore } from '../src/oauth/grants.js';
import { SqliteCommandStore } from '../src/command-registry.js';
import { FarcmdConnectorImpl } from '../src/connector.js';
import { ExecutionLimits, LimitExceeded, executionLimitOptionsFromEnv, setExecutionLimits } from '../src/limits.js';

process.env.FARCMD_ENCRYPTION_KEY??=randomBytes(32).toString('base64');

test('SSH concurrency: global and per-target slots are refused when full and freed exactly once',()=>{
  const l=new ExecutionLimits({maxConcurrent:3,maxPerTarget:2,perClientPerMinute:0});
  const a1=l.acquireSsh('a'), a2=l.acquireSsh('a');
  assert.throws(()=>l.acquireSsh('a'),/on this SSH target \(2\)/);
  const b1=l.acquireSsh('b');
  assert.throws(()=>l.acquireSsh('c'),/maximum number of SSH commands \(3\)/);
  a1(); a1(); // double release is harmless
  assert.equal(l.runningCount,2);
  const a3=l.acquireSsh('a'); a2(); a3(); b1();
  assert.equal(l.runningCount,0);
});

test('MCP execution rate limit is per user and client over a sliding minute',()=>{
  const l=new ExecutionLimits({maxConcurrent:1,maxPerTarget:1,perClientPerMinute:2}); const t=1_000_000;
  l.takeClientCall('u','c1',t); l.takeClientCall('u','c1',t+1000);
  assert.throws(()=>l.takeClientCall('u','c1',t+2000),(e:unknown)=>e instanceof LimitExceeded&&/at most 2 .*Try again in 58 s/.test((e as Error).message));
  l.takeClientCall('u','c2',t+2000); l.takeClientCall('v','c1',t+2000); // other client, other user: independent
  l.takeClientCall('u','c1',t+60_001); // the first call left the window
  new ExecutionLimits({maxConcurrent:1,maxPerTarget:1,perClientPerMinute:0}).takeClientCall('u','c1'); // 0 = off
});

test('limit configuration from the environment is validated',()=>{
  const saved={...process.env};
  try{
    for(const k of ['FARCMD_SSH_MAX_CONCURRENT','FARCMD_SSH_MAX_PER_TARGET','FARCMD_MCP_EXECUTIONS_PER_MINUTE'])delete process.env[k];
    assert.deepEqual(executionLimitOptionsFromEnv(),{maxConcurrent:8,maxPerTarget:2,perClientPerMinute:30});
    process.env.FARCMD_MCP_EXECUTIONS_PER_MINUTE='0'; assert.equal(executionLimitOptionsFromEnv().perClientPerMinute,0);
    process.env.FARCMD_SSH_MAX_PER_TARGET='0'; assert.throws(executionLimitOptionsFromEnv,/at least 1/);
    process.env.FARCMD_SSH_MAX_PER_TARGET='2.5'; assert.throws(executionLimitOptionsFromEnv,/non-negative integer/);
  }finally{process.env=saved;}
});

test('connector: rate limit and SSH slots are enforced before anything runs, and refusals are audited',async()=>{
  const dir=mkdtempSync(join(tmpdir(),'farcmd-limits-'));
  try{
    const db=new SqliteAuthStore(join(dir,'app.sqlite')).getDatabase(); const userId=randomUUID(); const now=Date.now();
    db.prepare('INSERT INTO users (id,name,email,created_at) VALUES (?,?,?,?)').run(userId,'U',userId+'@example.test',now);
    const keyId=randomUUID(), targetId=randomUUID(), l1=randomUUID(), l4=randomUUID();
    db.prepare('INSERT INTO ssh_keys (id,user_id,name,encrypted_private_key,created_at,updated_at) VALUES (?,?,?,?,?,?)').run(keyId,userId,'key','1.x.x',now,now);
    db.prepare('INSERT INTO ssh_targets (id,user_id,name,hostname,port,username,ssh_key_id,host_fingerprint,enabled,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)').run(targetId,userId,'target','localhost',22,'user',keyId,'sha256:abc',1,now,now);
    const commands=new SqliteCommandStore(db);
    commands.create({id:l1,userId,targetId,name:'Read',description:'',type:'shell',content:'uptime',level:1,enabled:true,createdAt:now,updatedAt:now});
    commands.create({id:l4,userId,targetId,name:'Restart',description:'',type:'shell',content:'reboot',level:4,enabled:true,createdAt:now,updatedAt:now});
    new SqliteOAuthGrantStore(db).upsert(userId,'client','Client',[1,4],false);
    const limits=new ExecutionLimits({maxConcurrent:4,maxPerTarget:1,perClientPerMinute:2}); setExecutionLimits(limits);
    const connector=new FarcmdConnectorImpl(db,'http://localhost:5999'); const ctx={userId,clientId:'client',accessToken:'t'};
    // Two calls fit the budget (the second continues the open request); the third is refused.
    const first=await connector.executeCommand(ctx,l4,4) as any; assert.equal((await connector.executeCommand(ctx,l4,4) as any).confirmationToken,first.confirmationToken);
    await assert.rejects(connector.executeCommand(ctx,l4,4),/Rate limit/);
    assert.equal((db.prepare('SELECT COUNT(*) AS n FROM pending_executions').get() as any).n,1);
    // Polling a confirmation for its result is not an execution and is not limited.
    assert.equal(((await connector.executeCommand(ctx,l4,4,first.confirmationToken)) as any).pending,true);
    // The target's only slot is busy: the approved command is refused before any SSH work.
    const hold=limits.acquireSsh(targetId);
    await assert.rejects(connector.approvePending(userId,first.confirmationToken),/concurrent commands on this SSH target/);
    hold();
    assert.equal(limits.runningCount,0);
    // With the slot free, it gets past the limiter (and stops later: this test target has no capability).
    await assert.rejects(connector.approvePending(userId,first.confirmationToken),/no installed SSH capability/);
    assert.equal(limits.runningCount,0,'the slot is released when execution fails');
    const denied=(db.prepare("SELECT details FROM security_events WHERE event='command.execute_denied'").all() as any[]).map(r=>JSON.parse(r.details).error);
    assert.ok(denied.some(e=>/Rate limit/.test(e)));
  }finally{setExecutionLimits(new ExecutionLimits(executionLimitOptionsFromEnv()));rmSync(dir,{recursive:true,force:true});}
});
