import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import ssh2 from 'ssh2';
import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import formbody from '@fastify/formbody';
import { SqliteAuthStore, SqliteUserStore } from '../src/storage/sqlite.js';
import { AuditLog, sanitizeDetails } from '../src/audit.js';
import { mountWebApi, AUDITED_ROUTES } from '../src/web-api.js';
import { FarcmdConnectorImpl } from '../src/connector.js';
import { SqliteOAuthGrantStore } from '../src/oauth/grants.js';

process.env.FARCMD_ENCRYPTION_KEY??=randomBytes(32).toString('base64');
function fixture(){const dir=mkdtempSync(join(tmpdir(),'farcmd-audit-'));const store=new SqliteAuthStore(join(dir,'app.sqlite'));return {dir,store,db:store.getDatabase(),log:new AuditLog(store.getDatabase())};}

test('audit entries form an HMAC chain that detects edits, deletions and forged recomputation',()=>{
  const f=fixture();
  try{
    for(let i=0;i<5;i++)f.log.append({event:'test.event',actor:'system',userId:'u1',details:{i}});
    const ok=f.log.verify(); assert.equal(ok.ok,true); assert.equal(ok.checked,5); assert.equal(ok.headSeq,5);
    // edit content
    f.db.prepare("UPDATE security_events SET details='{\"i\":99}' WHERE seq=3").run();
    assert.deepEqual([f.log.verify().ok,f.log.verify().brokenAtSeq],[false,3]);
    f.db.prepare("UPDATE security_events SET details='{\"i\":2}' WHERE seq=3").run();
    assert.equal(f.log.verify().ok,true);
    // change the outcome of an entry
    f.db.prepare("UPDATE security_events SET outcome='failure' WHERE seq=2").run();
    assert.equal(f.log.verify().brokenAtSeq,2);
    f.db.prepare("UPDATE security_events SET outcome='success' WHERE seq=2").run();
    // delete from the middle
    const row=f.db.prepare('SELECT * FROM security_events WHERE seq=4').get() as any;
    f.db.prepare('DELETE FROM security_events WHERE seq=4').run();
    const gap=f.log.verify(); assert.equal(gap.ok,false); assert.match(gap.reason!,/missing/);
    f.db.prepare('INSERT INTO security_events (id,user_id,client_id,event,details,created_at,seq,actor,outcome,ip,target_type,target_id,prev_hash,hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(row.id,row.user_id,row.client_id,row.event,row.details,row.created_at,row.seq,row.actor,row.outcome,row.ip,row.target_type,row.target_id,row.prev_hash,row.hash);
    assert.equal(f.log.verify().ok,true);
    // a database-only attacker cannot recompute valid hashes without the environment key
    const saved=process.env.FARCMD_ENCRYPTION_KEY;
    process.env.FARCMD_ENCRYPTION_KEY=randomBytes(32).toString('base64');
    try{assert.equal(f.log.verify().ok,false);}finally{process.env.FARCMD_ENCRYPTION_KEY=saved;}
  }finally{rmSync(f.dir,{recursive:true,force:true});}
});

test('audit details never keep secret-looking fields',()=>{
  assert.deepEqual(sanitizeDetails({name:'ok',password:'p',sudoPassword:'s',privateKey:'k',passphrase:'x',confirmationToken:'t',nested:{secret:'s',keep:1}}),{name:'ok',nested:{keep:1}});
});

test('pruning removes old entries, records the removal and leaves a verifiable chain',()=>{
  const f=fixture();
  try{
    f.log.append({event:'old.one',actor:'system'}); f.log.append({event:'old.two',actor:'system'});
    f.db.prepare('UPDATE security_events SET created_at=? WHERE seq<=2').run(Date.now()-10*86_400_000);
    f.log.append({event:'fresh',actor:'system'});
    assert.equal(f.log.prune(86_400_000),2);
    const events=(f.db.prepare('SELECT event FROM security_events ORDER BY seq').all() as any[]).map(r=>r.event);
    assert.deepEqual(events,['fresh','audit.pruned']);
    assert.equal(f.log.verify().ok,true);
  }finally{rmSync(f.dir,{recursive:true,force:true});}
});

test('every mutating web API route is audited',async()=>{
  const f=fixture();
  try{
    const app=Fastify(); const routes:string[]=[];
    app.addHook('onRoute',r=>{for(const m of [r.method].flat())routes.push(m+' '+r.url);});
    await app.register(formbody); await app.register(cookie); await mountWebApi(app,new SqliteUserStore(f.db),f.store);
    await app.ready();
    const mutating=routes.filter(r=>/^(POST|PATCH|PUT|DELETE) \/api\//.test(r));
    assert.ok(mutating.length>20);
    assert.deepEqual(mutating.filter(r=>!(r in AUDITED_ROUTES)),[]);
  }finally{rmSync(f.dir,{recursive:true,force:true});}
});

test('web API actions are recorded per user without secrets and are readable via /api/audit',async()=>{
  const f=fixture();
  try{
    const app=Fastify(); await app.register(formbody); await app.register(cookie); await mountWebApi(app,new SqliteUserStore(f.db),f.store);
    const password='correct horse battery staple';
    const reg=await app.inject({method:'POST',url:'/api/auth/register',payload:{name:'Owner',email:'owner@example.test',password}});
    assert.equal(reg.statusCode,201);
    const userId=reg.json().user.id; const cookieHeader='farcmd_session='+reg.cookies.find(c=>c.name==='farcmd_session')!.value;
    const api=(method:any,url:string,payload?:unknown)=>app.inject({method,url,headers:{cookie:cookieHeader},...(payload!==undefined?{payload:payload as any}:{})});
    assert.equal((await app.inject({method:'POST',url:'/api/auth/login',payload:{email:'owner@example.test',password:'wrong password!'}})).statusCode,401);
    const master=ssh2.utils.generateKeyPairSync('ed25519',{comment:'audit-test',passphrase:'key passphrase',cipher:'aes256-cbc'});
    const key=await api('POST','/api/ssh/keys',{name:'master',privateKey:String(master.private)}); assert.equal(key.statusCode,201);
    const keyId=key.json().key.id;
    assert.equal((await api('POST','/api/ssh/keys/'+keyId+'/unlock',{passphrase:'wrong'})).statusCode,400);
    const target=await api('POST','/api/ssh/targets',{name:'t',hostname:'192.0.2.1',port:22,username:'deploy',sshKeyId:keyId}); const targetId=target.json().target.id;
    const cmd=await api('POST','/api/commands',{name:'restart',description:'d',type:'shell',content:'systemctl restart app',targetId,level:3}); const commandId=cmd.json().command.id;
    assert.equal((await api('PATCH','/api/commands/'+commandId,{level:5})).statusCode,200);
    assert.equal((await api('POST','/api/commands/'+commandId+'/execution-password',{password:'level five password'})).statusCode,200);
    new SqliteOAuthGrantStore(f.db).upsert(userId,'https://client.example/meta.json','Client',[1,2,3],false);
    assert.equal((await api('POST','/api/oauth/grants/'+encodeURIComponent('https://client.example/meta.json')+'/revoke')).statusCode,200);
    await new FarcmdConnectorImpl(f.db,'http://localhost').executeCommand({userId,clientId:'https://client.example/meta.json',accessToken:'x'},commandId,5).catch(()=>undefined);
    assert.equal((await api('DELETE','/api/ssh/keys/00000000-0000-4000-8000-000000000000')).statusCode,404); // failure is recorded too
    await api('POST','/api/auth/logout');
    assert.equal((await app.inject({method:'DELETE',url:'/api/commands/'+commandId})).statusCode,401); // unauthenticated: not recorded

    const all=JSON.stringify(f.db.prepare('SELECT * FROM security_events').all());
    for(const secret of [password,'wrong password!','key passphrase','level five password','systemctl restart app',String(master.private).split('\n')[1]!])assert.ok(!all.includes(secret),'leaked: '+secret.slice(0,20));
    const rows=(f.db.prepare('SELECT event,outcome,user_id,target_id,details FROM security_events WHERE seq IS NOT NULL ORDER BY seq').all() as any[]);
    const events=rows.map(r=>r.event+':'+r.outcome);
    assert.deepEqual(events,['auth.register:success','auth.login:failure','ssh_key.upload:success','ssh_key.unlock:failure','ssh_target.create:success','command.create:success','command.update:success','command.level5_password_set:success','oauth_grant.revoke:success','command.execute_denied:failure','ssh_key.delete:failure','auth.logout:success']);
    assert.ok(rows.every(r=>r.user_id===userId),'every entry is attributed to the account owner');
    const update=JSON.parse(rows[6].details); assert.equal(update.level,5); assert.deepEqual(update.fields,['level']);
    assert.match(JSON.parse(rows[5].details).contentSha256,/^[0-9a-f]{64}$/);
    // read API: newest first, scoped to the user, and chain verification
    const login=await app.inject({method:'POST',url:'/api/auth/login',payload:{email:'owner@example.test',password}});
    const c2='farcmd_session='+login.cookies.find(c=>c.name==='farcmd_session')!.value;
    const listed=(await app.inject({method:'GET',url:'/api/audit?outcome=failure',headers:{cookie:c2}})).json();
    assert.deepEqual(listed.entries.map((e:any)=>e.event),['ssh_key.delete','command.execute_denied','ssh_key.unlock','auth.login']);
    assert.equal((await app.inject({method:'GET',url:'/api/audit?event=command',headers:{cookie:c2}})).json().total,4);
    const other=await app.inject({method:'POST',url:'/api/auth/register',payload:{name:'Other',email:'other@example.test',password}});
    const c3='farcmd_session='+other.cookies.find(c=>c.name==='farcmd_session')!.value;
    assert.deepEqual((await app.inject({method:'GET',url:'/api/audit',headers:{cookie:c3}})).json().entries.map((e:any)=>e.event),['auth.register']);
    const verified=(await app.inject({method:'GET',url:'/api/audit/verify',headers:{cookie:c2}})).json();
    assert.equal(verified.ok,true); assert.match(verified.headHash,/^[0-9a-f]{64}$/);
  }finally{rmSync(f.dir,{recursive:true,force:true});}
});
