import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import formbody from '@fastify/formbody';
import { SqliteAuthStore, SqliteUserStore } from '../src/storage/sqlite.js';
import { isActiveUser } from '../src/storage/interface.js';
import { UserAdmin } from '../src/user-admin.js';
import { AuditLog } from '../src/audit.js';
import { mountWebApi } from '../src/web-api.js';
import { mountMcpHttp } from '../src/mcp/http.js';
import { issueAccessToken } from '../src/oauth/jwt.js';
import { FarcmdConnectorImpl } from '../src/connector.js';
import { SqliteOAuthGrantStore } from '../src/oauth/grants.js';
import { SqliteCommandStore } from '../src/command-registry.js';
import { McpAccessPolicy } from '../src/mcp-access.js';

process.env.FARCMD_ENCRYPTION_KEY??=randomBytes(32).toString('base64');
const PASSWORD='correct horse battery staple';
const ISSUER='http://localhost:5999'; const RESOURCE=ISSUER+'/mcp'; const JWT=randomBytes(32); const CLIENT='https://client.example/c.json';

async function fixture(){
  const dir=mkdtempSync(join(tmpdir(),'farcmd-mcp-access-'));
  const store=new SqliteAuthStore(join(dir,'app.sqlite')); const db=store.getDatabase(); const users=new SqliteUserStore(db);
  const connector=new FarcmdConnectorImpl(db,ISSUER);
  const app=Fastify(); await app.register(formbody); await app.register(cookie); await mountWebApi(app,users,store);
  await mountMcpHttp(app,{connector,publicUrl:ISSUER,jwtSecret:JWT,resource:RESOURCE,isUserActive:id=>isActiveUser(users.getUser(id))});
  const admin=new UserAdmin(db);
  const user=await admin.create({email:'m@example.test',name:'Em',password:PASSWORD});
  new SqliteOAuthGrantStore(db).upsert(user.id,CLIENT,'Client',[1,4],false);
  // A level 1 and a level 4 command on a target that is never reached in these tests.
  const keyId=randomUUID(), targetId=randomUUID(), l1=randomUUID(), l4=randomUUID(); const now=Date.now();
  db.prepare('INSERT INTO ssh_keys (id,user_id,name,encrypted_private_key,created_at,updated_at) VALUES (?,?,?,?,?,?)').run(keyId,user.id,'key','1.x.x',now,now);
  db.prepare('INSERT INTO ssh_targets (id,user_id,name,hostname,port,username,ssh_key_id,host_fingerprint,enabled,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)').run(targetId,user.id,'target','localhost',22,'user',keyId,'sha256:abc',1,now,now);
  const commands=new SqliteCommandStore(db);
  commands.create({id:l1,userId:user.id,targetId,name:'Read',description:'',type:'shell',content:'uptime',level:1,enabled:true,createdAt:now,updatedAt:now});
  commands.create({id:l4,userId:user.id,targetId,name:'Restart',description:'',type:'shell',content:'reboot',level:4,enabled:true,createdAt:now,updatedAt:now});
  const token=await issueAccessToken(JWT,ISSUER,RESOURCE,user.id,CLIENT,'mcp');
  const rpc=async(method:string,params:Record<string,unknown>)=>{
    const r=await app.inject({method:'POST',url:'/mcp',headers:{authorization:'Bearer '+token,accept:'application/json, text/event-stream','content-type':'application/json'},payload:{jsonrpc:'2.0',id:1,method,params}});
    const line=String(r.body).split('\n').find(l=>l.startsWith('data: ')); return JSON.parse(line?line.slice(6):r.body).result;
  };
  const tools=async()=>((await rpc('tools/list',{})).tools as any[]).map(t=>t.name).sort();
  const call=async(name:string,args:Record<string,unknown>={})=>{const r=await rpc('tools/call',{name,arguments:args});return {error:!!r.isError,text:r.content[0].text as string};};
  const loginRes=await app.inject({method:'POST',url:'/api/auth/login',payload:{email:'m@example.test',password:PASSWORD}});
  const c=loginRes.cookies.find((x:any)=>x.name==='farcmd_session')!; const webCookie='farcmd_session='+c.value;
  const setOwn=(enabled:boolean)=>app.inject({method:'PUT',url:'/api/mcp-access',headers:{cookie:webCookie,origin:ISSUER},payload:{enabled}});
  const getOwn=async()=>(await app.inject({method:'GET',url:'/api/mcp-access',headers:{cookie:webCookie}})).json();
  const ctx={userId:user.id,clientId:CLIENT,accessToken:token};
  return {dir,db,app,admin,user,connector,l1,l4,tools,call,setOwn,getOwn,webCookie,ctx,done:()=>rmSync(dir,{recursive:true,force:true})};
}
const ALL_TOOLS=['command_level_1','command_level_4','farcmd_health','list_commands'];

test('each switch (user, administrator per user, global) refuses every MCP path; the web UI keeps working',async()=>{
  const f=await fixture();
  try{
    assert.deepEqual(await f.tools(),ALL_TOOLS);
    assert.equal((await f.call('farcmd_health')).error,false);
    const cases:[string,()=>Promise<unknown>|unknown,()=>Promise<unknown>|unknown,RegExp][]=[
      ['user',async()=>assert.equal((await f.setOwn(false)).statusCode,200),async()=>assert.equal((await f.setOwn(true)).statusCode,200),/turned off for this account.*web UI/],
      ['admin',()=>f.admin.setMcpBlocked('m@example.test',true),()=>f.admin.setMcpBlocked('m@example.test',false),/disabled for this account by the administrator/],
      ['global',()=>f.admin.setMcpGlobal(false),()=>f.admin.setMcpGlobal(true),/disabled on this farcmd server by the administrator/],
    ];
    for(const [name,off,on,message] of cases){
      await off();
      // The still-valid access token is accepted, but no execution tool is exposed and every tool refuses.
      assert.deepEqual(await f.tools(),['farcmd_health','list_commands'],name+': execution tools hidden');
      for(const [tool,args] of [['farcmd_health',{}],['list_commands',{}]] as const){const r=await f.call(tool,args);assert.equal(r.error,true,name+' '+tool);assert.match(r.text,message);}
      await assert.rejects(f.connector.executeCommand(f.ctx,f.l1,1),message,name+': execution refused even if a client calls a tool it saw before');
      await assert.rejects(f.connector.executeCommand(f.ctx,f.l4,4),message,name+': no confirmation request is created');
      assert.equal((f.db.prepare('SELECT COUNT(*) AS n FROM pending_executions').get() as any).n,0);
      assert.equal((await f.app.inject({method:'GET',url:'/api/commands',headers:{cookie:f.webCookie}})).statusCode,200,name+': web UI unaffected');
      await on();
      assert.deepEqual(await f.tools(),ALL_TOOLS,name+': restored without reconnecting');
      assert.equal((await f.call('farcmd_health')).error,false);
    }
    // Refusals are audited like any other refused MCP call.
    assert.ok((f.db.prepare("SELECT COUNT(*) AS n FROM security_events WHERE event='command.execute_denied'").get() as any).n>=6);
    assert.equal(new AuditLog(f.db).verify().ok,true);
  }finally{f.done();}
});

test('a confirmation requested while MCP was on cannot be approved after it is turned off',async()=>{
  const f=await fixture();
  try{
    const pending=await f.connector.executeCommand(f.ctx,f.l4,4); assert.ok('pending' in pending);
    const token=(pending as any).confirmationToken as string;
    assert.equal((await f.setOwn(false)).statusCode,200);
    const approve=await f.app.inject({method:'POST',url:'/api/confirm/'+encodeURIComponent(token),headers:{cookie:f.webCookie,origin:ISSUER},payload:{}});
    assert.equal(approve.statusCode,400); assert.match(approve.json().error,/MCP access is turned off/);
    assert.equal((f.db.prepare("SELECT COUNT(*) AS n FROM execution_history").get() as any).n,0,'nothing ran');
    await assert.rejects(f.connector.executeCommand(f.ctx,f.l4,4,token),/MCP access is turned off/,'the result cannot be fetched either');
  }finally{f.done();}
});

test('the user cannot lift an administrator block; the API reports every switch and audits changes',async()=>{
  const f=await fixture();
  try{
    assert.deepEqual(await f.getOwn(),{globalEnabled:true,adminBlocked:false,userEnabled:true,effective:true});
    f.admin.setMcpBlocked('m@example.test',true);
    assert.equal((await f.setOwn(true)).statusCode,200);
    assert.deepEqual(await f.getOwn(),{globalEnabled:true,adminBlocked:true,userEnabled:true,effective:false,reason:'admin'});
    assert.equal((await f.call('farcmd_health')).error,true);
    assert.equal((await f.app.inject({method:'PUT',url:'/api/mcp-access',headers:{cookie:f.webCookie,origin:ISSUER},payload:{enabled:'no'}})).statusCode,400);
    assert.equal((await f.app.inject({method:'PUT',url:'/api/mcp-access',payload:{enabled:false}})).statusCode,401);
    // Account disable wins over everything and is reported as such.
    f.admin.setMcpBlocked('m@example.test',false); f.admin.setDisabled('m@example.test',true);
    assert.equal(new McpAccessPolicy(f.db).status(f.user.id).reason,'account');
    const events=(f.db.prepare("SELECT event,outcome FROM security_events WHERE event LIKE '%mcp%' ORDER BY seq").all() as any[]).map(r=>r.event+':'+r.outcome);
    assert.deepEqual(events,['admin.mcp.block_user:success','mcp_access.update:success','mcp_access.update:failure','admin.mcp.unblock_user:success']);
    const detail=JSON.parse((f.db.prepare("SELECT details FROM security_events WHERE event='mcp_access.update' ORDER BY seq LIMIT 1").get() as any).details);
    assert.equal(detail.enabled,true,'the new value is recorded');
  }finally{f.done();}
});

test('farcmd-admin mcp: --all and --email switches, status and user list',()=>{
  const dir=mkdtempSync(join(tmpdir(),'farcmd-mcp-cli-'));
  try{
    const env={...process.env,STORAGE_PATH:join(dir,'app.sqlite')};
    const cli=(args:string[],input?:string)=>spawnSync(process.execPath,['--import','tsx','src/cli/admin.ts',...args],{env,input,encoding:'utf8'});
    assert.equal(cli(['user','create','--email','a@example.test','--name','A','--password-stdin'],PASSWORD+'\n').status,0);
    assert.equal(cli(['user','create','--email','b@example.test','--name','B','--password-stdin'],PASSWORD+'\n').status,0);
    assert.match(cli(['mcp','status']).stdout,/all users\): ENABLED/);
    assert.equal(cli(['mcp','disable']).status,2,'needs --all or --email');
    assert.equal(cli(['mcp','disable','--all','--email','a@example.test']).status,2,'not both');
    assert.match(cli(['mcp','disable','--email','a@example.test']).stdout,/OFF \(blocked by administrator\)/);
    assert.match(cli(['mcp','status']).stdout,/a@example\.test: OFF \(blocked by administrator\)/);
    assert.match(cli(['user','list']).stdout,/a@example\.test.*MCP BLOCKED[\s\S]*b@example\.test.*MCP on/);
    assert.match(cli(['mcp','disable','--all']).stdout,/DISABLED for all users/);
    assert.match(cli(['mcp','status','--email','b@example.test']).stdout,/OFF \(disabled for all users\)/);
    const enabled=cli(['mcp','enable','--all']); assert.match(enabled.stdout,/ENABLED for all users/); assert.match(enabled.stdout,/Still blocked individually: a@example\.test/);
    assert.match(cli(['mcp','enable','--email','a@example.test']).stdout,/a@example\.test: MCP access ON/);
    assert.equal(cli(['mcp','enable','--email','nobody@example.test']).status,1);
    const db=new SqliteAuthStore(env.STORAGE_PATH).getDatabase();
    const audit=(db.prepare("SELECT event FROM security_events WHERE event LIKE 'admin.mcp.%' ORDER BY seq").all() as any[]).map(r=>r.event);
    assert.deepEqual(audit,['admin.mcp.block_user','admin.mcp.disable_all','admin.mcp.enable_all','admin.mcp.unblock_user']);
  }finally{rmSync(dir,{recursive:true,force:true});}
});
