/**
 * Level 4/5 approvals through URL elicitation on the stateless MCP endpoint, with the real SDK client
 * over HTTP, and the fallback for clients without it. The person's approval in the browser is
 * simulated by completing the pending request (the real web approval runs SSH; see the e2e test).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import formbody from '@fastify/formbody';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { ElicitRequestSchema, ElicitationCompleteNotificationSchema } from '@modelcontextprotocol/sdk/types.js';
import { SqliteAuthStore, SqliteUserStore } from '../src/storage/sqlite.js';
import { isActiveUser } from '../src/storage/interface.js';
import { UserAdmin } from '../src/user-admin.js';
import { mountWebApi } from '../src/web-api.js';
import { asWebClient } from './web-client.js';
import { mountMcpHttp } from '../src/mcp/http.js';
import { forgetClientCapabilities } from '../src/mcp/elicitation.js';
import { issueAccessToken } from '../src/oauth/jwt.js';
import { FarcmdConnectorImpl, notifyConfirmationChanged } from '../src/connector.js';
import { SqliteOAuthGrantStore } from '../src/oauth/grants.js';
import { SqliteCommandStore } from '../src/command-registry.js';
import { SqliteExecutionStore } from '../src/execution.js';

process.env.FARCMD_ENCRYPTION_KEY??=randomBytes(32).toString('base64');
const PASSWORD='correct horse battery staple';
const ISSUER='http://localhost:5999'; const RESOURCE=ISSUER+'/mcp'; const JWT=randomBytes(32); const CLIENT='https://client.example/c.json';

async function fixture(){
  const dir=mkdtempSync(join(tmpdir(),'farcmd-elicit-'));
  const store=new SqliteAuthStore(join(dir,'app.sqlite')); const db=store.getDatabase(); const users=new SqliteUserStore(db);
  const connector=new FarcmdConnectorImpl(db,ISSUER);
  const app=Fastify(); await app.register(formbody); await app.register(cookie); asWebClient(app); await mountWebApi(app,users,store);
  await mountMcpHttp(app,{connector,publicUrl:ISSUER,jwtSecret:JWT,resource:RESOURCE,isUserActive:id=>isActiveUser(users.getUser(id))});
  const address=await app.listen({host:'127.0.0.1',port:0});
  const user=await new UserAdmin(db).create({email:'e@example.test',name:'El',password:PASSWORD});
  new SqliteOAuthGrantStore(db).upsert(user.id,CLIENT,'Client',[1,4,5],false);
  const keyId=randomUUID(), targetId=randomUUID(), l1=randomUUID(), l4=randomUUID(); const now=Date.now();
  db.prepare('INSERT INTO ssh_keys (id,user_id,name,encrypted_private_key,created_at,updated_at) VALUES (?,?,?,?,?,?)').run(keyId,user.id,'key','1.x.x',now,now);
  db.prepare('INSERT INTO ssh_targets (id,user_id,name,hostname,port,username,ssh_key_id,host_fingerprint,enabled,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)').run(targetId,user.id,'target','localhost',22,'user',keyId,'sha256:abc',1,now,now);
  const commands=new SqliteCommandStore(db);
  commands.create({id:l1,userId:user.id,targetId,name:'Read',description:'',type:'shell',content:'uptime',level:1,enabled:true,createdAt:now,updatedAt:now});
  commands.create({id:l4,userId:user.id,targetId,name:'Restart',description:'',type:'shell',content:'reboot',level:4,enabled:true,createdAt:now,updatedAt:now});
  const token=await issueAccessToken(JWT,ISSUER,RESOURCE,user.id,CLIENT,'mcp');
  const pending=new SqliteExecutionStore(db);
  /** An MCP client over real HTTP; `elicit` answers elicitation/create when the client declares URL mode. */
  const connect=async(opts:{url:boolean;elicit?:(params:any)=>Promise<any>|any})=>{
    const client=new Client({name:'test',version:'1'},{capabilities:opts.url?{elicitation:{url:{}}}:{}});
    const completed:string[]=[];
    if(opts.url){
      client.setRequestHandler(ElicitRequestSchema,async req=>opts.elicit!(req.params));
      client.setNotificationHandler(ElicitationCompleteNotificationSchema,n=>{completed.push(n.params.elicitationId);});
    }
    await client.connect(new StreamableHTTPClientTransport(new URL(address+'/mcp'),{requestInit:{headers:{authorization:'Bearer '+token}}}));
    const call=async(args:Record<string,unknown>)=>{const r:any=await client.callTool({name:'command_level_4',arguments:args});return {error:!!r.isError,text:r.content[0].text as string};};
    return {client,call,completed};
  };
  /** What the web approval does once the command has run. */
  const approve=(url:string,stdout:string)=>{const t=new URL(url).searchParams.get('token')!;pending.complete(t,{exitCode:0,stdout,stderr:'',durationMs:7});notifyConfirmationChanged(t);};
  const events=(name:string)=>(db.prepare('SELECT details FROM security_events WHERE event=? ORDER BY seq').all(name) as any[]).map(r=>JSON.parse(r.details));
  return {db,app,user,l1,l4,connect,approve,pending,events,done:async()=>{await app.close();forgetClientCapabilities();rmSync(dir,{recursive:true,force:true});}};
}

test('URL elicitation: the approval link goes through the client and the same call returns the result',async()=>{
  const f=await fixture();
  try{
    let asked:any;
    const c=await f.connect({url:true,elicit:p=>{asked=p;setTimeout(()=>f.approve(p.url,'restarted\n'),100);return {action:'accept'};}});
    const r=await c.call({commandId:f.l4});
    assert.equal(r.error,false,r.text);
    const body=JSON.parse(r.text); assert.equal(body.pending,undefined); assert.equal(body.stdout,'restarted\n'); assert.equal(body.exitCode,0);
    assert.equal(asked.mode,'url'); assert.match(asked.url,/^http:\/\/localhost:5999\/\?page=confirm&token=/); assert.match(asked.message,/level 4 command is waiting for your approval/);
    await new Promise(r=>setTimeout(r,50));
    assert.deepEqual(c.completed,[asked.elicitationId],'completion notification for this elicitation');
    const token=new URL(asked.url).searchParams.get('token')!;
    assert.equal(f.pending.get(token)?.status,'consumed','the result is delivered once');
    await c.client.close();
  }finally{await f.done();}
});

test('URL elicitation declined or dismissed: nothing runs and the request can no longer be approved',async()=>{
  const f=await fixture();
  try{
    for(const action of ['decline','cancel'] as const){
      let url='';
      const c=await f.connect({url:true,elicit:p=>{url=p.url;return {action};}});
      const r=await c.call({commandId:f.l4});
      assert.equal(r.error,true); assert.match(r.text,action==='decline'?/declined/:/dismissed/);
      const token=new URL(url).searchParams.get('token')!;
      assert.equal(f.pending.get(token)?.status,'expired');
      await assert.rejects(new FarcmdConnectorImpl(f.db,ISSUER).approvePending(f.user.id,token),/already approved, declined or has expired/);
      assert.equal((await c.call({commandId:f.l4,confirmationToken:token})).error,true,'the token no longer works');
      await c.client.close();
    }
    assert.deepEqual(f.events('command.confirmation_declined').map(d=>d.reason),['decline','cancel']);
  }finally{await f.done();}
});

test('fallback: clients without URL elicitation, or whose elicitation fails, get the token to call again',async()=>{
  const f=await fixture();
  try{
    const plain=await f.connect({url:false});
    const first=JSON.parse((await plain.call({commandId:f.l4})).text);
    assert.equal(first.pending,true); assert.ok(first.confirmationToken); assert.match(first.approvalUrl,/page=confirm/);
    assert.equal(JSON.parse((await plain.call({commandId:f.l4,confirmationToken:first.confirmationToken})).text).pending,true,'still pending before approval');
    f.approve(first.approvalUrl,'later\n');
    assert.equal(JSON.parse((await plain.call({commandId:f.l4,confirmationToken:first.confirmationToken})).text).stdout,'later\n');
    await plain.client.close();

    const failing=await f.connect({url:true,elicit:()=>{throw new Error('cannot open links here');}});
    const fb=JSON.parse((await failing.call({commandId:f.l4})).text);
    assert.equal(fb.pending,true,'a client error falls back to the pending result'); assert.equal(f.pending.get(fb.confirmationToken)?.status,'pending','and the request can still be approved');
    await failing.client.close();
  }finally{await f.done();}
});

test('an elicitation answer is accepted only from the same user and client',async()=>{
  const f=await fixture();
  try{
    let id='';
    const c=await f.connect({url:true,elicit:p=>{id=p.elicitationId;return new Promise(()=>undefined);}}); // never answers
    const call=c.call({commandId:f.l4});
    while(!id)await new Promise(r=>setTimeout(r,20));
    const [row]=f.db.prepare("SELECT token FROM pending_executions WHERE status='pending'").all() as any[];
    // Forge a decline for someone else's elicitation: the request ids are unguessable, but even a matching
    // answer from another client must not be delivered. Here a different client sends a well-formed answer.
    const other=await issueAccessToken(JWT,ISSUER,RESOURCE,f.user.id,'https://other.example/c.json','mcp');
    const forged=await f.app.inject({method:'POST',url:'/mcp',headers:{authorization:'Bearer '+other,accept:'application/json, text/event-stream','content-type':'application/json'},payload:{jsonrpc:'2.0',id:'farcmd-elicit-x',result:{action:'decline'}}});
    assert.equal(forged.statusCode,202);
    assert.equal(f.pending.get(row.token)?.status,'pending','not declined');
    f.approve(ISSUER+'/?page=confirm&token='+row.token,'ok\n');
    assert.equal(JSON.parse((await call).text).stdout,'ok\n');
    await c.client.close();
  }finally{await f.done();}
});

test('web Run: level rules, output hiding and audit, without reaching SSH',async()=>{
  const f=await fixture();
  try{
    const login=await f.app.inject({method:'POST',url:'/api/auth/login',payload:{email:'e@example.test',password:PASSWORD}});
    const cookieHeader='farcmd_session='+login.cookies.find((x:any)=>x.name==='farcmd_session')!.value;
    const run=(id:string,payload:Record<string,unknown>={})=>f.app.inject({method:'POST',url:'/api/commands/'+id+'/run',headers:{cookie:cookieHeader},payload});
    const r1=await run(f.l1); assert.equal(r1.statusCode,400); assert.match(r1.json().error,/no installed SSH capability/);
    const r4=await run(f.l4); assert.equal(r4.statusCode,400); assert.match(r4.json().error,/must be confirmed/);
    const l5=randomUUID(); const now=Date.now(); const target=(f.db.prepare('SELECT id FROM ssh_targets').get() as any).id;
    new SqliteCommandStore(f.db).create({id:l5,userId:f.user.id,targetId:target,name:'Wipe',description:'',type:'shell',content:'rm -rf /srv/x',level:5,enabled:true,createdAt:now,updatedAt:now});
    assert.match((await run(l5)).json().error,/Execution password required/);
    const patched=await f.app.inject({method:'PATCH',url:'/api/commands/'+f.l4,headers:{cookie:cookieHeader},payload:{showOutputOnApproval:true}});
    assert.equal(patched.json().command.showOutputOnApproval,true);
    const events=(f.db.prepare("SELECT outcome,details FROM security_events WHERE event='command.web_run' ORDER BY seq").all() as any[]);
    assert.equal(events.length,3); assert.ok(events.every(e=>e.outcome==='failure'));
    assert.equal((f.db.prepare("SELECT COUNT(*) AS n FROM execution_history").get() as any).n,0,'nothing ran');
  }finally{await f.done();}
});
