import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import formbody from '@fastify/formbody';
import { SqliteAuthStore, SqliteUserStore } from '../src/storage/sqlite.js';
import { isActiveUser } from '../src/storage/interface.js';
import { UserAdmin } from '../src/user-admin.js';
import { AuditLog } from '../src/audit.js';
import { mountWebApi, CSRF_HEADER } from '../src/web-api.js';
import { asWebClient } from './web-client.js';
import { mountMcpHttp } from '../src/mcp/http.js';
import { issueAccessToken } from '../src/oauth/jwt.js';
import { FarcmdConnectorImpl } from '../src/connector.js';
import { SqliteOAuthGrantStore } from '../src/oauth/grants.js';
import { MAX_PENDING_SUGGESTIONS } from '../src/storage/command-suggestions.js';

process.env.FARCMD_ENCRYPTION_KEY??=randomBytes(32).toString('base64');
const PASSWORD='correct horse battery staple';
const ISSUER='http://localhost:5999'; const RESOURCE=ISSUER+'/mcp'; const JWT=randomBytes(32);
const CLIENT='https://client.example/c.json', OTHER_CLIENT='https://other.example/c.json', THIRD_CLIENT='https://third.example/c.json';

let fixtureCount=0;
async function fixture(){
  const dir=mkdtempSync(join(tmpdir(),'farcmd-suggestions-'));
  const store=new SqliteAuthStore(join(dir,'app.sqlite')); const db=store.getDatabase(); const users=new SqliteUserStore(db);
  const connector=new FarcmdConnectorImpl(db,ISSUER);
  const app=Fastify(); await app.register(formbody); await app.register(cookie); asWebClient(app); await mountWebApi(app,users,store,ISSUER);
  await mountMcpHttp(app,{connector,publicUrl:ISSUER,jwtSecret:JWT,resource:RESOURCE,isUserActive:id=>isActiveUser(users.getUser(id))});
  const admin=new UserAdmin(db);
  const user=await admin.create({email:'s@example.test',name:'Es',password:PASSWORD});
  const other=await admin.create({email:'o@example.test',name:'Oh',password:PASSWORD});
  const grants=new SqliteOAuthGrantStore(db);
  // Both sources allow suggestions (opt-in per source); THIRD_CLIENT keeps the default: off.
  grants.upsert(user.id,CLIENT,'Claude',[1],false,true); grants.upsert(user.id,OTHER_CLIENT,'Other',[1],false,true); grants.upsert(user.id,THIRD_CLIENT,'Third',[1],false);
  // A target that is never contacted: suggestions and command creation touch no machine.
  const keyId=randomUUID(), targetId=randomUUID(), now=Date.now();
  db.prepare('INSERT INTO ssh_keys (id,user_id,name,encrypted_private_key,created_at,updated_at) VALUES (?,?,?,?,?,?)').run(keyId,user.id,'key','1.x.x',now,now);
  db.prepare('INSERT INTO ssh_targets (id,user_id,name,hostname,port,username,ssh_key_id,host_fingerprint,enabled,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)').run(targetId,user.id,'dev','localhost',22,'deploy',keyId,'sha256:abc',1,now,now);
  const tokens:Record<string,string>={}; for(const c of [CLIENT,OTHER_CLIENT,THIRD_CLIENT])tokens[c]=await issueAccessToken(JWT,ISSUER,RESOURCE,user.id,c,'mcp');
  const tools=async(client:string)=>{const r=await app.inject({method:'POST',url:'/mcp',headers:{authorization:'Bearer '+tokens[client],accept:'application/json, text/event-stream','content-type':'application/json'},payload:{jsonrpc:'2.0',id:1,method:'tools/list',params:{}}});const line=String(r.body).split('\n').find(l=>l.startsWith('data: '));return (JSON.parse(line?line.slice(6):r.body).result.tools as any[]).map(t=>t.name).sort();};
  const call=async(name:string,args:Record<string,unknown>={},client=CLIENT)=>{
    const r=await app.inject({method:'POST',url:'/mcp',headers:{authorization:'Bearer '+tokens[client],accept:'application/json, text/event-stream','content-type':'application/json'},payload:{jsonrpc:'2.0',id:1,method:'tools/call',params:{name,arguments:args}}});
    const line=String(r.body).split('\n').find(l=>l.startsWith('data: ')); const result=JSON.parse(line?line.slice(6):r.body).result;
    return {error:!!result.isError,text:result.content[0].text as string,data:result.structuredContent as any};
  };
  // Each fixture signs in from its own address, so the login rate limit (per address) does not carry over between tests.
  const remoteAddress='10.0.'+(fixtureCount>>8&255)+'.'+(++fixtureCount&255);
  const login=async(email:string)=>{const r=await app.inject({method:'POST',url:'/api/auth/login',remoteAddress,payload:{email,password:PASSWORD}});const c=r.cookies.find((x:any)=>x.name==='farcmd_session')!;return 'farcmd_session='+c.value;};
  const webCookie=await login('s@example.test'); const otherCookie=await login('o@example.test');
  const web=(method:'GET'|'POST'|'PATCH',url:string,payload?:unknown,cookieHeader=webCookie,headers:Record<string,string>={})=>app.inject({method,url,headers:{cookie:cookieHeader,origin:ISSUER,...headers},...(payload!==undefined?{payload:payload as any}:{})});
  const count=(table:string)=>(db.prepare('SELECT COUNT(*) AS n FROM '+table).get() as {n:number}).n;
  return {dir,db,app,user,other,grants,targetId,call,tools,web,otherCookie,count,connector,done:()=>rmSync(dir,{recursive:true,force:true})};
}
const SUGGESTION={name:'saarnavideo: redeploy',description:'Pull, build, migrate and restart saarnavideo.',content:'/opt/server-commands/saarnavideo-redeploy.sh',level:3,targetHint:'dev server',rationale:'The person wants to redeploy from chat.'};

test('suggest_command only records a pending suggestion: no command is created, installed, enabled or listed',async()=>{
  const f=await fixture();
  try{
    const r=await f.call('suggest_command',SUGGESTION);
    assert.equal(r.error,false,r.text);
    assert.equal(r.data.status,'pending');
    assert.equal(r.data.reviewUrl,ISSUER+'/?page=suggestion&id='+r.data.suggestionId);
    assert.match(r.data.next,/cannot create, install, enable or run/);
    assert.equal(f.count('commands'),0,'no command'); assert.equal(f.count('command_installations'),0,'no capability');
    assert.deepEqual((await f.call('list_commands')).data.commands,[],'nothing new to run');
    const row=f.db.prepare('SELECT * FROM command_suggestions').get() as any;
    assert.equal(row.status,'pending'); assert.equal(row.client_name,'Claude'); assert.equal(row.content,SUGGESTION.content); assert.equal(row.target_hint,'dev server');
    const audited=f.db.prepare("SELECT actor,client_id,target_id,details FROM security_events WHERE event='command.suggested'").get() as any;
    assert.equal(audited.actor,'mcp'); assert.equal(audited.client_id,'https://client.example/c.json'); assert.equal(audited.target_id,r.data.suggestionId);
    assert.ok(!audited.details.includes(SUGGESTION.content),'the audit keeps a hash of the content, not the content');
    assert.equal(new AuditLog(f.db).verify().ok,true);
  }finally{f.done();}
});

test('suggestions are validated like commands created in the web UI',async()=>{
  const f=await fixture();
  try{
    const multiLine=await f.call('suggest_command',{...SUGGESTION,content:'cd /srv\n./deploy.sh'});
    assert.equal(multiLine.error,true); assert.match(multiLine.text,/single line.*bash_script/);
    assert.equal((await f.call('suggest_command',{...SUGGESTION,type:'bash_script',content:'cd /srv\n./deploy.sh'})).error,false,'a Bash script may have several lines');
    assert.equal((await f.call('suggest_command',{...SUGGESTION,level:6})).error,true,'level outside 1-5');
    assert.equal((await f.call('suggest_command',{...SUGGESTION,content:'   '})).error,true,'blank content');
    assert.equal((await f.call('suggest_command',{...SUGGESTION,name:'x'.repeat(121)})).error,true,'name too long');
    assert.equal(f.count('command_suggestions'),1);
  }finally{f.done();}
});

test('a revoked grant cannot suggest, and the review list is capped',async()=>{
  const f=await fixture();
  try{
    for(let i=0;i<MAX_PENDING_SUGGESTIONS;i++)assert.equal((await f.call('suggest_command',{...SUGGESTION,name:'s'+i})).error,false);
    const over=await f.call('suggest_command',SUGGESTION);
    assert.equal(over.error,true); assert.match(over.text,/waiting for review/);
    f.grants.revoke(f.user.id,CLIENT);
    const revoked=await f.call('suggest_command',SUGGESTION);
    assert.equal(revoked.error,true); assert.match(revoked.text,/revoked|Unauthorized|not/i);
    assert.equal(f.count('command_suggestions'),MAX_PENDING_SUGGESTIONS);
  }finally{f.done();}
});

test('the person creates a command from a suggestion in the web UI; the client only sees the outcome',async()=>{
  const f=await fixture();
  try{
    const id=(await f.call('suggest_command',SUGGESTION)).data.suggestionId as string;
    const listed=(await f.web('GET','/api/command-suggestions')).json().suggestions;
    assert.equal(listed.length,1); assert.equal(listed[0].content,SUGGESTION.content,'the reviewer sees the exact content');
    // The person chooses the target and level; the command is created like any other, without a capability.
    const created=await f.web('POST','/api/commands',{name:SUGGESTION.name,description:SUGGESTION.description,type:'shell',content:SUGGESTION.content,targetId:f.targetId,level:4,suggestionId:id});
    assert.equal(created.statusCode,201,created.body);
    const command=created.json().command;
    assert.equal(command.level,4); assert.equal(f.count('command_installations'),0,'still needs Install in the web UI');
    const row=f.db.prepare('SELECT status,command_id FROM command_suggestions WHERE id=?').get(id) as any;
    assert.equal(row.status,'accepted'); assert.equal(row.command_id,command.id);
    assert.equal((await f.web('GET','/api/command-suggestions')).json().suggestions.length,0,'no longer pending');
    assert.equal((await f.web('POST','/api/commands',{name:'again',type:'shell',content:'true',targetId:f.targetId,level:1,suggestionId:id})).statusCode,409,'a suggestion is accepted once');
    const own=(await f.call('list_command_suggestions')).data.suggestions;
    assert.equal(own.length,1); assert.equal(own[0].status,'accepted'); assert.equal(own[0].id,id);
    assert.deepEqual(Object.keys(own[0]).sort(),['createdAt','id','level','name','resolvedAt','reviewUrl','status'],'no content, target or command details');
    assert.deepEqual((await f.call('list_command_suggestions',{},OTHER_CLIENT)).data.suggestions,[],'another client sees none of them');
    const audited=f.db.prepare("SELECT details FROM security_events WHERE event='command.create'").get() as any;
    assert.match(audited.details,new RegExp(id),'the command creation records which suggestion it came from');
  }finally{f.done();}
});

test('dismissing a suggestion: once, only by its owner, and only with the CSRF header',async()=>{
  const f=await fixture();
  try{
    const id=(await f.call('suggest_command',SUGGESTION)).data.suggestionId as string;
    assert.equal((await f.web('POST','/api/command-suggestions/'+id+'/dismiss',{},f.otherCookie)).statusCode,404,'another user');
    assert.equal((await f.web('POST','/api/commands',{name:'x',type:'shell',content:'true',targetId:f.targetId,level:1,suggestionId:id},f.otherCookie)).statusCode,400,'another user has no such target, and no such suggestion');
    assert.equal((await f.web('POST','/api/command-suggestions/'+id+'/dismiss',{},undefined,{[CSRF_HEADER]:'0'})).statusCode,403,'CSRF header required');
    assert.equal((await f.web('POST','/api/command-suggestions/'+id+'/dismiss',{})).statusCode,200);
    assert.equal((await f.web('POST','/api/command-suggestions/'+id+'/dismiss',{})).statusCode,409);
    assert.equal((await f.web('POST','/api/commands',{name:'x',type:'shell',content:'true',targetId:f.targetId,level:1,suggestionId:id})).statusCode,409,'a dismissed suggestion cannot be accepted');
    assert.equal(f.count('commands'),0);
    assert.equal((await f.call('list_command_suggestions')).data.suggestions[0].status,'dismissed');
    assert.equal((f.db.prepare("SELECT COUNT(*) AS n FROM security_events WHERE event='command_suggestion.dismiss' AND outcome='success'").get() as any).n,1);
  }finally{f.done();}
});

test('suggestions are off unless the OAuth source allows them; the person switches them on in the web UI',async()=>{
  const f=await fixture();
  try{
    const SUGGEST_TOOLS=['list_command_suggestions','suggest_command'];
    assert.deepEqual((await f.tools(THIRD_CLIENT)).filter(t=>SUGGEST_TOOLS.includes(t)),[],'not listed by default');
    assert.deepEqual((await f.tools(CLIENT)).filter(t=>SUGGEST_TOOLS.includes(t)),SUGGEST_TOOLS,'listed where allowed');
    const ctx={userId:f.user.id,clientId:THIRD_CLIENT,accessToken:'t'};
    // A client that calls the tool anyway (it saw it earlier, or guesses the name) is refused.
    assert.equal((await f.call('suggest_command',SUGGESTION,THIRD_CLIENT)).error,true);
    await assert.rejects(f.connector.suggestCommand(ctx,{...SUGGESTION,type:'shell',level:3} as any),/not allowed for this OAuth source.*OAuth Sources page/);
    await assert.rejects(f.connector.listSuggestions(ctx),/not allowed for this OAuth source/);
    assert.equal(f.count('command_suggestions'),0);
    // The OAuth Sources page saves levels and the switch together; leaving allowSuggestions out keeps it as is.
    assert.equal((await f.web('PATCH','/api/oauth/grants/'+encodeURIComponent(THIRD_CLIENT),{visibleLevels:[1],level5PermanentlyHidden:false,allowSuggestions:true})).statusCode,200);
    assert.equal(f.grants.get(f.user.id,THIRD_CLIENT)?.allowSuggestions,true);
    assert.equal((await f.web('PATCH','/api/oauth/grants/'+encodeURIComponent(THIRD_CLIENT),{visibleLevels:[1,2],level5PermanentlyHidden:false})).statusCode,200);
    assert.equal(f.grants.get(f.user.id,THIRD_CLIENT)?.allowSuggestions,true,'unchanged when not sent');
    assert.deepEqual((await f.tools(THIRD_CLIENT)).filter(t=>SUGGEST_TOOLS.includes(t)),SUGGEST_TOOLS,'listed from the next request on');
    assert.equal((await f.call('suggest_command',SUGGESTION,THIRD_CLIENT)).error,false);
    // Switching it off hides the tools again; suggestions already made stay for review.
    await f.web('PATCH','/api/oauth/grants/'+encodeURIComponent(THIRD_CLIENT),{visibleLevels:[1,2],level5PermanentlyHidden:false,allowSuggestions:false});
    assert.deepEqual((await f.tools(THIRD_CLIENT)).filter(t=>SUGGEST_TOOLS.includes(t)),[]);
    assert.equal((await f.web('GET','/api/command-suggestions')).json().suggestions.length,1);
    const audited=f.db.prepare("SELECT details FROM security_events WHERE event='oauth_grant.update' ORDER BY seq").all() as any[];
    assert.deepEqual(audited.map(a=>JSON.parse(a.details).allowSuggestions),[true,undefined,false]);
  }finally{f.done();}
});
