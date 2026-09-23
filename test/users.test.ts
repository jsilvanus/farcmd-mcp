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
import { SqliteSettingsStore } from '../src/storage/settings.js';
import { isActiveUser } from '../src/storage/interface.js';
import { UserAdmin } from '../src/user-admin.js';
import { AuditLog } from '../src/audit.js';
import { mountWebApi } from '../src/web-api.js';
import { asWebClient } from './web-client.js';
import { mountAuthorizationServer } from '../src/oauth/authorization-server.js';
import { mountMcpHttp } from '../src/mcp/http.js';
import { issueAccessToken } from '../src/oauth/jwt.js';
import { FarcmdConnectorImpl } from '../src/connector.js';
import { SqliteOAuthGrantStore } from '../src/oauth/grants.js';

process.env.FARCMD_ENCRYPTION_KEY??=randomBytes(32).toString('base64');
const PASSWORD='correct horse battery staple';
const ISSUER='http://localhost:5999'; const RESOURCE=ISSUER+'/mcp'; const JWT=randomBytes(32);

async function fixture(){
  const dir=mkdtempSync(join(tmpdir(),'farcmd-users-'));
  const store=new SqliteAuthStore(join(dir,'app.sqlite')); const db=store.getDatabase(); const users=new SqliteUserStore(db);
  const app=Fastify(); await app.register(formbody); await app.register(cookie); asWebClient(app); await mountWebApi(app,users,store);
  await mountAuthorizationServer(app,ISSUER,RESOURCE,JWT,store,users);
  await mountMcpHttp(app,{connector:new FarcmdConnectorImpl(db,ISSUER),publicUrl:ISSUER,jwtSecret:JWT,resource:RESOURCE,isUserActive:id=>isActiveUser(users.getUser(id))});
  return {dir,store,db,users,app,admin:new UserAdmin(db),done:()=>rmSync(dir,{recursive:true,force:true})};
}
const login=async(app:any,email:string,password=PASSWORD)=>{const r=await app.inject({method:'POST',url:'/api/auth/login',payload:{email,password}});return {status:r.statusCode as number,cookie:r.cookies.find((c:any)=>c.name==='farcmd_session')?('farcmd_session='+r.cookies.find((c:any)=>c.name==='farcmd_session').value):''};};
const mcpHealth=async(app:any,token:string)=>{
  const r=await app.inject({method:'POST',url:'/mcp',headers:{authorization:'Bearer '+token,accept:'application/json, text/event-stream','content-type':'application/json'},payload:{jsonrpc:'2.0',id:1,method:'tools/call',params:{name:'farcmd_health',arguments:{}}}});
  return r.body as string;
};

test('self-service registration is off by default and controlled by the database setting',async()=>{
  const f=await fixture();
  try{
    assert.equal((await f.app.inject({method:'GET',url:'/api/auth/config'})).json().registrationEnabled,false);
    const refused=await f.app.inject({method:'POST',url:'/api/auth/register',payload:{name:'X',email:'x@example.test',password:PASSWORD}});
    assert.equal(refused.statusCode,403); assert.match(refused.json().error,/Registration is disabled/);
    assert.equal(f.users.getUserByEmail('x@example.test'),undefined);
    f.admin.setRegistration(true);
    assert.equal((await f.app.inject({method:'GET',url:'/api/auth/config'})).json().registrationEnabled,true);
    assert.equal((await f.app.inject({method:'POST',url:'/api/auth/register',payload:{name:'X',email:'x@example.test',password:PASSWORD}})).statusCode,201);
    f.admin.setRegistration(false);
    assert.equal((await f.app.inject({method:'POST',url:'/api/auth/register',payload:{name:'Y',email:'y@example.test',password:PASSWORD}})).statusCode,403);
    const events=(f.db.prepare('SELECT event,outcome FROM security_events WHERE seq IS NOT NULL ORDER BY seq').all() as any[]).map(r=>r.event+':'+r.outcome);
    assert.deepEqual(events,['auth.register:failure','admin.registration.enable:success','auth.register:success','admin.registration.disable:success','auth.register:failure']);
    assert.equal(new AuditLog(f.db).verify().ok,true);
  }finally{f.done();}
});

test('administrator-created users: validation, password change ends sessions, nothing secret audited',async()=>{
  const f=await fixture();
  try{
    await assert.rejects(()=>f.admin.create({email:'bad',name:'A',password:PASSWORD}),/Invalid email/);
    await assert.rejects(()=>f.admin.create({email:'a@example.test',name:'A',password:'short'}),/12-1024/);
    const user=await f.admin.create({email:' A@Example.test ',name:'Alice',password:PASSWORD});
    assert.equal(user.email,'a@example.test');
    await assert.rejects(()=>f.admin.create({email:'a@example.test',name:'A',password:PASSWORD}),/already exists/);
    const s=await login(f.app,'a@example.test'); assert.equal(s.status,200);
    const rt_1=f.store.oauthTokens().issueRefreshToken({familyId:randomUUID(),clientId:'c',subject:user.id,scope:'mcp',expires:Date.now()+60_000});
    await f.admin.setPassword('a@example.test','a brand new password');
    assert.equal((await f.app.inject({method:'GET',url:'/api/auth/session',headers:{cookie:s.cookie}})).statusCode,401,'old web session ended');
    assert.equal(f.store.oauthTokens().peekRefreshToken(rt_1),undefined,'refresh tokens revoked');
    assert.equal((await login(f.app,'a@example.test')).status,401);
    assert.equal((await login(f.app,'a@example.test','a brand new password')).status,200);
    const all=JSON.stringify(f.db.prepare('SELECT * FROM security_events').all());
    assert.ok(!all.includes(PASSWORD)&&!all.includes('a brand new password'));
    assert.deepEqual(f.admin.list().map(u=>[u.email,u.commands]),[['a@example.test',0]]);
  }finally{f.done();}
});

test('a disabled user is refused on every path and can be re-enabled',async()=>{
  const f=await fixture();
  try{
    const user=await f.admin.create({email:'d@example.test',name:'Dee',password:PASSWORD});
    new SqliteOAuthGrantStore(f.db).upsert(user.id,'https://client.example/c.json','Client',[1],false);
    const web=await login(f.app,'d@example.test');
    const rt_d=f.store.oauthTokens().issueRefreshToken({familyId:randomUUID(),clientId:'https://client.example/c.json',subject:user.id,scope:'mcp',expires:Date.now()+60_000});
    const access=await issueAccessToken(JWT,ISSUER,RESOURCE,user.id,'https://client.example/c.json','mcp');
    assert.match(await mcpHealth(f.app,access),/\\"ok\\": ?true|"ok": ?true/,'MCP works while active');
    const activeRefresh=await f.app.inject({method:'POST',url:'/oauth/token',payload:{grant_type:'refresh_token',refresh_token:rt_d,client_id:'https://client.example/c.json'}});
    assert.equal(activeRefresh.statusCode,200,'refresh works while active (control)');

    f.admin.setDisabled('d@example.test',true);
    const session=await f.app.inject({method:'GET',url:'/api/auth/session',headers:{cookie:web.cookie}});
    assert.equal(session.statusCode,401);
    const relogin=await login(f.app,'d@example.test'); assert.equal(relogin.status,403);
    assert.equal(f.store.oauthTokens().peekRefreshToken(rt_d),undefined,'refresh tokens revoked on disable');
    const rt_d2=f.store.oauthTokens().issueRefreshToken({familyId:randomUUID(),clientId:'https://client.example/c.json',subject:user.id,scope:'mcp',expires:Date.now()+60_000});
    const refresh=await f.app.inject({method:'POST',url:'/oauth/token',payload:{grant_type:'refresh_token',refresh_token:rt_d2,client_id:'https://client.example/c.json'}});
    assert.equal(refresh.statusCode,400); assert.equal(refresh.json().error,'invalid_grant');
    const mcp=await mcpHealth(f.app,access);
    assert.doesNotMatch(mcp,/"ok": ?true|\\"ok\\": ?true/); assert.match(mcp,/Authentication required/,'a still-valid access token is refused');

    f.admin.setDisabled('d@example.test',false);
    assert.equal((await login(f.app,'d@example.test')).status,200);
    assert.match(await mcpHealth(f.app,access),/"ok": ?true|\\"ok\\": ?true/);
    const events=(f.db.prepare("SELECT event FROM security_events WHERE event LIKE 'admin.%' ORDER BY seq").all() as any[]).map(r=>r.event);
    assert.deepEqual(events,['admin.user.create','admin.user.disable','admin.user.enable']);
  }finally{f.done();}
});

test('deleting a user removes their data but refuses while remote capabilities exist unless forced',async()=>{
  const f=await fixture();
  try{
    const user=await f.admin.create({email:'r@example.test',name:'Rem',password:PASSWORD});
    const other=await f.admin.create({email:'o@example.test',name:'Other',password:PASSWORD});
    const now=Date.now();
    for(const u of [user,other]){
      f.db.prepare('INSERT INTO ssh_keys (id,user_id,name,encrypted_private_key,created_at,updated_at) VALUES (?,?,?,?,?,?)').run(randomUUID(),u.id,'k','x',now,now);
      f.db.prepare("INSERT INTO commands (id,user_id,target_id,name,description,type,content,level,enabled,created_at,updated_at) VALUES (?,?,?,?,?,'shell','echo',1,1,?,?)").run(randomUUID(),u.id,'t','c','d',now,now);
    }
    f.db.prepare('INSERT INTO command_installations (id,user_id,command_id,target_id,master_key_id,encrypted_private_key,public_key,fingerprint,remote_script_path,authorized_key_line,installed_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)').run(randomUUID(),user.id,'c','t','m','x','ssh-ed25519 AAAA','fp','~/.ssh/farcmd/x.sh','line',now,now,now);
    await login(f.app,'r@example.test');
    assert.throws(()=>f.admin.delete('r@example.test'),/1 installed capability/);
    assert.ok(f.users.getUserByEmail('r@example.test'));
    const summary=f.admin.delete('r@example.test',true);
    assert.equal(summary.installedCapabilities,1);
    assert.equal(f.users.getUserByEmail('r@example.test'),undefined);
    for(const table of ['ssh_keys','commands','command_installations','web_sessions'])assert.equal((f.db.prepare('SELECT COUNT(*) AS n FROM '+table+' WHERE user_id=?').get(user.id) as any).n,0,table);
    assert.equal((f.db.prepare('SELECT COUNT(*) AS n FROM commands WHERE user_id=?').get(other.id) as any).n,1,'other users untouched');
    const deleted=f.db.prepare("SELECT details FROM security_events WHERE event='admin.user.delete'").get() as any;
    assert.equal(JSON.parse(deleted.details).installedCapabilitiesLeftOnHosts,1,'the audit trail survives deletion');
  }finally{f.done();}
});

test('farcmd-admin CLI: create, list, registration, password, delete; passwords never accepted as arguments',()=>{
  const dir=mkdtempSync(join(tmpdir(),'farcmd-cli-'));
  try{
    const env={...process.env,STORAGE_PATH:join(dir,'app.sqlite')};
    const cli=(args:string[],input?:string)=>spawnSync(process.execPath,['--import','tsx','src/cli/admin.ts',...args],{env,input,encoding:'utf8'});
    assert.equal(cli(['--help']).status,0);
    const created=cli(['user','create','--email','cli@example.test','--name','Cli User','--password-stdin'],PASSWORD+'\n');
    assert.equal(created.status,0,created.stderr); assert.match(created.stdout,/Created user cli@example.test/);
    assert.equal(cli(['user','create','--email','cli@example.test','--name','Again','--password-stdin'],PASSWORD+'\n').status,1);
    assert.match(cli(['user','list']).stdout,/cli@example.test  \|  Cli User  \|  active/);
    assert.equal(JSON.parse(cli(['user','list','--json']).stdout)[0].email,'cli@example.test');
    const withArg=cli(['user','create','--email','p@example.test','--name','P','--password',PASSWORD]);
    assert.equal(withArg.status,2); assert.match(withArg.stderr,/Unknown option '--password'/);
    const noTty=cli(['user','password','--email','cli@example.test'],'');
    assert.equal(noTty.status,2); assert.match(noTty.stderr,/--password-stdin/);
    assert.match(cli(['registration','status']).stdout,/disabled/);
    assert.match(cli(['registration','enable']).stdout,/ENABLED/);
    assert.equal(cli(['user','password','--email','cli@example.test','--password-stdin'],'another long password\n').status,0);
    assert.match(cli(['user','disable','--email','cli@example.test']).stdout,/Disabled/);
    assert.match(cli(['user','list']).stdout,/DISABLED/);
    assert.equal(cli(['user','delete','--email','cli@example.test']).status,1,'no confirmation without --yes in scripts');
    assert.equal(cli(['user','delete','--email','cli@example.test','--yes']).status,0);
    assert.equal(cli(['user','delete','--email','cli@example.test','--yes']).status,1);
    const store=new SqliteAuthStore(env.STORAGE_PATH);
    assert.equal(new SqliteSettingsStore(store.getDatabase()).registrationEnabled(),true);
    const audit=(store.getDatabase().prepare("SELECT event FROM security_events WHERE actor='system' ORDER BY seq").all() as any[]).map(r=>r.event);
    assert.deepEqual(audit,['admin.user.create','admin.registration.enable','admin.user.password','admin.user.disable','admin.user.delete']);
    assert.ok(!JSON.stringify(store.getDatabase().prepare('SELECT * FROM security_events').all()).includes('another long password'));
    const noKey=spawnSync(process.execPath,['--import','tsx','src/cli/admin.ts','user','list'],{env:{...env,FARCMD_ENCRYPTION_KEY:''},encoding:'utf8'});
    assert.equal(noKey.status,2); assert.match(noKey.stderr,/FARCMD_ENCRYPTION_KEY/);
  }finally{rmSync(dir,{recursive:true,force:true});}
});
