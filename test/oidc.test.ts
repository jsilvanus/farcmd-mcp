import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import formbody from '@fastify/formbody';
import { SqliteAuthStore, SqliteUserStore } from '../src/storage/sqlite.js';
import { isActiveUser } from '../src/storage/interface.js';
import { UserAdmin } from '../src/user-admin.js';
import { mountWebApi } from '../src/web-api.js';
import { mountAuthorizationServer } from '../src/oauth/authorization-server.js';
import { mountMcpHttp } from '../src/mcp/http.js';
import { FarcmdConnectorImpl } from '../src/connector.js';
import { OidcRelyingParty, oidcSettings, type OidcSettings } from '../src/oidc.js';
import { mountOidc } from '../src/oidc-routes.js';
import { asWebClient } from './web-client.js';
import { startFakeOidc } from './fake-oidc.js';

process.env.FARCMD_ENCRYPTION_KEY??=randomBytes(32).toString('base64');
const ISSUER='http://localhost:5999'; const RESOURCE=ISSUER+'/mcp'; const JWT=randomBytes(32);
const CLIENT_ID='farcmd'; const CLIENT_SECRET='s3cret';
// An MCP client identified by a client metadata document on a public IP literal; only its fetch is mocked.
const MCP_CLIENT='https://93.184.215.14/client.json'; const MCP_REDIRECT='https://93.184.215.14/cb';

async function fixture(overrides:Partial<OidcSettings>={},oidcOn=true){
  const idp=await startFakeOidc({clientId:CLIENT_ID,clientSecret:CLIENT_SECRET});
  const dir=mkdtempSync(join(tmpdir(),'farcmd-oidc-'));
  const store=new SqliteAuthStore(join(dir,'app.sqlite')); const db=store.getDatabase(); const users=new SqliteUserStore(db);
  const settings=oidcSettings({OIDC_ISSUER:idp.issuer,OIDC_CLIENT_ID:CLIENT_ID,OIDC_CLIENT_SECRET:CLIENT_SECRET,OIDC_BUTTON_LABEL:'Sign in with authentik'})!;
  Object.assign(settings,overrides);
  const label=oidcOn?{oidcButtonLabel:settings.buttonLabel}:{};
  const app=Fastify(); await app.register(formbody); await app.register(cookie); asWebClient(app);
  await mountWebApi(app,users,store,ISSUER,label);
  await mountAuthorizationServer(app,ISSUER,RESOURCE,JWT,store,users,label);
  if(oidcOn)await mountOidc(app,new OidcRelyingParty(settings,ISSUER+'/oidc/callback',db),users,store,ISSUER);
  await mountMcpHttp(app,{connector:new FarcmdConnectorImpl(db,ISSUER),publicUrl:ISSUER,jwtSecret:JWT,resource:RESOURCE,isUserActive:id=>isActiveUser(users.getUser(id))});
  const realFetch=globalThis.fetch;
  globalThis.fetch=(async(input:any,init?:any)=>String(input)===MCP_CLIENT?new Response(JSON.stringify({client_id:MCP_CLIENT,client_name:'Test client',redirect_uris:[MCP_REDIRECT]}),{headers:{'content-type':'application/json'}}):realFetch(input,init)) as typeof fetch;
  return {idp,app,db,users,admin:new UserAdmin(db),done:async()=>{globalThis.fetch=realFetch;await app.close();await idp.close();rmSync(dir,{recursive:true,force:true});}};
}

/** Browser round trip: farcmd -> provider -> farcmd callback. Returns the callback response and the state cookie used. */
async function signIn(app:any,startPath:string,tamper?:(state:string)=>string){
  const start=await app.inject({method:'GET',url:startPath});
  assert.equal(start.statusCode,302,start.body);
  const state=start.cookies.find((c:any)=>c.name==='farcmd_oidc')!;
  assert.equal(state.httpOnly,true); assert.equal(state.sameSite,'Lax'); assert.equal(state.path,'/oidc');
  const atProvider=await fetch(String(start.headers.location),{redirect:'manual'});
  assert.equal(atProvider.status,302);
  const callback=new URL(atProvider.headers.get('location')!);
  assert.equal(callback.origin+callback.pathname,ISSUER+'/oidc/callback');
  const url=callback.pathname+callback.search;
  const response=await app.inject({method:'GET',url,cookies:{farcmd_oidc:tamper?tamper(state.value):state.value}});
  return {response,url,state:state.value};
}
const sessionCookie=(r:any)=>{const c=r.cookies.find((c:any)=>c.name==='farcmd_session');return c?{farcmd_session:c.value}:undefined;};

test('OIDC settings come from the environment and are validated at startup',()=>{
  assert.equal(oidcSettings({}),undefined,'off without OIDC_ISSUER');
  assert.equal(oidcSettings({OIDC_ISSUER:'  ',OIDC_CLIENT_ID:'x'}),undefined);
  assert.throws(()=>oidcSettings({OIDC_ISSUER:'https://idp.example/'}),/OIDC_CLIENT_ID is required/);
  assert.throws(()=>oidcSettings({OIDC_ISSUER:'not a url',OIDC_CLIENT_ID:'x'}),/absolute URL/);
  assert.throws(()=>oidcSettings({OIDC_ISSUER:'http://idp.example/',OIDC_CLIENT_ID:'x',NODE_ENV:'production'}),/https/);
  assert.throws(()=>oidcSettings({OIDC_ISSUER:'https://idp.example/',OIDC_CLIENT_ID:'x',OIDC_SCOPES:'email'}),/openid/);
  assert.throws(()=>oidcSettings({OIDC_ISSUER:'https://idp.example/',OIDC_CLIENT_ID:'x',OIDC_CREATE_USERS:'yes'}),/OIDC_CREATE_USERS/);
  const s=oidcSettings({OIDC_ISSUER:'https://auth.example.org/application/o/farcmd/',OIDC_CLIENT_ID:'x'})!;
  assert.equal(s.issuer.href,'https://auth.example.org/application/o/farcmd/','the issuer is kept exactly, trailing slash included');
  assert.equal(s.scopes,'openid email profile'); assert.equal(s.buttonLabel,'Sign in with single sign-on');
  assert.equal(s.createUsers,false); assert.equal(s.trustEmail,false); assert.equal(s.clientSecret,undefined);
});

test('with OIDC off there is no single sign-on option anywhere',async()=>{
  const f=await fixture({},false);
  try{
    assert.equal((await f.app.inject({method:'GET',url:'/api/auth/config'})).json().oidc,undefined);
    assert.equal((await f.app.inject({method:'GET',url:'/oidc/login'})).statusCode,404);
    assert.equal((await f.app.inject({method:'GET',url:'/oidc/callback?code=x&state=y'})).statusCode,404);
    const q=new URLSearchParams({response_type:'code',client_id:MCP_CLIENT,redirect_uri:MCP_REDIRECT,code_challenge:'x',code_challenge_method:'S256'});
    const page=await f.app.inject({method:'GET',url:'/oauth/authorize?'+q});
    assert.equal(page.statusCode,200); assert.doesNotMatch(page.body,/oidc/);
  }finally{await f.done();}
});

test('web sign-in through the provider links an existing account by verified email, then by subject',async()=>{
  const f=await fixture();
  try{
    assert.deepEqual((await f.app.inject({method:'GET',url:'/api/auth/config'})).json().oidc,{label:'Sign in with authentik',url:'/oidc/login'});
    await f.admin.create({email:'person@example.test',name:'Person',password:'correct horse battery staple'});
    const {response}=await signIn(f.app,'/oidc/login');
    assert.equal(response.statusCode,302,response.body); assert.equal(response.headers.location,'/');
    const session=await f.app.inject({method:'GET',url:'/api/auth/session',cookies:sessionCookie(response)});
    assert.equal(session.json().user.email,'person@example.test');
    // Later the provider reports another email: the account is found by the linked subject.
    f.idp.state.nextUser={sub:'user-1',email:'renamed@example.test',email_verified:true};
    const again=(await signIn(f.app,'/oidc/login')).response;
    assert.equal((await f.app.inject({method:'GET',url:'/api/auth/session',cookies:sessionCookie(again)})).json().user.email,'person@example.test');
    const events=(f.db.prepare("SELECT outcome,details FROM security_events WHERE event='auth.oidc_login' ORDER BY seq").all() as any[]);
    assert.deepEqual(events.map(e=>[e.outcome,JSON.parse(e.details).linked]),[['success','email'],['success','existing']]);
  }finally{await f.done();}
});

test('an unverified email is not linked unless OIDC_TRUST_EMAIL; unknown users get an account only with OIDC_CREATE_USERS',async()=>{
  for(const [overrides,expectCreated] of [[{},false],[{createUsers:true},true]] as const){
    const f=await fixture(overrides);
    try{
      await f.admin.create({email:'person@example.test',name:'Person',password:'correct horse battery staple'});
      f.idp.state.nextUser={sub:'other',email:'person@example.test',email_verified:false,name:'Mallory'};
      const {response}=await signIn(f.app,'/oidc/login');
      if(!expectCreated){assert.equal(response.statusCode,403);assert.match(response.body,/no farcmd account/);assert.equal(sessionCookie(response),undefined);continue;}
      assert.equal(response.statusCode,302);
      const user=(await f.app.inject({method:'GET',url:'/api/auth/session',cookies:sessionCookie(response)})).json().user;
      assert.equal(user.name,'Mallory'); assert.equal(user.email,undefined,'the unverified email is not taken over');
      assert.equal(f.users.listUsers().length,2);
    }finally{await f.done();}
  }
  const f=await fixture({trustEmail:true});
  try{
    await f.admin.create({email:'person@example.test',name:'Person',password:'correct horse battery staple'});
    f.idp.state.nextUser={sub:'other',email:'person@example.test',email_verified:false};
    const {response}=await signIn(f.app,'/oidc/login');
    assert.equal((await f.app.inject({method:'GET',url:'/api/auth/session',cookies:sessionCookie(response)})).json().user.name,'Person');
  }finally{await f.done();}
});

test('email from userinfo is used when the ID token has none',async()=>{
  const f=await fixture();
  try{
    await f.admin.create({email:'person@example.test',name:'Person',password:'correct horse battery staple'});
    f.idp.state.idTokenOmitsEmail=true;
    const {response}=await signIn(f.app,'/oidc/login');
    assert.equal(response.statusCode,302,response.body);
  }finally{await f.done();}
});

test('the callback needs this browser\'s state cookie, is single use and refuses a wrong nonce or a disabled account',async()=>{
  const f=await fixture();
  try{
    await f.admin.create({email:'person@example.test',name:'Person',password:'correct horse battery staple'});
    const forged=await signIn(f.app,'/oidc/login',()=>'someone-else');
    assert.equal(forged.response.statusCode,400); assert.equal(sessionCookie(forged.response),undefined);
    const ok=await signIn(f.app,'/oidc/login');
    assert.equal(ok.response.statusCode,302);
    const replay=await f.app.inject({method:'GET',url:ok.url,cookies:{farcmd_oidc:ok.state}});
    assert.equal(replay.statusCode,400,'a state is used once');
    f.idp.state.nonceOverride='wrong';
    assert.equal((await signIn(f.app,'/oidc/login')).response.statusCode,400);
    f.idp.state.nonceOverride=undefined;
    f.admin.setDisabled('person@example.test',true);
    const disabled=(await signIn(f.app,'/oidc/login')).response;
    assert.equal(disabled.statusCode,403); assert.match(disabled.body,/disabled/);
    const failures=(f.db.prepare("SELECT COUNT(*) AS n FROM security_events WHERE event='auth.oidc_login' AND outcome='failure'").get() as any).n;
    assert.equal(failures,4,"forged state, replay, wrong nonce, disabled account");
  }finally{await f.done();}
});

test('MCP authorization through the provider ends with consent and a working /mcp token',async()=>{
  const f=await fixture();
  try{
    await f.admin.create({email:'person@example.test',name:'Person',password:'correct horse battery staple'});
    const verifier=randomBytes(32).toString('base64url');
    const q=new URLSearchParams({response_type:'code',client_id:MCP_CLIENT,redirect_uri:MCP_REDIRECT,code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256',state:'client-state'});
    const page=await f.app.inject({method:'GET',url:'/oauth/authorize?'+q});
    const link=/href="(\/oidc\/login\?oauth=[^"]+)"/.exec(page.body);
    assert.ok(link,'the sign-in page offers single sign-on'); assert.match(page.body,/Sign in with authentik/);
    assert.equal((await f.app.inject({method:'GET',url:'/oidc/login?oauth=bm9wZQ'})).statusCode,400,'an invalid authorization request is refused before leaving farcmd');
    const {response:consent}=await signIn(f.app,link[1]!.replaceAll('&amp;','&'));
    assert.equal(consent.statusCode,200,consent.body);
    assert.match(consent.body,/Authorize farcmd/); assert.match(consent.body,/as <strong>Person<\/strong>/);
    assert.match(String(consent.headers['content-security-policy']),/form-action 'self' https:\/\/93\.184\.215\.14/);
    assert.equal(sessionCookie(consent),undefined,'signing in for an MCP client opens no web session');
    const session=/name="session" value="([^"]+)"/.exec(consent.body)![1]!;
    const approve=await f.app.inject({method:'POST',url:'/oauth/authorize',payload:{session,action:'approve',level:'1'}});
    assert.equal(approve.statusCode,302,approve.body);
    const back=new URL(String(approve.headers.location)); assert.equal(back.searchParams.get('state'),'client-state');
    const token=await f.app.inject({method:'POST',url:'/oauth/token',payload:{grant_type:'authorization_code',code:back.searchParams.get('code')!,code_verifier:verifier,client_id:MCP_CLIENT,redirect_uri:MCP_REDIRECT}});
    assert.equal(token.statusCode,200,token.body);
    const mcp=await f.app.inject({method:'POST',url:'/mcp',headers:{authorization:'Bearer '+token.json().access_token,accept:'application/json, text/event-stream','content-type':'application/json'},payload:{jsonrpc:'2.0',id:1,method:'tools/call',params:{name:'farcmd_health',arguments:{}}}});
    assert.equal(mcp.statusCode,200); assert.match(mcp.body,/"structuredContent":\{"ok":true\}/);
    const audited=f.db.prepare("SELECT details FROM security_events WHERE event='oauth.login' ORDER BY seq DESC").get() as any;
    assert.match(audited.details,/"method":"oidc"/);
  }finally{await f.done();}
});
