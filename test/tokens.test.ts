import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import Fastify from 'fastify';
import formbody from '@fastify/formbody';
import { SqliteAuthStore, SqliteUserStore } from '../src/storage/sqlite.js';
import { mountAuthorizationServer } from '../src/oauth/authorization-server.js';
import { SqliteOAuthGrantStore } from '../src/oauth/grants.js';
import { hashToken, REFRESH_TOKEN_LIFETIME_MS } from '../src/oauth/tokens.js';

process.env.FARCMD_ENCRYPTION_KEY??=randomBytes(32).toString('base64');
const ISSUER='http://localhost:5999'; const CLIENT='https://client.example/c.json'; const REDIRECT='https://client.example/cb';

async function fixture(path?:string){
  const dir=path??mkdtempSync(join(tmpdir(),'farcmd-tokens-'));
  const store=new SqliteAuthStore(join(dir,'app.sqlite')); const db=store.getDatabase(); const users=new SqliteUserStore(db);
  const app=Fastify(); await app.register(formbody); await mountAuthorizationServer(app,ISSUER,ISSUER+'/mcp',randomBytes(32),store,users);
  const userId=randomUUID(); users.createUser({id:userId,name:'U',email:userId+'@example.test',createdAt:Date.now()});
  new SqliteOAuthGrantStore(db).upsert(userId,CLIENT,'Client',[1],false);
  const tokens=store.oauthTokens();
  const newCode=()=>{const verifier=randomBytes(32).toString('base64url');const code=randomBytes(24).toString('base64url');
    tokens.saveAuthorizationCode(code,{clientId:CLIENT,redirectUri:REDIRECT,challenge:createHash('sha256').update(verifier).digest('base64url'),subject:userId,scope:'mcp',expires:Date.now()+60_000});return {code,verifier};};
  const post=(payload:Record<string,string>)=>app.inject({method:'POST',url:'/oauth/token',payload});
  const exchange=(c:{code:string;verifier:string})=>post({grant_type:'authorization_code',code:c.code,code_verifier:c.verifier,client_id:CLIENT,redirect_uri:REDIRECT});
  const refresh=(token:string,clientId=CLIENT)=>post({grant_type:'refresh_token',refresh_token:token,client_id:clientId});
  const events=()=>(db.prepare("SELECT event,outcome FROM security_events WHERE event LIKE 'oauth.%' ORDER BY seq").all() as any[]).map(r=>r.event+':'+r.outcome);
  return {dir,store,db,userId,tokens,newCode,exchange,refresh,events,done:()=>{if(!path)rmSync(dir,{recursive:true,force:true});}};
}

test('codes and refresh tokens are stored only as hashes',async()=>{
  const f=await fixture();
  try{
    const c=f.newCode(); const r=await f.exchange(c); assert.equal(r.statusCode,200,r.body);
    const refreshToken=r.json().refresh_token as string;
    const dump=JSON.stringify([f.db.prepare('SELECT * FROM refresh_tokens').all(),f.db.prepare('SELECT * FROM authorization_codes').all()]);
    assert.ok(!dump.includes(refreshToken)&&!dump.includes(c.code),'no plaintext token or code in the database');
    assert.ok(dump.includes(hashToken(refreshToken))&&dump.includes(hashToken(c.code)));
  }finally{f.done();}
});

test('refresh tokens rotate; reusing a used token revokes the whole family',async()=>{
  const f=await fixture();
  try{
    const r0=(await f.exchange(f.newCode())).json(); const t1=r0.refresh_token as string;
    const expires=f.tokens.peekRefreshToken(t1)!.expires;
    const r1=await f.refresh(t1); assert.equal(r1.statusCode,200,r1.body);
    const t2=r1.json().refresh_token as string; assert.ok(t2&&t2!==t1,'a new refresh token is issued');
    assert.equal(f.tokens.peekRefreshToken(t2)!.expires,expires,'absolute lifetime: rotation does not extend the family');
    assert.ok(Math.abs(expires-(Date.now()+REFRESH_TOKEN_LIFETIME_MS))<60_000);
    const t3=(await f.refresh(t2)).json().refresh_token as string;
    // An attacker replays the stolen t1: refused, and every live token in the family is revoked.
    const replay=await f.refresh(t1); assert.equal(replay.statusCode,400); assert.equal(replay.json().error,'invalid_grant');
    assert.equal((await f.refresh(t3)).statusCode,400,'the legitimate client\'s current token was revoked too');
    assert.ok(f.events().includes('oauth.refresh_token_reuse:failure'));
    // A new authorization starts a fresh family that works independently.
    const fresh=(await f.exchange(f.newCode())).json().refresh_token as string;
    assert.equal((await f.refresh(fresh)).statusCode,200);
  }finally{f.done();}
});

test('authorization codes are single use; a second redemption revokes what the first produced',async()=>{
  const f=await fixture();
  try{
    const c=f.newCode(); const first=await f.exchange(c); assert.equal(first.statusCode,200);
    const second=await f.exchange(c); assert.equal(second.statusCode,400);
    assert.equal((await f.refresh(first.json().refresh_token)).statusCode,400,'tokens from the reused code are revoked');
    assert.ok(f.events().includes('oauth.code_reuse:failure'));
  }finally{f.done();}
});

test('a mismatched client or revoked grant does not consume or use the token',async()=>{
  const f=await fixture();
  try{
    const t=(await f.exchange(f.newCode())).json().refresh_token as string;
    assert.equal((await f.refresh(t,'https://evil.example/c.json')).statusCode,400);
    const ok=await f.refresh(t); assert.equal(ok.statusCode,200,'the wrong client did not burn the token');
    new SqliteOAuthGrantStore(f.db).revoke(f.userId,CLIENT);
    assert.equal(f.tokens.peekRefreshToken(ok.json().refresh_token),undefined,'revoking the grant deletes its refresh tokens');
    assert.equal((await f.refresh(ok.json().refresh_token)).statusCode,400);
  }finally{f.done();}
});

test('expired refresh tokens and codes are refused',async()=>{
  const f=await fixture();
  try{
    const t=(await f.exchange(f.newCode())).json().refresh_token as string;
    f.db.prepare('UPDATE refresh_tokens SET expires=?').run(Date.now()-1);
    assert.equal((await f.refresh(t)).statusCode,400);
    const c=f.newCode(); f.db.prepare('UPDATE authorization_codes SET expires=? WHERE code=?').run(Date.now()-1,hashToken(c.code));
    assert.equal((await f.exchange(c)).statusCode,400);
  }finally{f.done();}
});

test('migration hashes existing plaintext refresh tokens without breaking connected clients',async()=>{
  const dir=mkdtempSync(join(tmpdir(),'farcmd-tokens-legacy-'));
  try{
    const f=await fixture(dir);
    // Simulate rows written by the previous version (plaintext token, no family).
    const legacy=randomBytes(32).toString('base64url');
    f.db.prepare('INSERT INTO refresh_tokens (token,client_id,subject,scope,expires) VALUES (?,?,?,?,?)').run(legacy,CLIENT,f.userId,'mcp',Date.now()+86_400_000);
    f.db.prepare('INSERT INTO authorization_codes (code,client_id,redirect_uri,challenge,subject,scope,expires) VALUES (?,?,?,?,?,?,?)').run('legacy-code',CLIENT,REDIRECT,'x',f.userId,'mcp',Date.now()+60_000);
    const restarted=new SqliteAuthStore(join(dir,'app.sqlite')); // migrations run on startup
    const db=restarted.getDatabase();
    const rows=JSON.stringify(db.prepare('SELECT * FROM refresh_tokens').all());
    assert.ok(!rows.includes(legacy)&&rows.includes(hashToken(legacy)),'plaintext replaced by its hash');
    assert.equal((db.prepare("SELECT COUNT(*) AS n FROM authorization_codes WHERE code='legacy-code'").get() as any).n,0,'unhashed codes dropped');
    const r=await f.refresh(legacy); assert.equal(r.statusCode,200,'the legacy token still works once, then rotates');
    assert.equal((await f.refresh(legacy)).statusCode,400);
    new SqliteAuthStore(join(dir,'app.sqlite'));
    assert.equal((db.prepare('SELECT COUNT(*) AS n FROM refresh_tokens WHERE family_id IS NULL').get() as any).n,0,'migration is idempotent');
  }finally{rmSync(dir,{recursive:true,force:true});}
});

test('authorization flow: sign-in session is kept in SQLite, survives a restart and is single use',async()=>{
  const dir=mkdtempSync(join(tmpdir(),'farcmd-authorize-'));
  // Client metadata document of a client on a public IP literal (no DNS needed); only its fetch is mocked.
  const client='https://93.184.215.14/client.json'; const redirect='https://93.184.215.14/cb';
  const realFetch=globalThis.fetch;
  globalThis.fetch=(async(input:any,init?:any)=>String(input)===client?new Response(JSON.stringify({client_id:client,client_name:'Test client',redirect_uris:[redirect]}),{headers:{'content-type':'application/json'}}):realFetch(input,init)) as typeof fetch;
  try{
    const f=await fixture(dir);
    const password='correct horse battery staple';
    const { UserAdmin }=await import('../src/user-admin.js');
    await new UserAdmin(f.db).create({email:'o@example.test',name:'O',password});
    const verifier=randomBytes(32).toString('base64url');
    const oauth=Buffer.from(new URLSearchParams({response_type:'code',client_id:client,redirect_uri:redirect,code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256',state:'s1'}).toString()).toString('base64url');
    const app1=Fastify(); await app1.register(formbody); await mountAuthorizationServer(app1,ISSUER,ISSUER+'/mcp',randomBytes(32),f.store,new SqliteUserStore(f.db));
    const signIn=await app1.inject({method:'POST',url:'/oauth/authorize',payload:{oauth,email:'o@example.test',password}});
    assert.equal(signIn.statusCode,200,signIn.body);
    const session=/name="session" value="([^"]+)"/.exec(signIn.body)![1]!;
    assert.equal((f.db.prepare('SELECT COUNT(*) AS n FROM oauth_login_sessions').get() as any).n,1);
    assert.ok(!JSON.stringify(f.db.prepare('SELECT * FROM oauth_login_sessions').all()).includes(session),'only the hash is stored');
    // The server restarts between sign-in and consent: a fresh process (app2) still knows the session.
    const restarted=new SqliteAuthStore(join(dir,'app.sqlite'));
    const app2=Fastify(); await app2.register(formbody); await mountAuthorizationServer(app2,ISSUER,ISSUER+'/mcp',randomBytes(32),restarted,new SqliteUserStore(restarted.getDatabase()));
    const approve=await app2.inject({method:'POST',url:'/oauth/authorize',payload:{session,action:'approve',level:'1'}});
    assert.equal(approve.statusCode,302,approve.body);
    const location=new URL(String(approve.headers.location)); assert.equal(location.searchParams.get('state'),'s1'); assert.ok(location.searchParams.get('code'));
    const again=await app2.inject({method:'POST',url:'/oauth/authorize',payload:{session,action:'approve',level:'1'}});
    assert.equal(again.statusCode,400,'the sign-in session is single use');
    const token=await app2.inject({method:'POST',url:'/oauth/token',payload:{grant_type:'authorization_code',code:location.searchParams.get('code')!,code_verifier:verifier,client_id:client,redirect_uri:redirect}});
    assert.equal(token.statusCode,200,token.body);
    // Expired sessions are refused and purged.
    f.tokens.saveLoginSession('old',{userId:f.userId,oauth,expires:Date.now()-1});
    assert.equal(f.tokens.getLoginSession('old'),undefined); f.tokens.cleanup();
    assert.equal((f.db.prepare('SELECT COUNT(*) AS n FROM oauth_login_sessions').get() as any).n,0);
    f.done();
  }finally{globalThis.fetch=realFetch;rmSync(dir,{recursive:true,force:true});}
});
