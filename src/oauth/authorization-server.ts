import type { FastifyInstance } from 'fastify';
import { verify } from '@node-rs/argon2';
import type { AuthStore, UserStore } from '../storage/interface.js';
import { fetchCimdMetadata, isCimdClientId } from './cimd.js';
import { randomToken, verifyS256 } from './pkce.js';
import { issueAccessToken } from './jwt.js';

const loginSessions=new Map<string,{userId:string;oauth:string;expires:number}>();
const LEVELS=[1,2,3,4,5] as const;

function escapeHtml(value:string):string{return value.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'","&#39;");}
function page(title:string,body:string):string{return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'+escapeHtml(title)+'</title><style>body{font-family:system-ui,sans-serif;background:#f6f7f9;margin:0;padding:4rem 1rem}main{max-width:520px;margin:0 auto;background:#fff;padding:2rem;border-radius:12px;box-shadow:0 8px 30px rgba(0,0,0,.08)}h1{margin-top:0}label{display:block;margin:.9rem 0 .35rem}input{margin-right:.5rem}button{margin-top:1rem;padding:.7rem 1.1rem;border:0;border-radius:7px;cursor:pointer}.secondary{margin-left:.5rem;background:#eee}.error{color:#b00020}.level{padding:.7rem 0;border-top:1px solid #eee}.muted{color:#666;font-size:.9rem}</style></head><body><main>'+body+'</main></body></html>';}
function loginPage(oauth:string,error?:string):string{return page('farcmd sign in','<h1>Sign in</h1><p>Sign in to authorize this MCP client.</p>'+(error?'<p class="error">'+escapeHtml(error)+'</p>':'')+'<form method="post" action="/oauth/authorize"><input type="hidden" name="oauth" value="'+escapeHtml(oauth)+'"><label for="email">Email</label><input id="email" name="email" type="email" autocomplete="username" required autofocus><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required><button type="submit">Sign in</button></form>');}
function consentPage(session:string,userName:string,clientName:string,current:number[],permanent5:boolean):string{
 const descriptions=['Safe/read-only operations','Low-impact operations','Normal mutating operations','High-impact operations','Dangerous/destructive operations'];
 const levels=LEVELS.map(level=>'<div class="level"><label><input type="checkbox" name="level" value="'+level+'" '+(current.includes(level)?'checked':'')+' '+(level===5&&permanent5?'disabled':'')+'>Level '+level+' — '+descriptions[level-1]+'</label></div>').join('');
 return page('Authorize farcmd','<h1>Authorize farcmd</h1><p><strong>'+escapeHtml(clientName)+'</strong> wants access as <strong>'+escapeHtml(userName)+'</strong>.</p><p>Select which command levels this OAuth source should show to the MCP client.</p><form method="post" action="/oauth/authorize"><input type="hidden" name="session" value="'+escapeHtml(session)+'">'+levels+(permanent5?'<p class="muted">Level 5 has been permanently hidden from this OAuth client.</p>':'<div class="level"><label><input type="checkbox" name="permanentLevel5" value="yes"> Permanently hide level 5 from this OAuth source</label></div>')+'<button type="submit" name="action" value="approve">Approve selected levels</button><button class="secondary" type="submit" name="action" value="deny">Deny</button></form>');
}
async function validateRequest(query:Record<string,string|undefined>){
 if(query.response_type!=='code'||!query.client_id||!query.redirect_uri||!query.code_challenge||query.code_challenge_method!=='S256')throw new Error('Invalid OAuth request');
 if(!isCimdClientId(query.client_id))throw new Error('Invalid client_id');
 const metadata=await fetchCimdMetadata(query.client_id);
 if(!metadata.redirect_uris.includes(query.redirect_uri))throw new Error('Invalid redirect_uri');
 return metadata;
}
function encodeOAuth(query:Record<string,string|undefined>):string{return Buffer.from(new URLSearchParams(Object.entries(query).filter((entry):entry is [string,string]=>typeof entry[1]==='string')).toString()).toString('base64url');}
function decodeOAuth(value:string):Record<string,string|undefined>{return Object.fromEntries(new URLSearchParams(Buffer.from(value,'base64url').toString('utf8')));}
function selectedLevels(body:Record<string,string|undefined|string[]>):number[]{const raw=body.level;const values=Array.isArray(raw)?raw:(raw?[raw]:[]);return [...new Set(values.map(Number))].filter(v=>LEVELS.includes(v as any));}

export async function mountAuthorizationServer(app:FastifyInstance,issuer:string,resource:string,secret:Uint8Array,authStore:AuthStore,users:UserStore):Promise<void>{
 app.get('/oauth/authorize',async(request,reply)=>{const q=request.query as Record<string,string|undefined>;try{await validateRequest(q);return reply.type('text/html').send(loginPage(encodeOAuth(q)));}catch{return reply.code(400).type('text/html').send(page('Invalid request','<h1>Invalid authorization request</h1>'));}});
 app.post('/oauth/authorize',async(request,reply)=>{
  const body=request.body as Record<string,string|undefined|string[]>;if(!body.oauth&&!body.session)return reply.code(400).type('text/html').send(page('Login required','<h1>Login required</h1>'));
  let q:Record<string,string|undefined>;let metadata:Awaited<ReturnType<typeof validateRequest>>;let userId:string;
  try{
   if(body.session){const session=loginSessions.get(body.session as string);if(!session||session.expires<Date.now())throw new Error('Expired login session');q=decodeOAuth(session.oauth);userId=session.userId;}
   else{q=decodeOAuth(body.oauth as string);if(!body.email||!body.password)throw new Error('Login required');const user=users.getUserByEmail(body.email as string);if(!user?.passwordHash||!(await verify(user.passwordHash,body.password as string)))return reply.code(401).type('text/html').send(loginPage(body.oauth as string,'Invalid email or password.'));userId=user.id;}
   metadata=await validateRequest(q);
  }catch{return reply.code(400).type('text/html').send(page('Invalid request','<h1>Invalid authorization request</h1>'));}
  const user=users.getUser(userId);if(!user)return reply.code(401).type('text/html').send(page('Invalid account','<h1>Invalid account</h1>'));
  if(body.action===undefined){const session=randomToken();loginSessions.set(session,{userId:user.id,oauth:body.oauth??loginSessions.get(body.session as string)!.oauth,expires:Date.now()+5*60_000});const grant=authStore.getOAuthGrant(user.id,q.client_id!);const levels=grant?.visibleLevels??[1,2,3];return reply.type('text/html').send(consentPage(session,user.name,metadata.client_name,levels,!!grant?.level5PermanentlyHidden));}
  if(!body.session)return reply.code(400).type('text/html').send(page('Invalid session','<h1>Invalid authorization session</h1>'));
  const session=loginSessions.get(body.session as string);if(!session||session.expires<Date.now())return reply.code(400).type('text/html').send(page('Expired session','<h1>Authorization session expired</h1>'));loginSessions.delete(body.session as string);
  const target=new URL(q.redirect_uri!);target.searchParams.set('iss',issuer);if(q.state)target.searchParams.set('state',q.state);
  if(body.action!=='approve'){target.searchParams.set('error','access_denied');return reply.redirect(target.toString());}
  const allowed=selectedLevels(body);const permanent5=body.permanentLevel5==='yes';const existing=authStore.getOAuthGrant(user.id,q.client_id!);
  if(existing?.level5PermanentlyHidden&&(!permanent5||allowed.includes(5))){return reply.code(400).type('text/html').send(page('Permission denied','<h1>Level 5 is permanently prohibited for this OAuth source.</h1>'));}
  if(permanent5&&allowed.includes(5))return reply.code(400).type('text/html').send(page('Invalid selection','<h1>Level 5 cannot be both allowed and permanently prohibited.</h1>'));
  authStore.upsertOAuthGrant(user.id,q.client_id!,metadata.client_name,allowed,permanent5||!!existing?.level5PermanentlyHidden);
  const code=randomToken();authStore.saveAuthorizationCode({code,clientId:q.client_id!,redirectUri:q.redirect_uri!,challenge:q.code_challenge!,subject:user.id,scope:q.scope??'mcp',expires:Date.now()+60_000});
  target.searchParams.set('code',code);return reply.redirect(target.toString());
 });
 app.post('/oauth/token',async(request,reply)=>{
  const b=request.body as Record<string,string|undefined>;
  if(b.grant_type==='authorization_code'){const code=b.code?authStore.consumeAuthorizationCode(b.code):undefined;const grant=code?authStore.getOAuthGrant(code.subject,code.clientId):undefined;if(!code||!grant||grant.revokedAt||b.client_id!==code.clientId||b.redirect_uri!==code.redirectUri||!b.code_verifier||!verifyS256(b.code_verifier,code.challenge))return reply.code(400).send({error:'invalid_grant'});authStore.touchOAuthGrant(code.subject,code.clientId);const access=await issueAccessToken(secret,issuer,resource,code.subject,code.clientId,code.scope);const refreshToken=randomToken();authStore.saveRefreshToken({token:refreshToken,clientId:code.clientId,subject:code.subject,scope:code.scope,expires:Date.now()+30*86_400_000});return {access_token:access,token_type:'Bearer',expires_in:3600,refresh_token:refreshToken,scope:code.scope};}
  if(b.grant_type==='refresh_token'){const refreshToken=b.refresh_token?authStore.getRefreshToken(b.refresh_token):undefined;const grant=refreshToken?authStore.getOAuthGrant(refreshToken.subject,refreshToken.clientId):undefined;if(!refreshToken||!grant||grant.revokedAt||b.client_id!==refreshToken.clientId)return reply.code(400).send({error:'invalid_grant'});authStore.touchOAuthGrant(refreshToken.subject,refreshToken.clientId);const access=await issueAccessToken(secret,issuer,resource,refreshToken.subject,refreshToken.clientId,refreshToken.scope);return {access_token:access,token_type:'Bearer',expires_in:3600,scope:refreshToken.scope};}
  return reply.code(400).send({error:'unsupported_grant_type'});
 });
}
