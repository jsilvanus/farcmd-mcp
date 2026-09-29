import type { DatabaseSync } from 'node:sqlite';
import type { FastifyInstance, FastifyReply } from 'fastify';
import { AuditLog } from './audit.js';
import { rateLimit } from './login-rate-limit.js';
import { decodeOAuth, escapeHtml, page, showConsent, validateRequest } from './oauth/authorization-server.js';
import { OIDC_STATE_LIFETIME_MS, OidcError, type OidcPurpose, type OidcRelyingParty } from './oidc.js';
import { isActiveUser, type AuthStore, type UserStore, type WebSessionStore } from './storage/interface.js';
import { WebSessionService } from './web-session.js';
import { webSessionCookieOptions } from './web-api.js';

const STATE_COOKIE='farcmd_oidc';

function errorPage(reply:FastifyReply,status:number,message:string,purpose?:OidcPurpose){
  const next=purpose?.kind==='oauth'?'<p>Start the connection again from your MCP client.</p>':'<p><a href="/">Back to sign in</a></p>';
  return reply.code(status).type('text/html').send(page('Sign-in failed','<h1>Sign-in failed</h1><p class="error">'+escapeHtml(message)+'</p>'+next));
}

/**
 * OIDC sign-in routes (mounted only when OIDC_ISSUER is set):
 *   GET /oidc/login              web UI sign-in
 *   GET /oidc/login?oauth=...    sign-in for a pending MCP OAuth authorization request (from /oauth/authorize)
 *   GET /oidc/callback           the provider's redirect_uri; continues to a web session or to the OAuth consent page
 */
export async function mountOidc(app:FastifyInstance,rp:OidcRelyingParty,users:UserStore,store:AuthStore&WebSessionStore&{getDatabase():DatabaseSync},publicUrl:string):Promise<void>{
  const sessions=new WebSessionService(store);
  const audit=new AuditLog(store.getDatabase());
  const production=process.env.NODE_ENV==='production';

  app.get('/oidc/login',async(request,reply)=>{
    if(!rateLimit('oidc:'+request.ip,30,15*60_000))return errorPage(reply,429,'Too many sign-in attempts. Try again later.');
    const oauth=(request.query as Record<string,unknown>).oauth;
    let purpose:OidcPurpose={kind:'web'};
    if(oauth!==undefined){
      if(typeof oauth!=='string')return errorPage(reply,400,'Invalid authorization request.');
      try{await validateRequest(decodeOAuth(oauth));}catch{return errorPage(reply,400,'Invalid authorization request.');}
      purpose={kind:'oauth',oauth};
    }
    let started:{url:URL;state:string};
    try{started=await rp.start(purpose);}
    catch(error){request.log.warn({err:error instanceof Error?error.message:String(error)},'OIDC provider unavailable');return errorPage(reply,503,'The sign-in service cannot be reached right now. Try again later.',purpose);}
    reply.setCookie(STATE_COOKIE,started.state,{httpOnly:true,secure:production,sameSite:'lax',path:'/oidc',maxAge:OIDC_STATE_LIFETIME_MS/1000});
    return reply.redirect(started.url.toString());
  });

  app.get('/oidc/callback',async(request,reply)=>{
    const cookieState=request.cookies?.[STATE_COOKIE];
    reply.clearCookie(STATE_COOKIE,{path:'/oidc'});
    // The provider redirected to <publicUrl>/oidc/callback; rebuild that URL (the app may sit behind a proxy).
    const callbackUrl=new URL(request.url,publicUrl);
    let result:Awaited<ReturnType<OidcRelyingParty['finish']>>;
    try{result=await rp.finish(callbackUrl,cookieState);}
    catch(error){
      const purpose=error instanceof OidcError?error.purpose:undefined;
      const reason=error instanceof Error?error.message.slice(0,200):'sign-in failed';
      request.log.warn({reason},'OIDC sign-in failed');
      audit.record({event:'auth.oidc_login',actor:purpose?.kind==='oauth'?'oauth':'web',outcome:'failure',ip:request.ip,details:{reason}});
      return errorPage(reply,400,'The sign-in could not be completed. Please try again.',purpose);
    }
    const {purpose,identity}=result;
    const resolved=rp.resolveUser(identity,users);
    if('error' in resolved){
      audit.record({event:'auth.oidc_login',actor:purpose.kind==='oauth'?'oauth':'web',outcome:'failure',ip:request.ip,details:{reason:'no account',issuer:identity.issuer}});
      return errorPage(reply,403,resolved.error,purpose);
    }
    const user=resolved.user;
    if(!isActiveUser(users.getUser(user.id))){
      audit.record({event:'auth.oidc_login',actor:purpose.kind==='oauth'?'oauth':'web',outcome:'failure',userId:user.id,ip:request.ip,targetType:'user',targetId:user.id,details:{reason:'account disabled'}});
      return errorPage(reply,403,'This account is disabled.',purpose);
    }
    if(purpose.kind==='web'){
      audit.record({event:'auth.oidc_login',actor:'web',outcome:'success',userId:user.id,ip:request.ip,targetType:'user',targetId:user.id,details:{linked:resolved.linked}});
      reply.setCookie('farcmd_session',sessions.create(user.id),webSessionCookieOptions());
      return reply.redirect('/');
    }
    const q=decodeOAuth(purpose.oauth);
    let metadata:Awaited<ReturnType<typeof validateRequest>>;
    try{metadata=await validateRequest(q);}catch{return errorPage(reply,400,'Invalid authorization request.',purpose);}
    store.recordSecurityEvent?.(user.id,q.client_id,'oauth.login',{method:'oidc',linked:resolved.linked,ip:request.ip});
    return showConsent(reply,store,user,purpose.oauth,q,metadata);
  });
}
