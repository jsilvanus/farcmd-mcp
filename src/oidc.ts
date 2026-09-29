import * as client from 'openid-client';
import { createHash } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import type { McpUser, UserStore } from './storage/interface.js';
import { EMAIL_PATTERN, MAX_EMAIL_LENGTH, normalizeEmail } from './user-admin.js';

/**
 * OpenID Connect sign-in: farcmd is a Relying Party of an external OIDC provider (e.g. authentik).
 * It sends the browser to the provider and verifies the ID token it gets back; it never issues ID tokens itself.
 * The provider only replaces the password check: web sessions, OAuth grants for MCP clients and the /mcp
 * access tokens stay farcmd's own. OIDC is off (no button, no /oidc routes) unless OIDC_ISSUER is set.
 */
export interface OidcSettings {
  issuer:URL;
  clientId:string;
  clientSecret?:string;
  scopes:string;
  buttonLabel:string;
  /** Create a farcmd account for a provider user who has none (OIDC_CREATE_USERS). */
  createUsers:boolean;
  /** Link to an existing account by email even when the provider does not mark it verified (OIDC_TRUST_EMAIL). */
  trustEmail:boolean;
}

function envBool(env:NodeJS.ProcessEnv,name:string):boolean{
  const raw=(env[name]??'').trim(); if(raw===''||raw==='false')return false; if(raw==='true')return true;
  throw new Error(name+' must be "true" or "false"');
}

/** OIDC settings from the environment, or undefined when OIDC_ISSUER is unset. Throws on an incomplete or unsafe configuration. */
export function oidcSettings(env:NodeJS.ProcessEnv=process.env):OidcSettings|undefined{
  const rawIssuer=(env.OIDC_ISSUER??'').trim(); if(!rawIssuer)return undefined;
  let issuer:URL; try{issuer=new URL(rawIssuer);}catch{throw new Error('OIDC_ISSUER must be an absolute URL');}
  if(issuer.protocol!=='https:'&&!(issuer.protocol==='http:'&&env.NODE_ENV!=='production'))throw new Error('OIDC_ISSUER must use https:// (http:// is allowed only outside production)');
  const clientId=(env.OIDC_CLIENT_ID??'').trim(); if(!clientId)throw new Error('OIDC_CLIENT_ID is required when OIDC_ISSUER is set');
  const scopes=(env.OIDC_SCOPES??'').trim()||'openid email profile';
  if(!scopes.split(/\s+/).includes('openid'))throw new Error('OIDC_SCOPES must include "openid"');
  const clientSecret=env.OIDC_CLIENT_SECRET||undefined;
  return {issuer,clientId,...(clientSecret?{clientSecret}:{}),scopes,buttonLabel:(env.OIDC_BUTTON_LABEL??'').trim()||'Sign in with single sign-on',createUsers:envBool(env,'OIDC_CREATE_USERS'),trustEmail:envBool(env,'OIDC_TRUST_EMAIL')};
}

/** Where a sign-in continues after the provider: the web UI, or a pending MCP OAuth authorization request (encoded). */
export type OidcPurpose={kind:'web'}|{kind:'oauth';oauth:string};
export interface OidcIdentity { issuer:string; subject:string; email?:string; emailVerified:boolean; name?:string; }
export type OidcUserResult={user:McpUser;linked:'existing'|'email'|'created'}|{error:string};

/** How long the browser has to come back from the provider. */
export const OIDC_STATE_LIFETIME_MS=10*60_000;
const hashState=(state:string)=>createHash('sha256').update(state).digest('hex');

export class OidcRelyingParty {
  private configuration:Promise<client.Configuration>|undefined;
  constructor(readonly settings:OidcSettings, readonly redirectUri:string, private readonly db:DatabaseSync){
    db.exec('CREATE TABLE IF NOT EXISTS oidc_login_states (state_hash TEXT PRIMARY KEY,code_verifier TEXT NOT NULL,nonce TEXT NOT NULL,purpose TEXT NOT NULL,expires INTEGER NOT NULL);'+
      'CREATE TABLE IF NOT EXISTS oidc_identities (issuer TEXT NOT NULL,subject TEXT NOT NULL,user_id TEXT NOT NULL,created_at INTEGER NOT NULL,last_login_at INTEGER NOT NULL,PRIMARY KEY(issuer,subject));'+
      'CREATE INDEX IF NOT EXISTS oidc_identities_user ON oidc_identities(user_id);');
  }

  /** Provider metadata, discovered on first use. A failed discovery is retried on the next sign-in, so startup does not depend on the provider. */
  config():Promise<client.Configuration>{
    if(!this.configuration){
      const {issuer,clientId,clientSecret}=this.settings;
      const insecure=issuer.protocol==='http:';
      this.configuration=client.discovery(issuer,clientId,clientSecret,clientSecret?client.ClientSecretBasic(clientSecret):client.None(),insecure?{execute:[client.allowInsecureRequests]}:undefined);
      this.configuration.catch(()=>{this.configuration=undefined;});
    }
    return this.configuration;
  }

  /** Starts a sign-in: stores state, nonce and PKCE verifier for the callback and returns the provider URL plus the state for the browser cookie. */
  async start(purpose:OidcPurpose):Promise<{url:URL;state:string}>{
    const config=await this.config();
    const state=client.randomState(); const nonce=client.randomNonce(); const verifier=client.randomPKCECodeVerifier();
    this.db.prepare('DELETE FROM oidc_login_states WHERE expires<?').run(Date.now());
    this.db.prepare('INSERT INTO oidc_login_states (state_hash,code_verifier,nonce,purpose,expires) VALUES (?,?,?,?,?)').run(hashState(state),verifier,nonce,JSON.stringify(purpose),Date.now()+OIDC_STATE_LIFETIME_MS);
    const url=client.buildAuthorizationUrl(config,{redirect_uri:this.redirectUri,scope:this.settings.scopes,state,nonce,code_challenge:await client.calculatePKCECodeChallenge(verifier),code_challenge_method:'S256'});
    return {url,state};
  }

  /**
   * Finishes a sign-in at the callback. The state must match the browser's cookie (so a callback URL from someone
   * else's sign-in cannot log this browser in) and is usable once. Verifies the code grant, PKCE, nonce and ID token.
   */
  async finish(callbackUrl:URL,cookieState:string|undefined):Promise<{purpose:OidcPurpose;identity:OidcIdentity}>{
    const state=callbackUrl.searchParams.get('state');
    if(!state||!cookieState||state!==cookieState)throw new OidcError('state mismatch');
    const row=this.db.prepare('DELETE FROM oidc_login_states WHERE state_hash=? RETURNING code_verifier,nonce,purpose,expires').get(hashState(state)) as {code_verifier:string;nonce:string;purpose:string;expires:number}|undefined;
    if(!row||row.expires<Date.now())throw new OidcError('unknown or expired sign-in');
    const purpose=JSON.parse(row.purpose) as OidcPurpose;
    const providerError=callbackUrl.searchParams.get('error');
    if(providerError)throw new OidcError('provider returned '+providerError.slice(0,100),purpose);
    const config=await this.config();
    const tokens=await client.authorizationCodeGrant(config,callbackUrl,{pkceCodeVerifier:row.code_verifier,expectedState:state,expectedNonce:row.nonce,idTokenExpected:true});
    const claims=tokens.claims(); if(!claims)throw new OidcError('no ID token',purpose);
    let email=typeof claims.email==='string'?claims.email:undefined; let emailVerified=claims.email_verified===true;
    let name=typeof claims.name==='string'?claims.name:typeof claims.preferred_username==='string'?claims.preferred_username:undefined;
    if(!email&&tokens.access_token&&config.serverMetadata().userinfo_endpoint){
      const info=await client.fetchUserInfo(config,tokens.access_token,claims.sub);
      if(typeof info.email==='string'){email=info.email;emailVerified=info.email_verified===true;}
      name??=typeof info.name==='string'?info.name:typeof info.preferred_username==='string'?info.preferred_username:undefined;
    }
    return {purpose,identity:{issuer:claims.iss,subject:claims.sub,...(email?{email}:{}),emailVerified,...(name?{name}:{})}};
  }

  /** The farcmd account for a provider identity: an existing link, else an account with the same (trusted) email, else a new account if allowed. */
  resolveUser(identity:OidcIdentity,users:UserStore):OidcUserResult{
    const now=Date.now();
    const link=this.db.prepare('SELECT user_id FROM oidc_identities WHERE issuer=? AND subject=?').get(identity.issuer,identity.subject) as {user_id:string}|undefined;
    if(link){
      const user=users.getUser(link.user_id); if(!user)return {error:'The account linked to this sign-in no longer exists.'};
      this.db.prepare('UPDATE oidc_identities SET last_login_at=? WHERE issuer=? AND subject=?').run(now,identity.issuer,identity.subject);
      return {user,linked:'existing'};
    }
    const email=identity.email?normalizeEmail(identity.email):undefined;
    const trusted=email&&EMAIL_PATTERN.test(email)&&email.length<=MAX_EMAIL_LENGTH&&(identity.emailVerified||this.settings.trustEmail)?email:undefined;
    const byEmail=trusted?users.getUserByEmail(trusted):undefined;
    if(byEmail){this.link(identity,byEmail.id,now);return {user:byEmail,linked:'email'};}
    if(!this.settings.createUsers)return {error:'There is no farcmd account for this sign-in. Ask the administrator to create one.'};
    const user:McpUser={id:crypto.randomUUID(),name:(identity.name??trusted??'User').trim().slice(0,120)||'User',...(trusted?{email:trusted}:{}),createdAt:now};
    users.createUser(user); this.link(identity,user.id,now);
    return {user,linked:'created'};
  }

  private link(identity:OidcIdentity,userId:string,now:number){this.db.prepare('INSERT INTO oidc_identities (issuer,subject,user_id,created_at,last_login_at) VALUES (?,?,?,?,?)').run(identity.issuer,identity.subject,userId,now,now);}
}

/** A sign-in that failed at the callback; purpose is known once the stored state was found. */
export class OidcError extends Error { constructor(message:string,readonly purpose?:OidcPurpose){super(message);} }
