import type { DatabaseSync } from 'node:sqlite';
import { createHash, randomUUID } from 'node:crypto';
import { randomToken } from './pkce.js';

/**
 * OAuth authorization codes and refresh tokens.
 *
 * - Only SHA-256 hashes are stored (in the existing `code` / `token` columns): a database leak does
 *   not yield usable tokens.
 * - Refresh tokens rotate: every use consumes the presented token and issues a new one in the same
 *   family. The family keeps the absolute expiry of the original authorization (no sliding lifetime).
 * - Used tokens are kept (marked used) until the family expires. Presenting a used token again means
 *   it was copied: the whole family is revoked (OAuth 2.1 refresh token reuse detection).
 * - Authorization codes are single use; they are marked consumed rather than deleted, and a second
 *   redemption revokes the token family the first one produced.
 */
export const REFRESH_TOKEN_LIFETIME_MS=30*86_400_000;
const CONSUMED_CODE_RETENTION_MS=10*60_000;

export function hashToken(token:string):string{ return createHash('sha256').update(token,'utf8').digest('hex'); }

export interface StoredAuthorizationCode { clientId:string; redirectUri:string; challenge:string; subject:string; scope:string; expires:number; familyId:string; }
export interface StoredRefreshToken { familyId:string; clientId:string; subject:string; scope:string; expires:number; createdAt:number; usedAt?:number; }
export type CodeRedemption =
  | {status:'ok'; code:StoredAuthorizationCode}
  | {status:'unknown'|'expired'}
  | {status:'reused'; code:StoredAuthorizationCode; revokedTokens:number};
export type RefreshRotation =
  | {status:'ok'; previous:StoredRefreshToken; token:string}
  | {status:'unknown'|'expired'}
  | {status:'reused'; previous:StoredRefreshToken; revokedTokens:number};

export function migrateOAuthTokenTables(db:DatabaseSync):void{
  for(const column of ['family_id TEXT','created_at INTEGER','used_at INTEGER'])try{db.exec('ALTER TABLE refresh_tokens ADD COLUMN '+column);}catch{}
  for(const column of ['hashed INTEGER NOT NULL DEFAULT 0','consumed_at INTEGER','family_id TEXT'])try{db.exec('ALTER TABLE authorization_codes ADD COLUMN '+column);}catch{}
  // Sign-in-to-consent step of /oauth/authorize (5 minutes). In the database rather than process memory,
  // so it survives restarts and is bounded by cleanup; only the token hash is stored.
  db.exec('CREATE TABLE IF NOT EXISTS oauth_login_sessions (token TEXT PRIMARY KEY, user_id TEXT NOT NULL, oauth TEXT NOT NULL, expires INTEGER NOT NULL)');
  db.exec('CREATE INDEX IF NOT EXISTS refresh_tokens_family ON refresh_tokens(family_id)');
  db.exec('CREATE INDEX IF NOT EXISTS refresh_tokens_subject ON refresh_tokens(subject,client_id)');
  // Legacy rows stored the token itself: replace it by its hash, each in its own family, keeping its expiry.
  const legacy=db.prepare('SELECT token FROM refresh_tokens WHERE family_id IS NULL').all() as {token:string}[];
  if(legacy.length){
    const update=db.prepare('UPDATE refresh_tokens SET token=?,family_id=?,created_at=? WHERE token=?');
    db.exec('BEGIN IMMEDIATE');
    try{for(const row of legacy)update.run(hashToken(row.token),randomUUID(),Date.now(),row.token);db.exec('COMMIT');}
    catch(error){try{db.exec('ROLLBACK');}catch{}throw error;}
  }
  // Legacy authorization codes live for 60 seconds; unhashed ones are simply dropped.
  db.prepare('DELETE FROM authorization_codes WHERE hashed=0').run();
}

export class SqliteOAuthTokenStore {
  constructor(private readonly db:DatabaseSync){}

  saveAuthorizationCode(code:string,r:Omit<StoredAuthorizationCode,'familyId'>):void{
    this.cleanup();
    this.db.prepare('INSERT INTO authorization_codes (code,client_id,redirect_uri,challenge,subject,scope,expires,hashed,family_id) VALUES (?,?,?,?,?,?,?,1,?)')
      .run(hashToken(code),r.clientId,r.redirectUri,r.challenge,r.subject,r.scope,r.expires,randomUUID());
  }
  /** Single use. A second redemption revokes the tokens issued from the first. */
  redeemAuthorizationCode(code:string):CodeRedemption{
    const key=hashToken(code);
    const r=this.db.prepare('SELECT * FROM authorization_codes WHERE code=? AND hashed=1').get(key) as any;
    if(!r)return {status:'unknown'};
    const stored:StoredAuthorizationCode={clientId:r.client_id,redirectUri:r.redirect_uri,challenge:r.challenge,subject:r.subject,scope:r.scope,expires:r.expires,familyId:r.family_id};
    const claimed=r.consumed_at==null&&Number(this.db.prepare('UPDATE authorization_codes SET consumed_at=? WHERE code=? AND consumed_at IS NULL').run(Date.now(),key).changes)===1;
    if(!claimed)return {status:'reused',code:stored,revokedTokens:this.revokeFamily(stored.familyId)};
    if(r.expires<Date.now())return {status:'expired'};
    return {status:'ok',code:stored};
  }

  issueRefreshToken(r:{familyId:string;clientId:string;subject:string;scope:string;expires:number}):string{
    const token=randomToken();
    this.db.prepare('INSERT INTO refresh_tokens (token,client_id,subject,scope,expires,family_id,created_at) VALUES (?,?,?,?,?,?,?)').run(hashToken(token),r.clientId,r.subject,r.scope,r.expires,r.familyId,Date.now());
    return token;
  }
  /** Look up without consuming (used to validate client, grant and user before rotation). */
  peekRefreshToken(token:string):StoredRefreshToken|undefined{
    const r=this.db.prepare('SELECT * FROM refresh_tokens WHERE token=?').get(hashToken(token)) as any;
    if(!r||r.expires<Date.now())return undefined;
    return {familyId:r.family_id,clientId:r.client_id,subject:r.subject,scope:r.scope,expires:r.expires,createdAt:r.created_at,...(r.used_at!=null?{usedAt:r.used_at}:{})};
  }
  /** Consume the presented token and issue its successor, or revoke the family on reuse. */
  rotateRefreshToken(token:string):RefreshRotation{
    const key=hashToken(token);
    const r=this.db.prepare('SELECT * FROM refresh_tokens WHERE token=?').get(key) as any;
    if(!r)return {status:'unknown'};
    const previous:StoredRefreshToken={familyId:r.family_id,clientId:r.client_id,subject:r.subject,scope:r.scope,expires:r.expires,createdAt:r.created_at,...(r.used_at!=null?{usedAt:r.used_at}:{})};
    if(r.expires<Date.now())return {status:'expired'};
    const claimed=r.used_at==null&&Number(this.db.prepare('UPDATE refresh_tokens SET used_at=? WHERE token=? AND used_at IS NULL').run(Date.now(),key).changes)===1;
    if(!claimed)return {status:'reused',previous,revokedTokens:this.revokeFamily(previous.familyId)};
    return {status:'ok',previous,token:this.issueRefreshToken({familyId:previous.familyId,clientId:previous.clientId,subject:previous.subject,scope:previous.scope,expires:previous.expires})};
  }
  saveLoginSession(token:string,r:{userId:string;oauth:string;expires:number}):void{
    this.db.prepare('DELETE FROM oauth_login_sessions WHERE expires<?').run(Date.now());
    this.db.prepare('INSERT INTO oauth_login_sessions (token,user_id,oauth,expires) VALUES (?,?,?,?)').run(hashToken(token),r.userId,r.oauth,r.expires);
  }
  getLoginSession(token:string):{userId:string;oauth:string;expires:number}|undefined{
    const r=this.db.prepare('SELECT * FROM oauth_login_sessions WHERE token=?').get(hashToken(token)) as any;
    return r&&r.expires>=Date.now()?{userId:r.user_id,oauth:r.oauth,expires:r.expires}:undefined;
  }
  /** Single use: true only for the caller that removed it. */
  consumeLoginSession(token:string):boolean{ return Number(this.db.prepare('DELETE FROM oauth_login_sessions WHERE token=? AND expires>=?').run(hashToken(token),Date.now()).changes)===1; }
  revokeFamily(familyId:string):number{ return Number(this.db.prepare('DELETE FROM refresh_tokens WHERE family_id=? AND used_at IS NULL').run(familyId).changes); }
  revokeForGrant(subject:string,clientId:string):number{ return Number(this.db.prepare('DELETE FROM refresh_tokens WHERE subject=? AND client_id=?').run(subject,clientId).changes); }
  cleanup(now=Date.now()):void{
    this.db.prepare('DELETE FROM refresh_tokens WHERE expires<?').run(now);
    this.db.prepare('DELETE FROM authorization_codes WHERE expires<?').run(now-CONSUMED_CODE_RETENTION_MS);
    this.db.prepare('DELETE FROM oauth_login_sessions WHERE expires<?').run(now);
  }
}
