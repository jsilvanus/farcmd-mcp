import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { verify } from '@node-rs/argon2';
import type { AuthStore, AuthorizationCodeRecord, McpUser, RefreshTokenRecord, UserStore, WebSessionRecord, WebSessionStore } from './interface.js';
import { SqliteOAuthGrantStore } from '../oauth/grants.js';

export class SqliteAuthStore implements AuthStore, WebSessionStore {
  private readonly db:DatabaseSync;
  constructor(path:string){
    mkdirSync(dirname(path),{recursive:true}); this.db=new DatabaseSync(path);
    this.db.exec(
      'CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE, password_hash TEXT, execution_password_hash TEXT, created_at INTEGER NOT NULL);' +
      'CREATE TABLE IF NOT EXISTS authorization_codes (code TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, challenge TEXT NOT NULL, subject TEXT NOT NULL, scope TEXT NOT NULL, expires INTEGER NOT NULL);' +
      'CREATE TABLE IF NOT EXISTS refresh_tokens (token TEXT PRIMARY KEY, client_id TEXT NOT NULL, subject TEXT NOT NULL, scope TEXT NOT NULL, expires INTEGER NOT NULL);' +
      'CREATE TABLE IF NOT EXISTS web_sessions (token TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires INTEGER NOT NULL);' +
      'CREATE TABLE IF NOT EXISTS ssh_keys (id TEXT PRIMARY KEY,user_id TEXT NOT NULL,name TEXT NOT NULL,encrypted_private_key TEXT NOT NULL,fingerprint TEXT,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);' +
      'CREATE TABLE IF NOT EXISTS ssh_targets (id TEXT PRIMARY KEY,user_id TEXT NOT NULL,name TEXT NOT NULL,hostname TEXT NOT NULL,port INTEGER NOT NULL,username TEXT NOT NULL,ssh_key_id TEXT NOT NULL,host_fingerprint TEXT,enabled INTEGER NOT NULL DEFAULT 1,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);' +
      'CREATE TABLE IF NOT EXISTS commands (id TEXT PRIMARY KEY,user_id TEXT NOT NULL,target_id TEXT NOT NULL,name TEXT NOT NULL,description TEXT NOT NULL,shell_command TEXT NOT NULL,level INTEGER NOT NULL CHECK(level BETWEEN 1 AND 5),enabled INTEGER NOT NULL DEFAULT 1,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);' +
      'CREATE TABLE IF NOT EXISTS oauth_grants (user_id TEXT NOT NULL,client_id TEXT NOT NULL,client_name TEXT NOT NULL,allowed_levels TEXT NOT NULL DEFAULT \'\',level5_permanently_denied INTEGER NOT NULL DEFAULT 0,visible_levels TEXT NOT NULL DEFAULT \'\',level5_permanently_hidden INTEGER NOT NULL DEFAULT 0,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,revoked_at INTEGER,last_used_at INTEGER,PRIMARY KEY(user_id,client_id));' +
      'CREATE TABLE IF NOT EXISTS pending_executions (token TEXT PRIMARY KEY,user_id TEXT NOT NULL,client_id TEXT NOT NULL,command_id TEXT NOT NULL,level INTEGER NOT NULL,created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,status TEXT NOT NULL,exit_code INTEGER,stdout TEXT,stderr TEXT,duration_ms INTEGER,signal TEXT);'
    );
    try{this.db.exec('ALTER TABLE users ADD COLUMN execution_password_hash TEXT');}catch{}
    try{this.db.exec('ALTER TABLE pending_executions ADD COLUMN exit_code INTEGER');}catch{}\n    try{this.db.exec('ALTER TABLE pending_executions ADD COLUMN stdout TEXT');}catch{}\n    try{this.db.exec('ALTER TABLE pending_executions ADD COLUMN stderr TEXT');}catch{}\n    try{this.db.exec('ALTER TABLE pending_executions ADD COLUMN duration_ms INTEGER');}catch{}\n    try{this.db.exec('ALTER TABLE pending_executions ADD COLUMN signal TEXT');}catch{}\n    try{this.db.exec('ALTER TABLE oauth_grants ADD COLUMN visible_levels TEXT NOT NULL DEFAULT \'\'');}catch{}
    try{this.db.exec('ALTER TABLE oauth_grants ADD COLUMN level5_permanently_hidden INTEGER NOT NULL DEFAULT 0');}catch{}
    this.db.exec('UPDATE oauth_grants SET visible_levels=allowed_levels WHERE visible_levels=\'\' AND allowed_levels<>\'\';UPDATE oauth_grants SET level5_permanently_hidden=level5_permanently_denied WHERE level5_permanently_denied=1 AND level5_permanently_hidden=0;');
  }
  getDatabase():DatabaseSync{return this.db;}
  private grants(){return new SqliteOAuthGrantStore(this.db);}
  getOAuthGrant(u:string,c:string){return this.grants().get(u,c);}
  upsertOAuthGrant(u:string,c:string,n:string,l:number[],p:boolean){this.grants().upsert(u,c,n,l as any,p);}
  revokeOAuthGrant(u:string,c:string){this.grants().revoke(u,c);}
  updateOAuthGrant(u:string,c:string,l:number[],p:boolean){this.grants().update(u,c,l as any,p);}
  listOAuthGrants(u:string){return this.grants().list(u);}
  touchOAuthGrant(u:string,c:string){this.grants().touch(u,c);}
  saveAuthorizationCode(r:AuthorizationCodeRecord):void{this.db.prepare('INSERT INTO authorization_codes (code,client_id,redirect_uri,challenge,subject,scope,expires) VALUES (?,?,?,?,?,?,?)').run(r.code,r.clientId,r.redirectUri,r.challenge,r.subject,r.scope,r.expires);}
  consumeAuthorizationCode(code:string):AuthorizationCodeRecord|undefined{const r=this.db.prepare('SELECT * FROM authorization_codes WHERE code=?').get(code) as any;if(!r||r.expires<Date.now()){this.db.prepare('DELETE FROM authorization_codes WHERE code=?').run(code);return undefined;}this.db.prepare('DELETE FROM authorization_codes WHERE code=?').run(code);return {code:r.code,clientId:r.client_id,redirectUri:r.redirect_uri,challenge:r.challenge,subject:r.subject,scope:r.scope,expires:r.expires};}
  saveRefreshToken(r:RefreshTokenRecord):void{this.db.prepare('INSERT INTO refresh_tokens (token,client_id,subject,scope,expires) VALUES (?,?,?,?,?)').run(r.token,r.clientId,r.subject,r.scope,r.expires);}
  getRefreshToken(token:string):RefreshTokenRecord|undefined{const r=this.db.prepare('SELECT * FROM refresh_tokens WHERE token=?').get(token) as any;if(!r||r.expires<Date.now()){if(r)this.db.prepare('DELETE FROM refresh_tokens WHERE token=?').run(token);return undefined;}return {token:r.token,clientId:r.client_id,subject:r.subject,scope:r.scope,expires:r.expires};}
  saveWebSession(r:WebSessionRecord):void{this.db.prepare('INSERT INTO web_sessions (token,user_id,expires) VALUES (?,?,?)').run(r.token,r.userId,r.expires);}
  getWebSession(token:string):WebSessionRecord|undefined{const r=this.db.prepare('SELECT * FROM web_sessions WHERE token=?').get(token) as any;return r?{token:r.token,userId:r.user_id,expires:r.expires}:undefined;}
  deleteWebSession(token:string):void{this.db.prepare('DELETE FROM web_sessions WHERE token=?').run(token);}
}
export class SqliteUserStore implements UserStore {
  constructor(private readonly db:DatabaseSync){}
  createUser(u:McpUser):void{this.db.prepare('INSERT INTO users (id,name,email,password_hash,execution_password_hash,created_at) VALUES (?,?,?,?,?,?)').run(u.id,u.name,u.email??null,u.passwordHash??null,u.executionPasswordHash??null,u.createdAt);}
  listUsers():McpUser[]{return (this.db.prepare('SELECT * FROM users ORDER BY name,id').all() as any[]).map(this.map);}
  getUser(id:string):McpUser|undefined{return this.map(this.db.prepare('SELECT * FROM users WHERE id=?').get(id) as any);}
  updateUser(id:string,name:string,email:string):void{this.db.prepare('UPDATE users SET name=?,email=? WHERE id=?').run(name,email,id);}
  setExecutionPassword(id:string,passwordHash:string):void{this.db.prepare('UPDATE users SET execution_password_hash=? WHERE id=?').run(passwordHash,id);}
  async verifyExecutionPassword(id:string,password:string):Promise<boolean>{const r=this.db.prepare('SELECT execution_password_hash FROM users WHERE id=?').get(id) as any;return !!r?.execution_password_hash&&await verify(r.execution_password_hash,password);}
  getUserByEmail(email:string):McpUser|undefined{return this.map(this.db.prepare('SELECT * FROM users WHERE lower(email)=lower(?)').get(email) as any);}
  private map=(r:any):McpUser|undefined=>r?{id:r.id,name:r.name,...(r.email?{email:r.email}:{}),...(r.password_hash?{passwordHash:r.password_hash}:{}),...(r.execution_password_hash?{executionPasswordHash:r.execution_password_hash}:{}),createdAt:r.created_at}:undefined;
}
