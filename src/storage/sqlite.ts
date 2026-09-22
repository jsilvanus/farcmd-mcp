import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import type { AuthStore, AuthorizationCodeRecord, McpUser, RefreshTokenRecord, UserStore, WebSessionRecord, WebSessionStore } from './interface.js';

export class SqliteAuthStore implements AuthStore, WebSessionStore {
  private readonly db: DatabaseSync;
  constructor(path:string) {
    mkdirSync(dirname(path),{recursive:true});
    this.db=new DatabaseSync(path);
    this.db.exec(
      'CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE, password_hash TEXT, created_at INTEGER NOT NULL);' +
      'CREATE TABLE IF NOT EXISTS authorization_codes (code TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, challenge TEXT NOT NULL, subject TEXT NOT NULL, scope TEXT NOT NULL, expires INTEGER NOT NULL);' +
      'CREATE TABLE IF NOT EXISTS refresh_tokens (token TEXT PRIMARY KEY, client_id TEXT NOT NULL, subject TEXT NOT NULL, scope TEXT NOT NULL, expires INTEGER NOT NULL);' +
      'CREATE TABLE IF NOT EXISTS web_sessions (token TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires INTEGER NOT NULL);' +
      'CREATE TABLE IF NOT EXISTS ssh_keys (id TEXT PRIMARY KEY,user_id TEXT NOT NULL,name TEXT NOT NULL,encrypted_private_key TEXT NOT NULL,fingerprint TEXT,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);' +
      'CREATE TABLE IF NOT EXISTS ssh_targets (id TEXT PRIMARY KEY,user_id TEXT NOT NULL,name TEXT NOT NULL,hostname TEXT NOT NULL,port INTEGER NOT NULL,username TEXT NOT NULL,ssh_key_id TEXT NOT NULL,host_fingerprint TEXT,enabled INTEGER NOT NULL DEFAULT 1,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);' + 'CREATE TABLE IF NOT EXISTS commands (id TEXT PRIMARY KEY,user_id TEXT NOT NULL,target_id TEXT NOT NULL,name TEXT NOT NULL,description TEXT NOT NULL,shell_command TEXT NOT NULL,level INTEGER NOT NULL CHECK(level BETWEEN 1 AND 5),enabled INTEGER NOT NULL DEFAULT 1,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);'
    );
  }
  getDatabase():DatabaseSync{return this.db;}
  saveAuthorizationCode(r:AuthorizationCodeRecord):void{this.db.prepare('INSERT INTO authorization_codes (code,client_id,redirect_uri,challenge,subject,scope,expires) VALUES (?,?,?,?,?,?,?)').run(r.code,r.clientId,r.redirectUri,r.challenge,r.subject,r.scope,r.expires);}
  consumeAuthorizationCode(code:string):AuthorizationCodeRecord|undefined{
    const r=this.db.prepare('SELECT code,client_id,redirect_uri,challenge,subject,scope,expires FROM authorization_codes WHERE code=?').get(code) as any;
    if(!r||r.expires<Date.now()){this.db.prepare('DELETE FROM authorization_codes WHERE code=?').run(code);return undefined;}
    this.db.prepare('DELETE FROM authorization_codes WHERE code=?').run(code);
    return {code:r.code,clientId:r.client_id,redirectUri:r.redirect_uri,challenge:r.challenge,subject:r.subject,scope:r.scope,expires:r.expires};
  }
  saveRefreshToken(r:RefreshTokenRecord):void{this.db.prepare('INSERT INTO refresh_tokens (token,client_id,subject,scope,expires) VALUES (?,?,?,?,?)').run(r.token,r.clientId,r.subject,r.scope,r.expires);}
  getRefreshToken(token:string):RefreshTokenRecord|undefined{
    const r=this.db.prepare('SELECT token,client_id,subject,scope,expires FROM refresh_tokens WHERE token=?').get(token) as any;
    if(!r||r.expires<Date.now()){if(r)this.db.prepare('DELETE FROM refresh_tokens WHERE token=?').run(token);return undefined;}
    return {token:r.token,clientId:r.client_id,subject:r.subject,scope:r.scope,expires:r.expires};
  }
  saveWebSession(r:WebSessionRecord):void{this.db.prepare('INSERT INTO web_sessions (token,user_id,expires) VALUES (?,?,?)').run(r.token,r.userId,r.expires);}
  getWebSession(token:string):WebSessionRecord|undefined{const r=this.db.prepare('SELECT token,user_id,expires FROM web_sessions WHERE token=?').get(token) as any;return r?{token:r.token,userId:r.user_id,expires:r.expires}:undefined;}
  deleteWebSession(token:string):void{this.db.prepare('DELETE FROM web_sessions WHERE token=?').run(token);}
}
export class SqliteUserStore implements UserStore {
  constructor(private readonly db:DatabaseSync){}
  createUser(u:McpUser):void{this.db.prepare('INSERT INTO users (id,name,email,password_hash,created_at) VALUES (?,?,?,?,?)').run(u.id,u.name,u.email??null,u.passwordHash??null,u.createdAt);}
  listUsers():McpUser[]{const rows=this.db.prepare('SELECT id,name,email,password_hash,created_at FROM users ORDER BY name,id').all() as any[];return rows.map(this.map);}
  getUser(id:string):McpUser|undefined{return this.map(this.db.prepare('SELECT id,name,email,password_hash,created_at FROM users WHERE id=?').get(id) as any);}
  updateUser(id:string,name:string,email:string):void{this.db.prepare('UPDATE users SET name=?,email=? WHERE id=?').run(name,email,id);}
  getUserByEmail(email:string):McpUser|undefined{return this.map(this.db.prepare('SELECT id,name,email,password_hash,created_at FROM users WHERE lower(email)=lower(?)').get(email) as any);}
  private map=(r:any):McpUser|undefined=>r?{id:r.id,name:r.name,...(r.email?{email:r.email}:{}),...(r.password_hash?{passwordHash:r.password_hash}:{}),createdAt:r.created_at}:undefined;
}
