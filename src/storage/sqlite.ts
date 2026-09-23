import { mkdirSync } from 'node:fs';
import { randomUUID, createHash } from 'node:crypto';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import type { AuthStore, McpUser, UserStore, WebSessionRecord, WebSessionStore } from './interface.js';
import { SqliteOAuthGrantStore } from '../oauth/grants.js';
import { AuditLog, migrateAuditTable, type AuditOutcome } from '../audit.js';
import { SqliteOAuthTokenStore, migrateOAuthTokenTables } from '../oauth/tokens.js';
import { migrateMcpAccess } from '../mcp-access.js';

export class SqliteAuthStore implements AuthStore, WebSessionStore {
  private readonly db:DatabaseSync;
  constructor(path:string){
    mkdirSync(dirname(path),{recursive:true}); this.db=new DatabaseSync(path);
    this.db.exec(
      'CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE, password_hash TEXT, created_at INTEGER NOT NULL);' +
      'CREATE TABLE IF NOT EXISTS authorization_codes (code TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, challenge TEXT NOT NULL, subject TEXT NOT NULL, scope TEXT NOT NULL, expires INTEGER NOT NULL);' +
      'CREATE TABLE IF NOT EXISTS refresh_tokens (token TEXT PRIMARY KEY, client_id TEXT NOT NULL, subject TEXT NOT NULL, scope TEXT NOT NULL, expires INTEGER NOT NULL);' +
      'CREATE TABLE IF NOT EXISTS web_sessions (token TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires INTEGER NOT NULL);' +
      'CREATE TABLE IF NOT EXISTS ssh_keys (id TEXT PRIMARY KEY,user_id TEXT NOT NULL,name TEXT NOT NULL,encrypted_private_key TEXT NOT NULL,fingerprint TEXT,public_key TEXT,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);' +
      'CREATE TABLE IF NOT EXISTS ssh_targets (id TEXT PRIMARY KEY,user_id TEXT NOT NULL,name TEXT NOT NULL,hostname TEXT NOT NULL,port INTEGER NOT NULL,username TEXT NOT NULL,ssh_key_id TEXT NOT NULL,host_fingerprint TEXT,enabled INTEGER NOT NULL DEFAULT 1,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);' +
      "CREATE TABLE IF NOT EXISTS commands (id TEXT PRIMARY KEY,user_id TEXT NOT NULL,target_id TEXT NOT NULL,name TEXT NOT NULL,description TEXT NOT NULL,shell_command TEXT NOT NULL DEFAULT '',type TEXT NOT NULL DEFAULT 'shell',content TEXT NOT NULL DEFAULT '',command_sha256 TEXT NOT NULL DEFAULT '',level INTEGER NOT NULL CHECK(level BETWEEN 1 AND 5),enabled INTEGER NOT NULL DEFAULT 1,execution_password_hash TEXT,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);" +
      'CREATE TABLE IF NOT EXISTS oauth_grants (user_id TEXT NOT NULL,client_id TEXT NOT NULL,client_name TEXT NOT NULL,allowed_levels TEXT NOT NULL DEFAULT \'\',level5_permanently_denied INTEGER NOT NULL DEFAULT 0,visible_levels TEXT NOT NULL DEFAULT \'\',level5_permanently_hidden INTEGER NOT NULL DEFAULT 0,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,revoked_at INTEGER,last_used_at INTEGER,PRIMARY KEY(user_id,client_id));' +
      'CREATE TABLE IF NOT EXISTS execution_history (id TEXT PRIMARY KEY,user_id TEXT NOT NULL,client_id TEXT NOT NULL,command_id TEXT NOT NULL,command_name TEXT NOT NULL,target_id TEXT NOT NULL,level INTEGER NOT NULL,started_at INTEGER NOT NULL,ended_at INTEGER NOT NULL,duration_ms INTEGER NOT NULL,exit_code INTEGER,stdout TEXT NOT NULL,stderr TEXT NOT NULL,status TEXT NOT NULL,error TEXT);' +
      'CREATE TABLE IF NOT EXISTS security_events (id TEXT PRIMARY KEY,user_id TEXT,client_id TEXT,event TEXT NOT NULL,details TEXT,created_at INTEGER NOT NULL);' +
      'CREATE TABLE IF NOT EXISTS pending_executions (token TEXT PRIMARY KEY,user_id TEXT NOT NULL,client_id TEXT NOT NULL,command_id TEXT NOT NULL,level INTEGER NOT NULL,created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,status TEXT NOT NULL,exit_code INTEGER,stdout TEXT,stderr TEXT,duration_ms INTEGER,signal TEXT);' +
      'CREATE TABLE IF NOT EXISTS command_installations (id TEXT PRIMARY KEY,user_id TEXT NOT NULL,command_id TEXT NOT NULL,target_id TEXT NOT NULL,master_key_id TEXT NOT NULL,encrypted_private_key TEXT NOT NULL,public_key TEXT NOT NULL,fingerprint TEXT NOT NULL,remote_script_path TEXT NOT NULL,authorized_key_line TEXT NOT NULL,script_content TEXT,command_sha256 TEXT,script_sha256 TEXT,authorized_key_sha256 TEXT,installed_at INTEGER,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,UNIQUE(user_id,command_id));' +
      'CREATE TABLE IF NOT EXISTS remote_capability_ledger (id TEXT PRIMARY KEY,user_id TEXT NOT NULL,target_id TEXT NOT NULL,command_id TEXT,public_key TEXT NOT NULL,fingerprint TEXT NOT NULL,authorized_key_line TEXT NOT NULL,remote_script_path TEXT NOT NULL,status TEXT NOT NULL,created_at INTEGER NOT NULL,last_attempt_at INTEGER,removed_at INTEGER,last_error TEXT,attempt_count INTEGER NOT NULL DEFAULT 0);' +
      // Verification authorities are deliberately a separate table from ssh_keys: they are never provisioning credentials.
      'CREATE TABLE IF NOT EXISTS verification_authorities (id TEXT PRIMARY KEY,user_id TEXT NOT NULL,target_id TEXT NOT NULL,username TEXT NOT NULL,privilege TEXT NOT NULL,encrypted_private_key TEXT NOT NULL,public_key TEXT NOT NULL,fingerprint TEXT NOT NULL,encrypted_secret TEXT NOT NULL,authorized_key_line TEXT NOT NULL,authorized_key_sha256 TEXT NOT NULL,sudoers_sha256 TEXT,python_path TEXT,verifier_sha256 TEXT,status TEXT NOT NULL,installed_at INTEGER,last_verified_at INTEGER,last_error TEXT,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,UNIQUE(user_id,target_id));'
    );
    try{this.db.exec('ALTER TABLE ssh_keys ADD COLUMN public_key TEXT');}catch{}
    try{this.db.exec("ALTER TABLE commands ADD COLUMN type TEXT NOT NULL DEFAULT 'shell'");}catch{}
    try{this.db.exec("ALTER TABLE commands ADD COLUMN content TEXT NOT NULL DEFAULT ''");}catch{}
    try{this.db.exec("UPDATE commands SET content=shell_command WHERE content='' AND shell_command<>''");}catch{}
    try{this.db.exec("ALTER TABLE commands ADD COLUMN command_sha256 TEXT NOT NULL DEFAULT ''");}catch{}
    try{const rows=this.db.prepare("SELECT id,type,content FROM commands WHERE command_sha256=''").all() as any[];const update=this.db.prepare('UPDATE commands SET command_sha256=? WHERE id=?');for(const row of rows)update.run(createHash('sha256').update(String(row.type)+'\0'+String(row.content),'utf8').digest('hex'),row.id);}catch{}
    try{this.db.exec("ALTER TABLE command_keys RENAME TO command_installations");}catch{}
    try{this.db.exec('ALTER TABLE command_installations ADD COLUMN remote_script_path TEXT NOT NULL DEFAULT \'\'');}catch{}
    try{this.db.exec('ALTER TABLE command_installations ADD COLUMN script_content TEXT');}catch{}
    try{this.db.exec('ALTER TABLE command_installations ADD COLUMN command_sha256 TEXT');}catch{}
    try{this.db.exec('ALTER TABLE command_installations ADD COLUMN script_sha256 TEXT');}catch{}
    try{this.db.exec('ALTER TABLE command_installations ADD COLUMN authorized_key_sha256 TEXT');}catch{}
    try{this.db.exec('ALTER TABLE command_installations ADD COLUMN authorized_key_line TEXT NOT NULL DEFAULT \'\'');}catch{}
    try{this.db.exec("UPDATE command_installations SET remote_script_path='legacy',authorized_key_line=public_key WHERE remote_script_path='' AND authorized_key_line=''");}catch{}
    try{this.db.exec('ALTER TABLE commands ADD COLUMN execution_password_hash TEXT');}catch{}
    try{this.db.exec('ALTER TABLE commands ADD COLUMN show_output_on_approval INTEGER NOT NULL DEFAULT 0');}catch{}
    try{this.db.exec('ALTER TABLE pending_executions ADD COLUMN exit_code INTEGER');}catch{}
    try{this.db.exec('ALTER TABLE pending_executions ADD COLUMN stdout TEXT');}catch{}
    try{this.db.exec('ALTER TABLE pending_executions ADD COLUMN stderr TEXT');}catch{}
    try{this.db.exec('ALTER TABLE pending_executions ADD COLUMN duration_ms INTEGER');}catch{}
    try{this.db.exec('ALTER TABLE pending_executions ADD COLUMN signal TEXT');}catch{}
    try{this.db.exec('ALTER TABLE oauth_grants ADD COLUMN visible_levels TEXT NOT NULL DEFAULT \'\'');}catch{}
    try{this.db.exec('ALTER TABLE oauth_grants ADD COLUMN level5_permanently_hidden INTEGER NOT NULL DEFAULT 0');}catch{}
    migrateAuditTable(this.db);
    migrateOAuthTokenTables(this.db);
    migrateMcpAccess(this.db);
    try{this.db.exec('ALTER TABLE users ADD COLUMN disabled_at INTEGER');}catch{}
    // Instance-wide settings managed by the operator (farcmd-admin CLI). Absent keys mean the secure default.
    this.db.exec('CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY,value TEXT NOT NULL,updated_at INTEGER NOT NULL)');
    this.db.exec('UPDATE oauth_grants SET visible_levels=allowed_levels WHERE visible_levels=\'\' AND allowed_levels<>\'\';UPDATE oauth_grants SET level5_permanently_hidden=level5_permanently_denied WHERE level5_permanently_denied=1 AND level5_permanently_hidden=0;');
  }
  getDatabase():DatabaseSync{return this.db;}
  recordSecurityEvent(userId:string|undefined,clientId:string|undefined,event:string,details?:Record<string,unknown>,outcome:AuditOutcome='success'):void{new AuditLog(this.db).record({event,actor:'oauth',outcome,userId,clientId,...(clientId?{targetType:'oauth_client',targetId:clientId}:{}),details});}
  cleanupSecurityEvents(maxAgeMs=90*24*60*60_000):number{return new AuditLog(this.db).prune(maxAgeMs);}
  private grants(){return new SqliteOAuthGrantStore(this.db);}
  getOAuthGrant(u:string,c:string){return this.grants().get(u,c);}
  upsertOAuthGrant(u:string,c:string,n:string,l:number[],p:boolean){this.grants().upsert(u,c,n,l as any,p);}
  revokeOAuthGrant(u:string,c:string){this.grants().revoke(u,c);}
  updateOAuthGrant(u:string,c:string,l:number[],p:boolean){this.grants().update(u,c,l as any,p);}
  listOAuthGrants(u:string){return this.grants().list(u);}
  touchOAuthGrant(u:string,c:string){this.grants().touch(u,c);}
  oauthTokens():SqliteOAuthTokenStore{return new SqliteOAuthTokenStore(this.db);}
  saveWebSession(r:WebSessionRecord):void{this.db.prepare('INSERT INTO web_sessions (token,user_id,expires) VALUES (?,?,?)').run(r.token,r.userId,r.expires);}
  getWebSession(token:string):WebSessionRecord|undefined{
    const r=this.db.prepare('SELECT * FROM web_sessions WHERE token=?').get(token) as any;
    return r?{token:r.token,userId:r.user_id,expires:r.expires}:undefined;
  }
  deleteWebSession(token:string):void{this.db.prepare('DELETE FROM web_sessions WHERE token=?').run(token);}
}
export class SqliteUserStore implements UserStore {
  constructor(private readonly db:DatabaseSync){}
  createUser(u:McpUser):void{this.db.prepare('INSERT INTO users (id,name,email,password_hash,created_at) VALUES (?,?,?,?,?)').run(u.id,u.name,u.email??null,u.passwordHash??null,u.createdAt);}
  listUsers():McpUser[]{return (this.db.prepare('SELECT * FROM users ORDER BY name,id').all() as any[]).map(this.map).filter((u):u is McpUser=>u!==undefined);}
  getUser(id:string):McpUser|undefined{return this.map(this.db.prepare('SELECT * FROM users WHERE id=?').get(id) as any);}
  updateUser(id:string,name:string,email:string):void{this.db.prepare('UPDATE users SET name=?,email=? WHERE id=?').run(name,email,id);}
  getUserByEmail(email:string):McpUser|undefined{return this.map(this.db.prepare('SELECT * FROM users WHERE lower(email)=lower(?)').get(email) as any);}
  private map=(r:any):McpUser|undefined=>r?{id:r.id,name:r.name,...(r.email?{email:r.email}:{}),...(r.password_hash?{passwordHash:r.password_hash}:{}),createdAt:r.created_at,...(r.disabled_at!=null?{disabledAt:r.disabled_at}:{})}:undefined;
}
