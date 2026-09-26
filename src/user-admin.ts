import type { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';
import { SqliteUserStore } from './storage/sqlite.js';
import { SqliteSettingsStore } from './storage/settings.js';
import { AuditLog } from './audit.js';
import { hashPassword } from './login-rate-limit.js';
import { SqliteOAuthTokenStore } from './oauth/tokens.js';
import { McpAccessPolicy, type McpAccessStatus } from './mcp-access.js';
import type { McpUser } from './storage/interface.js';

/**
 * Operator-level user administration (used by the farcmd-admin CLI). The web application has no
 * admin role: whoever controls the server's database and environment is the administrator.
 * Every change is written to the audit log with actor "system".
 */
export class UserAdminError extends Error { constructor(message:string){super(message);this.name='UserAdminError';} }
export interface UserSummary { id:string; name:string; email?:string; createdAt:number; disabledAt?:number; commands:number; targets:number; installedCapabilities:number; verifiers:number; mcp:McpAccessStatus; }

export const EMAIL_PATTERN=/^\S+@\S+\.\S+$/;
export const MAX_EMAIL_LENGTH=320;
export function normalizeEmail(email:string):string{ return email.trim().toLowerCase(); }
export function passwordLengthOk(password:string):boolean{ return password.length>=12&&password.length<=1024; }
export function validatePassword(password:string):void{ if(!passwordLengthOk(password))throw new UserAdminError('Password must be 12-1024 characters.'); }

/** Tables that hold per-user data, removed when a user is deleted. The audit log is kept (append-only). */
const USER_TABLES=['web_sessions','pending_executions','execution_history','command_installations','remote_capability_ledger','verification_authorities','commands','ssh_targets','ssh_keys','oauth_grants'] as const;

export class UserAdmin {
  private readonly users:SqliteUserStore; private readonly settings:SqliteSettingsStore; private readonly audit:AuditLog; private readonly mcp:McpAccessPolicy; private readonly tokens:SqliteOAuthTokenStore;
  constructor(private readonly db:DatabaseSync){ this.users=new SqliteUserStore(db); this.settings=new SqliteSettingsStore(db); this.audit=new AuditLog(db); this.mcp=new McpAccessPolicy(db); this.tokens=new SqliteOAuthTokenStore(db); }

  find(email:string):McpUser{ const u=this.users.getUserByEmail(normalizeEmail(email)); if(!u)throw new UserAdminError('No user with email '+email+'.'); return u; }
  private count(sql:string,userId:string):number{ return Number((this.db.prepare(sql).get(userId) as any).n); }
  summary(u:McpUser):UserSummary{
    return {id:u.id,name:u.name,...(u.email?{email:u.email}:{}),createdAt:u.createdAt,...(u.disabledAt!==undefined?{disabledAt:u.disabledAt}:{}),
      commands:this.count('SELECT COUNT(*) AS n FROM commands WHERE user_id=?',u.id),targets:this.count('SELECT COUNT(*) AS n FROM ssh_targets WHERE user_id=?',u.id),
      installedCapabilities:this.count('SELECT COUNT(*) AS n FROM command_installations WHERE user_id=?',u.id),verifiers:this.count('SELECT COUNT(*) AS n FROM verification_authorities WHERE user_id=?',u.id),mcp:this.mcp.status(u.id)};
  }
  list():UserSummary[]{ return this.users.listUsers().map(u=>this.summary(u)); }

  async create(input:{email:string;name:string;password:string}):Promise<McpUser>{
    const email=normalizeEmail(input.email); const name=input.name.trim();
    if(!EMAIL_PATTERN.test(email)||email.length>MAX_EMAIL_LENGTH)throw new UserAdminError('Invalid email.');
    if(name.length<1||name.length>120)throw new UserAdminError('Name must be 1-120 characters.');
    validatePassword(input.password);
    if(this.users.getUserByEmail(email))throw new UserAdminError('A user with that email already exists.');
    const user:McpUser={id:randomUUID(),name,email,passwordHash:await hashPassword(input.password),createdAt:Date.now()};
    this.users.createUser(user);
    this.audit.record({event:'admin.user.create',actor:'system',userId:user.id,targetType:'user',targetId:user.id,details:{email,name}});
    return user;
  }

  private endSessions(userId:string):{sessions:number;refreshTokens:number}{
    const sessions=Number(this.db.prepare('DELETE FROM web_sessions WHERE user_id=?').run(userId).changes);
    const refreshTokens=this.tokens.revokeForSubject(userId);
    return {sessions,refreshTokens};
  }
  /** Ends every web session and OAuth refresh token of the user. Access tokens expire within an hour; disabled users are refused immediately. */
  logoutEverywhere(email:string):{sessions:number;refreshTokens:number}{
    const u=this.find(email); const ended=this.endSessions(u.id);
    this.audit.record({event:'admin.user.logout',actor:'system',userId:u.id,targetType:'user',targetId:u.id,details:ended});
    return ended;
  }

  async setPassword(email:string,password:string):Promise<void>{
    const u=this.find(email); validatePassword(password);
    this.db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(await hashPassword(password),u.id);
    const ended=this.endSessions(u.id);
    this.audit.record({event:'admin.user.password',actor:'system',userId:u.id,targetType:'user',targetId:u.id,details:{sessionsEnded:ended.sessions,refreshTokensRevoked:ended.refreshTokens}});
  }

  setDisabled(email:string,disabled:boolean):void{
    const u=this.find(email);
    this.db.prepare('UPDATE users SET disabled_at=? WHERE id=?').run(disabled?Date.now():null,u.id);
    const ended=disabled?this.endSessions(u.id):undefined;
    this.audit.record({event:disabled?'admin.user.disable':'admin.user.enable',actor:'system',userId:u.id,targetType:'user',targetId:u.id,details:ended?{sessionsEnded:ended.sessions,refreshTokensRevoked:ended.refreshTokens}:{}});
  }

  /** Server-wide MCP switch (all users). The process and web UI keep running; OAuth grants are untouched. */
  mcpGlobalEnabled():boolean{ return this.mcp.globalEnabled(); }
  setMcpGlobal(enabled:boolean):void{
    this.mcp.setGlobalEnabled(enabled);
    this.audit.record({event:enabled?'admin.mcp.enable_all':'admin.mcp.disable_all',actor:'system',targetType:'setting',targetId:'mcp_enabled'});
  }
  /** Operator block for one user's MCP access; the user cannot lift it from the web UI. */
  setMcpBlocked(email:string,blocked:boolean):McpAccessStatus{
    const u=this.find(email); this.mcp.setAdminBlocked(u.id,blocked);
    this.audit.record({event:blocked?'admin.mcp.block_user':'admin.mcp.unblock_user',actor:'system',userId:u.id,targetType:'user',targetId:u.id});
    return this.mcp.status(u.id);
  }
  mcpStatus(email:string):McpAccessStatus{ return this.mcp.status(this.find(email).id); }

  /**
   * Delete a user and all of their farcmd data. Capabilities and verifiers installed on remote hosts
   * cannot be removed from here (no provisioning authority), so deletion is refused while any exist
   * unless force is set; the caller should remove them in the web UI first.
   */
  delete(email:string,force=false):UserSummary{
    const u=this.find(email); const summary=this.summary(u);
    const remoteLedger=this.count("SELECT COUNT(*) AS n FROM remote_capability_ledger WHERE user_id=? AND status IN ('pending_removal','removal_failed')",u.id);
    if(!force&&(summary.installedCapabilities||summary.verifiers||remoteLedger))
      throw new UserAdminError('User still has '+summary.installedCapabilities+' installed capabilit'+(summary.installedCapabilities===1?'y':'ies')+', '+summary.verifiers+' verifier(s) and '+remoteLedger+' pending remote cleanup(s) on remote hosts. Remove them in the web UI first, or pass --force to leave them on the hosts.');
    this.db.exec('BEGIN IMMEDIATE');
    try{
      for(const table of USER_TABLES)this.db.prepare('DELETE FROM '+table+' WHERE user_id=?').run(u.id);
      this.tokens.revokeForSubject(u.id);
      this.db.prepare('DELETE FROM users WHERE id=?').run(u.id);
      this.db.exec('COMMIT');
    }catch(error){try{this.db.exec('ROLLBACK');}catch{}throw error;}
    this.audit.record({event:'admin.user.delete',actor:'system',userId:u.id,targetType:'user',targetId:u.id,details:{email:u.email??null,force,commands:summary.commands,targets:summary.targets,installedCapabilitiesLeftOnHosts:summary.installedCapabilities,verifiersLeftOnHosts:summary.verifiers,pendingRemoteCleanup:remoteLedger}});
    return summary;
  }

  registrationEnabled():boolean{ return this.settings.registrationEnabled(); }
  setRegistration(enabled:boolean):void{
    this.settings.setRegistrationEnabled(enabled);
    this.audit.record({event:enabled?'admin.registration.enable':'admin.registration.disable',actor:'system',targetType:'setting',targetId:'registration_enabled'});
  }
}
