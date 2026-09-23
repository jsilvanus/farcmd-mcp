import type { DatabaseSync } from 'node:sqlite';
import { SqliteSettingsStore } from './storage/settings.js';

/**
 * MCP kill switch. MCP access for a user is allowed only if all three switches allow it:
 *   global  — operator, all users           (farcmd-admin mcp disable --all)
 *   admin   — operator, one user            (farcmd-admin mcp disable --email …); the user cannot undo it
 *   user    — the user themselves           (web UI "MCP access" button)
 * The farcmd process and the web UI keep running. OAuth grants and tokens are left intact, so
 * turning MCP back on takes effect immediately without clients reconnecting.
 */
export type McpDenialReason='global'|'admin'|'user'|'account';
export type McpAccessDecision={allowed:true}|{allowed:false;reason:McpDenialReason;message:string};
export interface McpAccessStatus { globalEnabled:boolean; adminBlocked:boolean; userEnabled:boolean; effective:boolean; reason?:McpDenialReason; }

const MESSAGES:Record<McpDenialReason,string>={
  global:'MCP access is disabled on this farcmd server by the administrator.',
  admin:'MCP access is disabled for this account by the administrator.',
  user:'MCP access is turned off for this account. It can be turned on again in the farcmd web UI.',
  account:'This farcmd account is disabled.',
};
export class McpAccessDenied extends Error { constructor(readonly reason:McpDenialReason){super(MESSAGES[reason]);this.name='McpAccessDenied';} }

export function migrateMcpAccess(db:DatabaseSync):void{
  for(const column of ['mcp_user_disabled_at INTEGER','mcp_admin_blocked_at INTEGER'])try{db.exec('ALTER TABLE users ADD COLUMN '+column);}catch{}
}

export class McpAccessPolicy {
  private readonly settings:SqliteSettingsStore;
  constructor(private readonly db:DatabaseSync){ this.settings=new SqliteSettingsStore(db); }
  globalEnabled():boolean{ return this.settings.get('mcp_enabled')!=='false'; }
  setGlobalEnabled(enabled:boolean):void{ this.settings.set('mcp_enabled',enabled?'true':'false'); }
  setUserEnabled(userId:string,enabled:boolean):void{ this.db.prepare('UPDATE users SET mcp_user_disabled_at=? WHERE id=?').run(enabled?null:Date.now(),userId); }
  setAdminBlocked(userId:string,blocked:boolean):void{ this.db.prepare('UPDATE users SET mcp_admin_blocked_at=? WHERE id=?').run(blocked?Date.now():null,userId); }
  status(userId:string):McpAccessStatus{
    const row=this.db.prepare('SELECT disabled_at,mcp_user_disabled_at,mcp_admin_blocked_at FROM users WHERE id=?').get(userId) as any;
    const globalEnabled=this.globalEnabled(); const adminBlocked=row?.mcp_admin_blocked_at!=null; const userEnabled=row?row.mcp_user_disabled_at==null:false;
    const reason:McpDenialReason|undefined=!row||row.disabled_at!=null?'account':!globalEnabled?'global':adminBlocked?'admin':!userEnabled?'user':undefined;
    return {globalEnabled,adminBlocked,userEnabled,effective:reason===undefined,...(reason?{reason}:{})};
  }
  check(userId:string):McpAccessDecision{
    const {reason}=this.status(userId);
    return reason?{allowed:false,reason,message:MESSAGES[reason]}:{allowed:true};
  }
  assertAllowed(userId:string):void{ const d=this.check(userId); if(!d.allowed)throw new McpAccessDenied(d.reason); }
}
