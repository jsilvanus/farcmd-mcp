import type { DatabaseSync } from 'node:sqlite';

export interface CommandInstallationRecord {
  id:string; userId:string; commandId:string; targetId:string; masterKeyId:string;
  encryptedPrivateKey:string; publicKey:string; fingerprint:string;
  remoteScriptPath:string; authorizedKeyLine:string; installedAt?:number; createdAt:number; updatedAt:number;
}

export class SqliteCommandInstallationStore {
  constructor(private readonly db:DatabaseSync){}
  get(userId:string,commandId:string):CommandInstallationRecord|undefined{
    return this.map(this.db.prepare('SELECT * FROM command_installations WHERE user_id=? AND command_id=?').get(userId,commandId) as any);
  }
  getById(userId:string,id:string):CommandInstallationRecord|undefined{
    return this.map(this.db.prepare('SELECT * FROM command_installations WHERE user_id=? AND id=?').get(userId,id) as any);
  }
  list(userId:string):CommandInstallationRecord[]{
    const rows=this.db.prepare('SELECT * FROM command_installations WHERE user_id=? ORDER BY created_at DESC,id').all(userId) as any[];
    return rows.map(this.map).filter((x):x is CommandInstallationRecord=>x!==undefined);
  }
  create(r:CommandInstallationRecord):void{
    this.db.prepare('INSERT INTO command_installations (id,user_id,command_id,target_id,master_key_id,encrypted_private_key,public_key,fingerprint,remote_script_path,authorized_key_line,installed_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)').run(r.id,r.userId,r.commandId,r.targetId,r.masterKeyId,r.encryptedPrivateKey,r.publicKey,r.fingerprint,r.remoteScriptPath,r.authorizedKeyLine,r.installedAt??null,r.createdAt,r.updatedAt);
  }
  delete(userId:string,id:string):void{this.db.prepare('DELETE FROM command_installations WHERE user_id=? AND id=?').run(userId,id);}
  private map=(r:any):CommandInstallationRecord|undefined=>r?{
    id:r.id,userId:r.user_id,commandId:r.command_id,targetId:r.target_id,masterKeyId:r.master_key_id,
    encryptedPrivateKey:r.encrypted_private_key,publicKey:r.public_key,fingerprint:r.fingerprint,
    remoteScriptPath:r.remote_script_path,authorizedKeyLine:r.authorized_key_line,
    ...(r.installed_at!==null&&r.installed_at!==undefined?{installedAt:r.installed_at}:{}),
    createdAt:r.created_at,updatedAt:r.updated_at
  }:undefined;
}

export type LedgerStatus='installed'|'pending_removal'|'removed'|'removal_failed';
export interface RemoteCapabilityLedgerRecord {
  id:string; userId:string; targetId:string; commandId?:string; publicKey:string; fingerprint:string;
  authorizedKeyLine:string; remoteScriptPath:string; status:LedgerStatus; createdAt:number;
  lastAttemptAt?:number; removedAt?:number; lastError?:string; attemptCount:number;
}

export class SqliteRemoteCapabilityLedgerStore {
  constructor(private readonly db:DatabaseSync){}
  createPending(r:Omit<RemoteCapabilityLedgerRecord,'status'|'attemptCount'>):void{
    this.db.prepare('INSERT INTO remote_capability_ledger (id,user_id,target_id,command_id,public_key,fingerprint,authorized_key_line,remote_script_path,status,created_at,attempt_count) VALUES (?,?,?,?,?,?,?,?,?,?,0)').run(r.id,r.userId,r.targetId,r.commandId??null,r.publicKey,r.fingerprint,r.authorizedKeyLine,r.remoteScriptPath,'pending_removal',r.createdAt);
  }
  list(userId:string,status?:LedgerStatus):RemoteCapabilityLedgerRecord[]{
    const rows=(status?this.db.prepare('SELECT * FROM remote_capability_ledger WHERE user_id=? AND status=? ORDER BY created_at DESC'):this.db.prepare('SELECT * FROM remote_capability_ledger WHERE user_id=? ORDER BY created_at DESC')).all(...(status?[userId,status]:[userId])) as any[];
    return rows.map(this.map).filter((x):x is RemoteCapabilityLedgerRecord=>x!==undefined);
  }
  pendingForTarget(userId:string,targetId:string):RemoteCapabilityLedgerRecord[]{const rows=this.db.prepare("SELECT * FROM remote_capability_ledger WHERE user_id=? AND target_id=? AND status IN ('pending_removal','removal_failed') ORDER BY created_at").all(userId,targetId) as any[];return rows.map(this.map).filter((x):x is RemoteCapabilityLedgerRecord=>x!==undefined);}
  markAttempt(userId:string,id:string,error?:string):void{
    this.db.prepare('UPDATE remote_capability_ledger SET status=?,last_attempt_at=?,last_error=?,attempt_count=attempt_count+1 WHERE user_id=? AND id=?').run(error?'removal_failed':'removed',Date.now(),error??null,userId,id);
    if(!error)this.db.prepare('UPDATE remote_capability_ledger SET removed_at=? WHERE user_id=? AND id=?').run(Date.now(),userId,id);
  }
  private map=(r:any):RemoteCapabilityLedgerRecord|undefined=>r?{
    id:r.id,userId:r.user_id,targetId:r.target_id,...(r.command_id?{commandId:r.command_id}:{}),
    publicKey:r.public_key,fingerprint:r.fingerprint,authorizedKeyLine:r.authorized_key_line,remoteScriptPath:r.remote_script_path,
    status:r.status as LedgerStatus,createdAt:r.created_at,...(r.last_attempt_at?{lastAttemptAt:r.last_attempt_at}:{}),
    ...(r.removed_at?{removedAt:r.removed_at}:{}),...(r.last_error?{lastError:r.last_error}:{}),attemptCount:r.attempt_count
  }:undefined;
}
