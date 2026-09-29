import type { DatabaseSync } from 'node:sqlite';
import { verify } from '@node-rs/argon2';
import { createHash } from 'node:crypto';

export function hashCommandContent(type:CommandType,content:string):string{return createHash('sha256').update(type+'\0'+content,'utf8').digest('hex');}

export type CommandLevel = 1|2|3|4|5;
export type CommandType = 'shell'|'bash_script';

export interface CommandRecord {
  id:string; userId:string; targetId:string; name:string; description:string;
  type:CommandType; content:string; commandSha256?:string; level:CommandLevel; enabled:boolean; createdAt:number; updatedAt:number;
  /** Level 4/5: show stdout/stderr to the person who approves (web approval page or web Run). */
  showOutputOnApproval?:boolean;
  /** Levels 1–2: opt in to the integrity verification that levels 3–5 always get. */
  verifyIntegrity?:boolean;
  /**
   * Starts at 1 and goes up by one whenever what runs changes: content, type, target or level (not name,
   * description or settings). MCP clients see it with changedAt, so they can notice that a command changed.
   */
  version?:number; changedAt?:number;
}

/** Levels 3–5 are always verified before they run; levels 1–2 only when the command opts in. */
export function requiresIntegrityVerification(c:Pick<CommandRecord,'level'|'verifyIntegrity'>):boolean{return c.level>=3||!!c.verifyIntegrity;}

const COMMAND_COLUMNS='id,user_id,target_id,name,description,type,content,command_sha256,level,enabled,show_output_on_approval,verify_integrity,version,changed_at,created_at,updated_at';
export class SqliteCommandStore {
  constructor(private readonly db:DatabaseSync){}
  list(userId:string):CommandRecord[]{const rows=this.db.prepare('SELECT '+COMMAND_COLUMNS+' FROM commands WHERE user_id=? ORDER BY name,id').all(userId) as any[];return rows.map(this.map).filter((c):c is CommandRecord=>c!==undefined);}
  get(userId:string,id:string):CommandRecord|undefined{return this.map(this.db.prepare('SELECT '+COMMAND_COLUMNS+' FROM commands WHERE user_id=? AND id=?').get(userId,id) as any);}
  create(r:CommandRecord):void{this.db.prepare('INSERT INTO commands (id,user_id,target_id,name,description,type,content,command_sha256,level,enabled,show_output_on_approval,verify_integrity,version,changed_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?)').run(r.id,r.userId,r.targetId,r.name,r.description,r.type,r.content,hashCommandContent(r.type,r.content),r.level,r.enabled?1:0,r.showOutputOnApproval?1:0,r.verifyIntegrity?1:0,r.createdAt,r.createdAt,r.updatedAt);}
  /** Bumps version and changed_at when what runs changes (the CASE compares against the row before the update). */
  update(r:CommandRecord):void{this.db.prepare('UPDATE commands SET version=version+(CASE WHEN content<>?1 OR type<>?2 OR target_id<>?3 OR level<>?4 THEN 1 ELSE 0 END),changed_at=(CASE WHEN content<>?1 OR type<>?2 OR target_id<>?3 OR level<>?4 THEN ?5 ELSE changed_at END),target_id=?3,name=?6,description=?7,type=?2,content=?1,command_sha256=?8,level=?4,enabled=?9,show_output_on_approval=?10,verify_integrity=?11,updated_at=?5 WHERE user_id=?12 AND id=?13').run(r.content,r.type,r.targetId,r.level,r.updatedAt,r.name,r.description,hashCommandContent(r.type,r.content),r.enabled?1:0,r.showOutputOnApproval?1:0,r.verifyIntegrity?1:0,r.userId,r.id);}
  delete(userId:string,id:string):void{this.db.prepare('DELETE FROM commands WHERE user_id=? AND id=?').run(userId,id);}
  hasExecutionPassword(userId:string,id:string):boolean{const r=this.db.prepare('SELECT execution_password_hash FROM commands WHERE user_id=? AND id=?').get(userId,id) as any;return typeof r?.execution_password_hash==='string'&&r.execution_password_hash.length>0;}
  clearExecutionPassword(userId:string,id:string):void{this.db.prepare('UPDATE commands SET execution_password_hash=NULL,updated_at=? WHERE user_id=? AND id=?').run(Date.now(),userId,id);}
  setExecutionPassword(userId:string,id:string,passwordHash:string):void{const result=this.db.prepare('UPDATE commands SET execution_password_hash=?,updated_at=? WHERE user_id=? AND id=? AND level=5').run(passwordHash,Date.now(),userId,id);if(Number(result.changes)!==1)throw new Error('Level 5 command not found.');}
  async verifyExecutionPassword(userId:string,id:string,password:string):Promise<boolean>{const r=this.db.prepare('SELECT execution_password_hash FROM commands WHERE user_id=? AND id=? AND level=5').get(userId,id) as any;return !!r?.execution_password_hash&&await verify(r.execution_password_hash,password);}
  private map=(r:any):CommandRecord|undefined=>r?{id:r.id,userId:r.user_id,targetId:r.target_id,name:r.name,description:r.description,type:(r.type==='bash_script'?'bash_script':'shell'),content:r.content,...(r.command_sha256?{commandSha256:r.command_sha256}:{}),level:r.level as CommandLevel,enabled:!!r.enabled,showOutputOnApproval:!!r.show_output_on_approval,verifyIntegrity:!!r.verify_integrity,version:r.version??1,changedAt:r.changed_at??r.updated_at,createdAt:r.created_at,updatedAt:r.updated_at}:undefined;
}
