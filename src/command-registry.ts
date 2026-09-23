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
}

export class SqliteCommandStore {
  constructor(private readonly db:DatabaseSync){}
  list(userId:string):CommandRecord[]{const rows=this.db.prepare('SELECT id,user_id,target_id,name,description,type,content,command_sha256,level,enabled,show_output_on_approval,created_at,updated_at FROM commands WHERE user_id=? ORDER BY name,id').all(userId) as any[];return rows.map(this.map).filter((c):c is CommandRecord=>c!==undefined);}
  get(userId:string,id:string):CommandRecord|undefined{return this.map(this.db.prepare('SELECT id,user_id,target_id,name,description,type,content,command_sha256,level,enabled,show_output_on_approval,created_at,updated_at FROM commands WHERE user_id=? AND id=?').get(userId,id) as any);}
  create(r:CommandRecord):void{this.db.prepare('INSERT INTO commands (id,user_id,target_id,name,description,type,content,command_sha256,level,enabled,show_output_on_approval,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)').run(r.id,r.userId,r.targetId,r.name,r.description,r.type,r.content,hashCommandContent(r.type,r.content),r.level,r.enabled?1:0,r.showOutputOnApproval?1:0,r.createdAt,r.updatedAt);}
  update(r:CommandRecord):void{this.db.prepare('UPDATE commands SET target_id=?,name=?,description=?,type=?,content=?,command_sha256=?,level=?,enabled=?,show_output_on_approval=?,updated_at=? WHERE user_id=? AND id=?').run(r.targetId,r.name,r.description,r.type,r.content,hashCommandContent(r.type,r.content),r.level,r.enabled?1:0,r.showOutputOnApproval?1:0,r.updatedAt,r.userId,r.id);}
  delete(userId:string,id:string):void{this.db.prepare('DELETE FROM commands WHERE user_id=? AND id=?').run(userId,id);}
  hasExecutionPassword(userId:string,id:string):boolean{const r=this.db.prepare('SELECT execution_password_hash FROM commands WHERE user_id=? AND id=?').get(userId,id) as any;return typeof r?.execution_password_hash==='string'&&r.execution_password_hash.length>0;}
  clearExecutionPassword(userId:string,id:string):void{this.db.prepare('UPDATE commands SET execution_password_hash=NULL,updated_at=? WHERE user_id=? AND id=?').run(Date.now(),userId,id);}
  setExecutionPassword(userId:string,id:string,passwordHash:string):void{const result=this.db.prepare('UPDATE commands SET execution_password_hash=?,updated_at=? WHERE user_id=? AND id=? AND level=5').run(passwordHash,Date.now(),userId,id);if(Number(result.changes)!==1)throw new Error('Level 5 command not found.');}
  async verifyExecutionPassword(userId:string,id:string,password:string):Promise<boolean>{const r=this.db.prepare('SELECT execution_password_hash FROM commands WHERE user_id=? AND id=? AND level=5').get(userId,id) as any;return !!r?.execution_password_hash&&await verify(r.execution_password_hash,password);}
  private map=(r:any):CommandRecord|undefined=>r?{id:r.id,userId:r.user_id,targetId:r.target_id,name:r.name,description:r.description,type:(r.type==='bash_script'?'bash_script':'shell'),content:r.content,...(r.command_sha256?{commandSha256:r.command_sha256}:{}),level:r.level as CommandLevel,enabled:!!r.enabled,showOutputOnApproval:!!r.show_output_on_approval,createdAt:r.created_at,updatedAt:r.updated_at}:undefined;
}
