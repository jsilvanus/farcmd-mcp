import type { DatabaseSync } from 'node:sqlite';
import { verify } from '@node-rs/argon2';

export type CommandLevel = 1|2|3|4|5;

export interface CommandRecord {
  id:string; userId:string; targetId:string; name:string; description:string;
  shellCommand:string; level:CommandLevel; enabled:boolean; createdAt:number; updatedAt:number;
}

export class SqliteCommandStore {
  constructor(private readonly db:DatabaseSync){}
  list(userId:string):CommandRecord[]{const rows=this.db.prepare('SELECT id,user_id,target_id,name,description,shell_command,level,enabled,created_at,updated_at FROM commands WHERE user_id=? ORDER BY name,id').all(userId) as any[];return rows.map(this.map);}
  get(userId:string,id:string):CommandRecord|undefined{return this.map(this.db.prepare('SELECT id,user_id,target_id,name,description,shell_command,level,enabled,created_at,updated_at FROM commands WHERE user_id=? AND id=?').get(userId,id) as any);}
  create(r:CommandRecord):void{this.db.prepare('INSERT INTO commands (id,user_id,target_id,name,description,shell_command,level,enabled,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)').run(r.id,r.userId,r.targetId,r.name,r.description,r.shellCommand,r.level,r.enabled?1:0,r.createdAt,r.updatedAt);}
  update(r:CommandRecord):void{this.db.prepare('UPDATE commands SET target_id=?,name=?,description=?,shell_command=?,level=?,enabled=?,updated_at=? WHERE user_id=? AND id=?').run(r.targetId,r.name,r.description,r.shellCommand,r.level,r.enabled?1:0,r.updatedAt,r.userId,r.id);}
  delete(userId:string,id:string):void{this.db.prepare('DELETE FROM commands WHERE user_id=? AND id=?').run(userId,id);}
  hasExecutionPassword(userId:string,id:string):boolean{const r=this.db.prepare('SELECT execution_password_hash FROM commands WHERE user_id=? AND id=?').get(userId,id) as any;return typeof r?.execution_password_hash==='string'&&r.execution_password_hash.length>0;}
  clearExecutionPassword(userId:string,id:string):void{this.db.prepare('UPDATE commands SET execution_password_hash=NULL,updated_at=? WHERE user_id=? AND id=?').run(Date.now(),userId,id);}
  setExecutionPassword(userId:string,id:string,passwordHash:string):void{const result=this.db.prepare('UPDATE commands SET execution_password_hash=?,updated_at=? WHERE user_id=? AND id=? AND level=5').run(passwordHash,Date.now(),userId,id);if(Number(result.changes)!==1)throw new Error('Level 5 command not found.');}
  async verifyExecutionPassword(userId:string,id:string,password:string):Promise<boolean>{const r=this.db.prepare('SELECT execution_password_hash FROM commands WHERE user_id=? AND id=? AND level=5').get(userId,id) as any;return !!r?.execution_password_hash&&await verify(r.execution_password_hash,password);}
  private map=(r:any):CommandRecord=>r?{id:r.id,userId:r.user_id,targetId:r.target_id,name:r.name,description:r.description,shellCommand:r.shell_command,level:r.level as CommandLevel,enabled:!!r.enabled,createdAt:r.created_at,updatedAt:r.updated_at} as CommandRecord;
}
