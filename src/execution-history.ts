import type { DatabaseSync } from 'node:sqlite';
import type { CommandLevel } from './command-registry.js';

export type ExecutionStatus='success'|'failed'|'timeout';

export interface ExecutionHistoryRecord {
  id:string; userId:string; clientId:string; commandId:string; commandName:string; targetId:string;
  level:CommandLevel; startedAt:number; endedAt:number; durationMs:number; exitCode:number|null;
  stdout:string; stderr:string; status:ExecutionStatus; error?:string;
}

export class SqliteExecutionHistoryStore {
  constructor(private readonly db:DatabaseSync){}
  create(record:ExecutionHistoryRecord):void{
    this.db.prepare('INSERT INTO execution_history (id,user_id,client_id,command_id,command_name,target_id,level,started_at,ended_at,duration_ms,exit_code,stdout,stderr,status,error) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
      .run(record.id,record.userId,record.clientId,record.commandId,record.commandName,record.targetId,record.level,record.startedAt,record.endedAt,record.durationMs,record.exitCode,record.stdout,record.stderr,record.status,record.error??null);
  }
  list(userId:string,options:{clientId?:string;commandId?:string;level?:CommandLevel;status?:ExecutionStatus;search?:string;limit?:number;offset?:number}={}):ExecutionHistoryRecord[]{
    const where=['user_id=?']; const args:any[]=[userId];
    if(options.clientId){where.push('client_id=?');args.push(options.clientId);}
    if(options.commandId){where.push('command_id=?');args.push(options.commandId);}
    if(options.level){where.push('level=?');args.push(options.level);}
    if(options.status){where.push('status=?');args.push(options.status);}
    if(options.search){where.push('(command_name LIKE ? OR client_id LIKE ? OR stdout LIKE ? OR stderr LIKE ?)');const q='%'+options.search+'%';args.push(q,q,q,q);}
    const limit=Math.min(Math.max(options.limit??50,1),200); const offset=Math.max(options.offset??0,0);
    args.push(limit,offset);
    const rows=this.db.prepare(`SELECT * FROM execution_history WHERE ${where.join(' AND ')} ORDER BY started_at DESC,id DESC LIMIT ? OFFSET ?`).all(...args) as any[];
    return rows.map(this.map);
  }
  count(userId:string):number{return Number((this.db.prepare('SELECT COUNT(*) AS count FROM execution_history WHERE user_id=?').get(userId) as any).count);}
  successfulCounts(userId:string):Array<{commandId:string;commandName:string;level:CommandLevel;count:number}>{return (this.db.prepare("SELECT command_id,command_name,level,COUNT(*) AS count FROM execution_history WHERE user_id=? AND status='success' GROUP BY command_id,command_name,level ORDER BY count DESC,command_name ASC").all(userId) as any[]).map(r=>({commandId:r.command_id,commandName:r.command_name,level:r.level,count:Number(r.count)}));}
  private map=(r:any):ExecutionHistoryRecord=>({id:r.id,userId:r.user_id,clientId:r.client_id,commandId:r.command_id,commandName:r.command_name,targetId:r.target_id,level:r.level,startedAt:r.started_at,endedAt:r.ended_at,durationMs:r.duration_ms,exitCode:r.exit_code===null?null:r.exit_code,stdout:r.stdout??'',stderr:r.stderr??'',status:r.status,error:r.error??undefined});
}
