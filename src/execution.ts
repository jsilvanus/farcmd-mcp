import type { DatabaseSync } from 'node:sqlite';
import type { CommandLevel } from './command-registry.js';

export type ConfirmationRequirement='none'|'human'|'password';
export function confirmationForLevel(level:CommandLevel):ConfirmationRequirement{return level<=3?'none':level===4?'human':'password';}
export interface PendingExecution {token:string;userId:string;clientId:string;commandId:string;level:CommandLevel;createdAt:number;expiresAt:number;status?:'pending'|'completed';result?:ExecutionResult;}
export interface ExecutionResult {exitCode:number|null;stdout:string;stderr:string;durationMs:number;signal?:string;}
export class SqliteExecutionStore {
  constructor(private readonly db:DatabaseSync){}
  create(p:PendingExecution):void{this.db.prepare('INSERT INTO pending_executions (token,user_id,client_id,command_id,level,created_at,expires_at,status) VALUES (?,?,?,?,?,?,?,?)').run(p.token,p.userId,p.clientId,p.commandId,p.level,p.createdAt,p.expiresAt,'pending');}
  get(token:string):PendingExecution|undefined{
    const r=this.db.prepare('SELECT token,user_id,client_id,command_id,level,created_at,expires_at,status,exit_code,stdout,stderr,duration_ms,signal FROM pending_executions WHERE token=?').get(token) as any;
    if(!r)return undefined;
    if(r.status==='pending'&&r.expires_at<Date.now()){this.expire(token);return undefined;}
    return {token:r.token,userId:r.user_id,clientId:r.client_id,commandId:r.command_id,level:r.level,createdAt:r.created_at,expiresAt:r.expires_at,status:r.status,result:r.status==='completed'?{exitCode:r.exit_code,stdout:r.stdout??'',stderr:r.stderr??'',durationMs:r.duration_ms, ...(r.signal?{signal:r.signal}:{})}:undefined};
  }
  consume(token:string):PendingExecution|undefined{const p=this.get(token);if(!p||p.status!=='pending')return undefined;const result=this.db.prepare("UPDATE pending_executions SET status='consumed' WHERE token=? AND status='pending'").run(token);return Number(result.changes)===1?p:undefined;}
  consumeCompleted(token:string):ExecutionResult|undefined{const p=this.get(token);if(!p||p.status!=='completed'||!p.result)return undefined;const result=this.db.prepare("UPDATE pending_executions SET status='consumed' WHERE token=? AND status='completed'").run(token);return Number(result.changes)===1?p.result:undefined;}
  complete(token:string,result:ExecutionResult):void{this.db.prepare("UPDATE pending_executions SET status='completed',exit_code=?,stdout=?,stderr=?,duration_ms=?,signal=? WHERE token=? AND status='pending'").run(result.exitCode,result.stdout,result.stderr,result.durationMs,result.signal??null,token);}
  expire(token:string):void{this.db.prepare("UPDATE pending_executions SET status='expired' WHERE token=? AND status='pending'").run(token);}
  cleanup(now=Date.now()):void{this.db.prepare("DELETE FROM pending_executions WHERE expires_at < ? OR status IN ('consumed','expired') AND expires_at < ?").run(now-24*60*60_000,now-24*60*60_000);}
}
