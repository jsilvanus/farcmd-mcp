import type { DatabaseSync } from 'node:sqlite';
import type { CommandLevel } from './command-registry.js';

export type ConfirmationRequirement='none'|'human'|'password';
export function confirmationForLevel(level:CommandLevel):ConfirmationRequirement{return level<=3?'none':level===4?'human':'password';}
export interface PendingExecution {token:string;userId:string;clientId:string;commandId:string;level:CommandLevel;createdAt:number;expiresAt:number;}
export class SqliteExecutionStore {
  constructor(private readonly db:DatabaseSync){}
  create(p:PendingExecution):void{this.db.prepare('INSERT INTO pending_executions (token,user_id,client_id,command_id,level,created_at,expires_at,status) VALUES (?,?,?,?,?,?,?,?)').run(p.token,p.userId,p.clientId,p.commandId,p.level,p.createdAt,p.expiresAt,'pending');}
  get(token:string):PendingExecution|undefined{const r=this.db.prepare("SELECT token,user_id,client_id,command_id,level,created_at,expires_at FROM pending_executions WHERE token=? AND status='pending'").get(token) as any;if(!r)return undefined;if(r.expires_at<Date.now()){this.expire(token);return undefined;}return {token:r.token,userId:r.user_id,clientId:r.client_id,commandId:r.command_id,level:r.level,createdAt:r.created_at,expiresAt:r.expires_at};}
  consume(token:string):PendingExecution|undefined{const p=this.get(token);if(!p)return undefined;const result=this.db.prepare("UPDATE pending_executions SET status='consumed' WHERE token=? AND status='pending'").run(token);return Number(result.changes)===1?p:undefined;}
  expire(token:string):void{this.db.prepare("UPDATE pending_executions SET status='expired' WHERE token=? AND status='pending'").run(token);}
}
