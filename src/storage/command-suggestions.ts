import type { DatabaseSync } from 'node:sqlite';
import type { CommandLevel, CommandType } from '../command-registry.js';

/**
 * Commands suggested by MCP clients. A suggestion is inert data: it never becomes a command by itself.
 * The signed-in person reviews it in the web UI and either creates a command from it (the ordinary
 * create form, then install and enable as for any command) or dismisses it.
 */
export type SuggestionStatus='pending'|'accepted'|'dismissed';
export interface CommandSuggestionRecord {
  id:string; userId:string; clientId:string; clientName:string;
  name:string; description:string; type:CommandType; content:string; level:CommandLevel;
  /** Free text from the client about where the command should run; the person picks the actual target. */
  targetHint:string; rationale:string;
  status:SuggestionStatus; commandId?:string; createdAt:number; resolvedAt?:number;
}
export interface SuggestionInput { name:string; description:string; type:CommandType; content:string; level:CommandLevel; targetHint:string; rationale:string; }

/** Open suggestions per user; a client cannot flood the review list. */
export const MAX_PENDING_SUGGESTIONS=50;
export const SUGGESTION_LIMITS={name:120,description:2000,content:100_000,targetHint:200,rationale:2000} as const;

/** Same rules as a command created in the web UI (web-api.ts), plus the suggestion-only fields. */
export function validateSuggestion(s:SuggestionInput):string|undefined{
  const content=s.type==='shell'?s.content.trim():s.content;
  if(!s.name.trim()||s.name.trim().length>SUGGESTION_LIMITS.name)return 'name must be 1-'+SUGGESTION_LIMITS.name+' characters.';
  if(s.description.length>SUGGESTION_LIMITS.description)return 'description must be at most '+SUGGESTION_LIMITS.description+' characters.';
  if(!content||content.length>SUGGESTION_LIMITS.content)return 'content must be 1-'+SUGGESTION_LIMITS.content+' characters.';
  if(s.type==='shell'&&/\r|\n/.test(content))return 'A shell command must be a single line; use type bash_script for several lines.';
  if(s.targetHint.length>SUGGESTION_LIMITS.targetHint)return 'targetHint must be at most '+SUGGESTION_LIMITS.targetHint+' characters.';
  if(s.rationale.length>SUGGESTION_LIMITS.rationale)return 'rationale must be at most '+SUGGESTION_LIMITS.rationale+' characters.';
  return undefined;
}

export function migrateCommandSuggestions(db:DatabaseSync):void{
  db.exec('CREATE TABLE IF NOT EXISTS command_suggestions (id TEXT PRIMARY KEY,user_id TEXT NOT NULL,client_id TEXT NOT NULL,client_name TEXT NOT NULL,name TEXT NOT NULL,description TEXT NOT NULL,type TEXT NOT NULL,content TEXT NOT NULL,level INTEGER NOT NULL,target_hint TEXT NOT NULL,rationale TEXT NOT NULL,status TEXT NOT NULL,command_id TEXT,created_at INTEGER NOT NULL,resolved_at INTEGER);'+
    'CREATE INDEX IF NOT EXISTS command_suggestions_user_status ON command_suggestions(user_id,status,created_at)');
}

const COLUMNS='id,user_id,client_id,client_name,name,description,type,content,level,target_hint,rationale,status,command_id,created_at,resolved_at';
export class SqliteCommandSuggestionStore {
  constructor(private readonly db:DatabaseSync){ migrateCommandSuggestions(db); }
  create(r:CommandSuggestionRecord):void{
    this.db.prepare('INSERT INTO command_suggestions ('+COLUMNS+') VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(r.id,r.userId,r.clientId,r.clientName,r.name,r.description,r.type,r.content,r.level,r.targetHint,r.rationale,r.status,r.commandId??null,r.createdAt,r.resolvedAt??null);
  }
  get(userId:string,id:string):CommandSuggestionRecord|undefined{return this.map(this.db.prepare('SELECT '+COLUMNS+' FROM command_suggestions WHERE user_id=? AND id=?').get(userId,id));}
  /** Newest first. */
  list(userId:string,status?:SuggestionStatus,clientId?:string,limit=100):CommandSuggestionRecord[]{
    const where=['user_id=?'],args:(string|number)[]=[userId];
    if(status){where.push('status=?');args.push(status);}
    if(clientId){where.push('client_id=?');args.push(clientId);}
    const rows=this.db.prepare('SELECT '+COLUMNS+' FROM command_suggestions WHERE '+where.join(' AND ')+' ORDER BY created_at DESC,id LIMIT ?').all(...args,limit);
    return rows.map(this.map).filter((x):x is CommandSuggestionRecord=>x!==undefined);
  }
  countPending(userId:string):number{return Number((this.db.prepare("SELECT count(*) AS n FROM command_suggestions WHERE user_id=? AND status='pending'").get(userId) as {n:number}).n);}
  /** Accept or dismiss a pending suggestion. False when it is not pending (already resolved, or not this user's). */
  resolve(userId:string,id:string,status:'accepted'|'dismissed',commandId?:string):boolean{
    const r=this.db.prepare("UPDATE command_suggestions SET status=?,command_id=?,resolved_at=? WHERE user_id=? AND id=? AND status='pending'").run(status,commandId??null,Date.now(),userId,id);
    return Number(r.changes)===1;
  }
  private map=(r:any):CommandSuggestionRecord|undefined=>r?{
    id:r.id,userId:r.user_id,clientId:r.client_id,clientName:r.client_name,name:r.name,description:r.description,
    type:r.type==='bash_script'?'bash_script':'shell',content:r.content,level:r.level as CommandLevel,targetHint:r.target_hint,rationale:r.rationale,
    status:r.status as SuggestionStatus,...(r.command_id?{commandId:r.command_id}:{}),createdAt:r.created_at,...(r.resolved_at!=null?{resolvedAt:r.resolved_at}:{}),
  }:undefined;
}
