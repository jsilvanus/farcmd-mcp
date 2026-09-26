import type { DatabaseSync } from 'node:sqlite';
import { createHmac, hkdfSync, randomUUID, timingSafeEqual } from 'node:crypto';
import { masterKey } from './crypto-at-rest.js';
import { DAY_MS, envRetentionMs } from './config.js';

/**
 * Append-only, tamper-evident audit log (table security_events).
 *
 * Every entry carries a sequence number and hash = HMAC-SHA256(K, prev_hash || canonical(entry)), where
 * K is derived from FARCMD_ENCRYPTION_KEY with HKDF. Editing, reordering or deleting an entry in the
 * middle breaks the chain, and someone with write access to the database alone (without the
 * environment key) cannot recompute it. Limits: truncating the newest entries is only detectable
 * against an externally noted head hash, and pruning intentionally drops the oldest entries (an
 * `audit.pruned` entry records the last removed hash).
 *
 * Details are sanitized: keys that look like secrets are never stored.
 */
export type AuditActor='web'|'mcp'|'oauth'|'system';
export type AuditOutcome='success'|'failure';
export interface AuditEntryInput {
  event:string; actor:AuditActor; outcome?:AuditOutcome;
  userId?:string|undefined; clientId?:string|undefined; ip?:string|undefined;
  targetType?:string|undefined; targetId?:string|undefined; details?:Record<string,unknown>|undefined;
}
export interface AuditEntry {
  seq:number; id:string; createdAt:number; userId?:string; clientId?:string; actor:AuditActor; event:string; outcome:AuditOutcome;
  ip?:string; targetType?:string; targetId?:string; details?:Record<string,unknown>; prevHash:string; hash:string;
}
export interface AuditQuery { event?:string; outcome?:AuditOutcome; search?:string; limit?:number; offset?:number; }
export interface AuditVerification { ok:boolean; checked:number; legacy:number; firstSeq?:number; headSeq?:number; headHash?:string; brokenAtSeq?:number; reason?:string; }

const GENESIS='0'.repeat(64);
const SECRET_KEY=/pass(word|phrase)?|secret|private.?key|token|cookie|authorization|^key$/i;
const MAX_DETAIL_STRING=500;

function chainKey():Buffer{
  return Buffer.from(hkdfSync('sha256',masterKey(),Buffer.alloc(0),'farcmd-audit-chain-v1',32));
}
/** Drop secret-looking keys and bound sizes; values are only ever primitives or arrays/objects of them. */
export function sanitizeDetails(value:unknown,depth=0):unknown{
  if(value===null||typeof value==='number'||typeof value==='boolean')return value;
  if(typeof value==='string')return value.length>MAX_DETAIL_STRING?value.slice(0,MAX_DETAIL_STRING)+'…':value;
  if(depth>3)return undefined;
  if(Array.isArray(value))return value.slice(0,50).map(v=>sanitizeDetails(v,depth+1));
  if(typeof value==='object'){
    const out:Record<string,unknown>={};
    for(const [k,v] of Object.entries(value as Record<string,unknown>)){if(SECRET_KEY.test(k))continue;const s=sanitizeDetails(v,depth+1);if(s!==undefined)out[k]=s;}
    return out;
  }
  return undefined;
}
function canonical(e:Omit<AuditEntry,'hash'|'details'>&{detailsJson:string|null}):string{
  return JSON.stringify([e.seq,e.id,e.createdAt,e.userId??null,e.clientId??null,e.actor,e.event,e.outcome,e.ip??null,e.targetType??null,e.targetId??null,e.detailsJson]);
}
function mac(key:Buffer,prevHash:string,body:string):string{ return createHmac('sha256',key).update(prevHash).update('\n').update(body).digest('hex'); }

export function migrateAuditTable(db:DatabaseSync):void{
  for(const column of ['seq INTEGER','actor TEXT','outcome TEXT','ip TEXT','target_type TEXT','target_id TEXT','prev_hash TEXT','hash TEXT'])
    try{db.exec('ALTER TABLE security_events ADD COLUMN '+column);}catch{}
  db.exec('CREATE UNIQUE INDEX IF NOT EXISTS security_events_seq ON security_events(seq)');
  db.exec('CREATE INDEX IF NOT EXISTS security_events_user ON security_events(user_id,created_at)');
}

export class AuditLog {
  constructor(private readonly db:DatabaseSync){}

  /** Never throws: auditing must not break the action being audited. Failures go to stderr. */
  record(input:AuditEntryInput):void{
    try{this.append(input);}catch(error){console.error('farcmd audit: failed to record '+input.event+': '+(error instanceof Error?error.message:String(error)));}
  }
  append(input:AuditEntryInput):AuditEntry{
    const key=chainKey();
    const details=input.details?sanitizeDetails(input.details) as Record<string,unknown>:undefined;
    const detailsJson=details&&Object.keys(details).length?JSON.stringify(details):null;
    // node:sqlite is synchronous, so reading the head and inserting cannot interleave with another append.
    this.db.exec('BEGIN IMMEDIATE');
    try{
      const head=this.db.prepare('SELECT seq,hash FROM security_events WHERE seq IS NOT NULL ORDER BY seq DESC LIMIT 1').get() as any;
      const entry={seq:(head?.seq??0)+1,id:randomUUID(),createdAt:Date.now(),
        ...(input.userId?{userId:input.userId}:{}),...(input.clientId?{clientId:input.clientId}:{}),actor:input.actor,event:input.event,outcome:input.outcome??'success',
        ...(input.ip?{ip:input.ip}:{}),...(input.targetType?{targetType:input.targetType}:{}),...(input.targetId?{targetId:input.targetId}:{}),prevHash:head?.hash??GENESIS};
      const hash=mac(key,entry.prevHash,canonical({...entry,detailsJson}));
      this.db.prepare('INSERT INTO security_events (id,user_id,client_id,event,details,created_at,seq,actor,outcome,ip,target_type,target_id,prev_hash,hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
        .run(entry.id,entry.userId??null,entry.clientId??null,entry.event,detailsJson,entry.createdAt,entry.seq,entry.actor,entry.outcome,entry.ip??null,entry.targetType??null,entry.targetId??null,entry.prevHash,hash);
      this.db.exec('COMMIT');
      return {...entry,...(details&&detailsJson?{details}:{}),hash};
    }catch(error){try{this.db.exec('ROLLBACK');}catch{}throw error;}
  }

  list(userId:string,q:AuditQuery={}):{entries:AuditEntry[];total:number}{
    const where=['user_id=?','seq IS NOT NULL']; const args:(string|number)[]=[userId];
    if(q.event){where.push('(event=? OR event LIKE ?)');args.push(q.event,q.event+'.%');}
    if(q.outcome){where.push('outcome=?');args.push(q.outcome);}
    if(q.search){where.push('(event LIKE ? OR target_id LIKE ? OR client_id LIKE ? OR details LIKE ?)');const s='%'+q.search+'%';args.push(s,s,s,s);}
    const total=Number((this.db.prepare('SELECT COUNT(*) AS n FROM security_events WHERE '+where.join(' AND ')).get(...args) as any).n);
    const limit=Math.min(Math.max(q.limit??100,1),500); const offset=Math.max(q.offset??0,0);
    const rows=this.db.prepare('SELECT * FROM security_events WHERE '+where.join(' AND ')+' ORDER BY seq DESC LIMIT ? OFFSET ?').all(...args,limit,offset) as any[];
    return {entries:rows.map(r=>this.map(r)),total};
  }

  /** Recompute the whole chain. Entries written before the chain existed (no seq) are counted as legacy. */
  verify():AuditVerification{
    const key=chainKey();
    const legacy=Number((this.db.prepare('SELECT COUNT(*) AS n FROM security_events WHERE seq IS NULL').get() as any).n);
    const rows=this.db.prepare('SELECT * FROM security_events WHERE seq IS NOT NULL ORDER BY seq').all() as any[];
    let prev:string|undefined; let prevSeq:number|undefined; let checked=0;
    for(const r of rows){
      const seq=Number(r.seq);
      if(prevSeq!==undefined&&seq!==prevSeq+1)return {ok:false,checked,legacy,brokenAtSeq:seq,reason:'Entries '+(prevSeq+1)+'–'+(seq-1)+' are missing.'};
      if(prev!==undefined&&r.prev_hash!==prev)return {ok:false,checked,legacy,brokenAtSeq:seq,reason:'Entry does not link to its predecessor.'};
      const expected=Buffer.from(mac(key,String(r.prev_hash),canonical({seq,id:r.id,createdAt:r.created_at,userId:r.user_id??undefined,clientId:r.client_id??undefined,actor:r.actor,event:r.event,outcome:r.outcome,ip:r.ip??undefined,targetType:r.target_type??undefined,targetId:r.target_id??undefined,prevHash:r.prev_hash,detailsJson:r.details??null})),'hex');
      const actual=Buffer.from(String(r.hash??''),'hex');
      if(actual.length!==expected.length||!timingSafeEqual(actual,expected))return {ok:false,checked,legacy,brokenAtSeq:seq,reason:'Entry content or hash was modified.'};
      prev=r.hash; prevSeq=seq; checked++;
    }
    const first=rows[0]; const last=rows[rows.length-1];
    return {ok:true,checked,legacy,...(first?{firstSeq:Number(first.seq)}:{}),...(last?{headSeq:Number(last.seq),headHash:String(last.hash)}:{})};
  }

  /** Remove entries older than maxAgeMs from the start of the chain; the removal itself is audited. */
  prune(maxAgeMs:number):number{
    const cutoff=Date.now()-maxAgeMs;
    const last=this.db.prepare('SELECT seq,hash FROM security_events WHERE seq IS NOT NULL AND created_at<? ORDER BY seq DESC LIMIT 1').get(cutoff) as any;
    const legacy=Number(this.db.prepare('DELETE FROM security_events WHERE seq IS NULL AND created_at<?').run(cutoff).changes);
    if(!last){if(legacy)this.record({event:'audit.pruned',actor:'system',details:{legacyRemoved:legacy}});return legacy;}
    const removed=Number(this.db.prepare('DELETE FROM security_events WHERE seq IS NOT NULL AND seq<=?').run(last.seq).changes);
    this.record({event:'audit.pruned',actor:'system',details:{removed:removed+legacy,throughSeq:Number(last.seq),lastRemovedHash:String(last.hash),retentionDays:Math.round(maxAgeMs/DAY_MS)}});
    return removed+legacy;
  }

  private map(r:any):AuditEntry{
    let details:Record<string,unknown>|undefined; try{details=r.details?JSON.parse(r.details):undefined;}catch{details={raw:String(r.details)};}
    return {seq:Number(r.seq),id:r.id,createdAt:r.created_at,...(r.user_id?{userId:r.user_id}:{}),...(r.client_id?{clientId:r.client_id}:{}),actor:r.actor??'system',event:r.event,outcome:r.outcome??'success',
      ...(r.ip?{ip:r.ip}:{}),...(r.target_type?{targetType:r.target_type}:{}),...(r.target_id?{targetId:r.target_id}:{}),...(details?{details}:{}),prevHash:r.prev_hash,hash:r.hash};
  }
}

/** Retention from FARCMD_AUDIT_RETENTION_DAYS (default 365, 0 = keep forever). */
export function auditRetentionMs():number{ return envRetentionMs('FARCMD_AUDIT_RETENTION_DAYS'); }
