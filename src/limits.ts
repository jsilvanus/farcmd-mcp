/**
 * Process-wide execution limits (shared by the MCP and web connectors):
 *
 * - SSH concurrency: at most FARCMD_SSH_MAX_CONCURRENT executions in total (default 8) and at most
 *   FARCMD_SSH_MAX_PER_TARGET per SSH target (default 2). A call over the limit is refused at once,
 *   not queued, so a misbehaving client cannot pile up work or connections to a host.
 * - MCP execution rate: at most FARCMD_MCP_EXECUTIONS_PER_MINUTE new executions (or level 4/5
 *   confirmation requests) per user and OAuth client in any 60-second window (default 30, 0 = off).
 *   Fetching the result of a confirmed request does not count.
 */
import { envInt } from './config.js';
export class LimitExceeded extends Error { constructor(message:string){super(message);this.name='LimitExceeded';} }
export interface ExecutionLimitOptions { maxConcurrent:number; maxPerTarget:number; perClientPerMinute:number; }

export function executionLimitOptionsFromEnv():ExecutionLimitOptions{
  const maxConcurrent=envInt('FARCMD_SSH_MAX_CONCURRENT',8), maxPerTarget=envInt('FARCMD_SSH_MAX_PER_TARGET',2);
  if(maxConcurrent<1||maxPerTarget<1)throw new Error('FARCMD_SSH_MAX_CONCURRENT and FARCMD_SSH_MAX_PER_TARGET must be at least 1');
  return {maxConcurrent,maxPerTarget,perClientPerMinute:envInt('FARCMD_MCP_EXECUTIONS_PER_MINUTE',30)};
}

export class ExecutionLimits {
  private running=0; private readonly perTarget=new Map<string,number>(); private readonly calls=new Map<string,number[]>();
  constructor(readonly options:ExecutionLimitOptions){}

  /** Reserve an SSH execution slot; call the returned function exactly once when done. */
  acquireSsh(targetId:string):()=>void{
    const onTarget=this.perTarget.get(targetId)??0;
    if(this.running>=this.options.maxConcurrent)throw new LimitExceeded('farcmd is running the maximum number of SSH commands ('+this.options.maxConcurrent+'). Try again shortly.');
    if(onTarget>=this.options.maxPerTarget)throw new LimitExceeded('The maximum number of concurrent commands on this SSH target ('+this.options.maxPerTarget+') is running. Try again shortly.');
    this.running++; this.perTarget.set(targetId,onTarget+1);
    let released=false;
    return ()=>{ if(released)return; released=true; this.running--; const n=(this.perTarget.get(targetId)??1)-1; if(n>0)this.perTarget.set(targetId,n); else this.perTarget.delete(targetId); };
  }
  /** Count one MCP execution for this user and client, or refuse it. */
  takeClientCall(userId:string,clientId:string,now=Date.now()):void{
    const limit=this.options.perClientPerMinute; if(limit===0)return;
    const key=userId+'\n'+clientId; const recent=(this.calls.get(key)??[]).filter(t=>t>now-60_000);
    if(recent.length>=limit){this.calls.set(key,recent);throw new LimitExceeded('Rate limit: at most '+limit+' command executions per minute for this MCP client. Try again in '+Math.ceil((recent[0]!+60_000-now)/1000)+' s.');}
    recent.push(now); this.calls.set(key,recent);
    if(this.calls.size>10_000)for(const [k,v] of this.calls)if(!v.some(t=>t>now-60_000))this.calls.delete(k);
  }
  get runningCount():number{ return this.running; }
}

let shared:ExecutionLimits|undefined;
export function executionLimits():ExecutionLimits{ return shared??=new ExecutionLimits(executionLimitOptionsFromEnv()); }
/** Replace the process-wide limits (tests, or re-reading configuration). */
export function setExecutionLimits(limits:ExecutionLimits):void{ shared=limits; }
