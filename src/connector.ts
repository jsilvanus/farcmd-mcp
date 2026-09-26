import type { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { decryptSecret } from './crypto-at-rest.js';
import { executeSshCommand, openSshSession, sha256Hex, type SshExecResult, type SshSession } from './ssh.js';
import { CapabilityVerificationService } from './capability-verification.js';
import { AuditLog, type AuditActor, type AuditOutcome } from './audit.js';
import { SqliteSshStore } from './storage/ssh.js';
import { SqliteCommandStore, type CommandLevel, type CommandRecord, hashCommandContent, requiresIntegrityVerification } from './command-registry.js';
import { SqliteCommandInstallationStore, commandInstallationKeyAad } from './storage/command-installations.js';
import { SqliteOAuthGrantStore } from './oauth/grants.js';
import { SqliteExecutionStore, confirmationForLevel, type ConfirmationRequirement } from './execution.js';
import { randomToken } from './oauth/pkce.js';
import { SqliteExecutionHistoryStore } from './execution-history.js';
import { McpAccessPolicy } from './mcp-access.js';
import { executionLimits } from './limits.js';

export interface ConnectorContext { userId:string; clientId:string; accessToken:string; }
export interface CommandSummary { id:string; name:string; description:string; level:CommandLevel; enabled:boolean; confirmation:ConfirmationRequirement; }
export interface CommandExecution { ok:true; commandId:string; level:CommandLevel; exitCode:number|null; stdout:string; stderr:string; durationMs:number; signal?:string; truncated?:boolean; }
const NEXT_STEP='Show approvalUrl to the person and wait until they say they have approved it. Then call this tool again with the same commandId to get the result. Passing confirmationToken is optional: it only identifies this request and is not a credential.';
export interface PendingConfirmation {ok:true;pending:true;commandId:string;level:CommandLevel;confirmation:ConfirmationRequirement;approvalUrl:string;confirmationToken:string;expiresAt:number;
  /** Plain-language instructions for the model. */
  next:string;}
export interface FarcmdConnector {
  health(context:ConnectorContext):Promise<{ok:true}>;
  listCommands(context:ConnectorContext):Promise<CommandSummary[]>;
  visibleLevels(context:ConnectorContext):CommandLevel[];
  executeCommand(context:ConnectorContext,commandId:string,expectedLevel:CommandLevel,confirmationToken?:string):Promise<CommandExecution|PendingConfirmation>;
  approvePending(userId:string,token:string,password?:string):Promise<CommandExecution>;
  awaitConfirmation(context:ConnectorContext,commandId:string,level:CommandLevel,token:string,signal:AbortSignal):Promise<CommandExecution|undefined>;
  declinePending(context:ConnectorContext,token:string,reason:string):void;
  runFromWeb(userId:string,commandId:string,options:{password?:string;confirmed?:boolean}):Promise<CommandExecution>;
}

/**
 * Wakes MCP calls that wait for a web approval (URL elicitation). The web API and the MCP endpoint use
 * separate connector instances in one process, so this is module level; waiters also re-check the
 * database every few seconds, so a missed event only delays the result.
 */
const confirmationEvents=new EventEmitter(); confirmationEvents.setMaxListeners(0);
export function notifyConfirmationChanged(token:string):void{confirmationEvents.emit(token);}
const CONFIRMATION_POLL_MS=2_000;
/** Integrity verification refused the run; it is already audited, unlike other refusals. */
class ExecutionBlockedError extends Error { constructor(reason:string){super('Execution blocked: '+reason);this.name='ExecutionBlockedError';} }

export class FarcmdConnectorImpl implements FarcmdConnector {
  private readonly ssh:SqliteSshStore; private readonly commands:SqliteCommandStore; private readonly grants:SqliteOAuthGrantStore; private readonly pending:SqliteExecutionStore;  private readonly history:SqliteExecutionHistoryStore; private readonly installations:SqliteCommandInstallationStore; private readonly verifier:CapabilityVerificationService; private readonly access:McpAccessPolicy; private readonly auditLog:AuditLog;
  constructor(private readonly db:DatabaseSync,private readonly publicUrl:string){
    this.ssh=new SqliteSshStore(db); this.commands=new SqliteCommandStore(db); this.grants=new SqliteOAuthGrantStore(db); this.pending=new SqliteExecutionStore(db); this.pending.cleanup(); this.history=new SqliteExecutionHistoryStore(db); this.installations=new SqliteCommandInstallationStore(db); this.verifier=new CapabilityVerificationService(db,publicUrl); this.access=new McpAccessPolicy(db); this.auditLog=new AuditLog(db);
  }
  /** The client's grant, unless it was revoked. */
  private activeGrant(userId:string,clientId:string){const grant=this.grants.get(userId,clientId);return grant&&!grant.revokedAt?grant:undefined;}
  /** The pending request behind token, if it belongs to this user and client. */
  private ownPending(context:ConnectorContext,token:string){const p=this.pending.get(token);return p&&p.userId===context.userId&&p.clientId===context.clientId?p:undefined;}
  private pendingResponse(commandId:string,level:CommandLevel,confirmation:ConfirmationRequirement,token:string,expiresAt:number):PendingConfirmation{
    return {ok:true,pending:true,commandId,level,confirmation,approvalUrl:this.publicUrl+'/?page=confirm&token='+encodeURIComponent(token),confirmationToken:token,expiresAt,next:NEXT_STEP};
  }
  /** Level 5: checks the command's execution password and audits the outcome. */
  private async checkExecutionPassword(userId:string,clientId:string,commandId:string,password:string|undefined,actor:AuditActor):Promise<void>{
    if(!password)throw new Error('Execution password required.');
    if(!await this.commands.verifyExecutionPassword(userId,commandId,password)){this.audit(userId,clientId,'command.level5_password_failed',{commandId},'failure',actor);throw new Error('Invalid execution password.');}
    this.audit(userId,clientId,'command.level5_password_accepted',{commandId},'success',actor);
  }
  // MCP kill switch: health and list_commands stay registered so the client sees why access is refused;
  // no execution tool is exposed while MCP access is off.
  async health(context:ConnectorContext):Promise<{ok:true}>{this.access.assertAllowed(context.userId);return {ok:true};}
  visibleLevels(context:ConnectorContext):CommandLevel[]{if(!this.access.check(context.userId).allowed)return [];return [...this.activeGrant(context.userId,context.clientId)?.visibleLevels??[]];}
  async listCommands(context:ConnectorContext):Promise<CommandSummary[]>{
    this.access.assertAllowed(context.userId);
    const grant=this.activeGrant(context.userId,context.clientId);
    if(!grant)return [];
    return this.commands.list(context.userId).filter(c=>c.enabled&&grant.visibleLevels.includes(c.level)).map(c=>({id:c.id,name:c.name,description:c.description,level:c.level,enabled:c.enabled,confirmation:confirmationForLevel(c.level)}));
  }
  async executeCommand(context:ConnectorContext,commandId:string,expectedLevel:CommandLevel,confirmationToken?:string):Promise<CommandExecution|PendingConfirmation>{
    try{
      return await this.executeCommandChecked(context,commandId,expectedLevel,confirmationToken);
    }catch(error){
      // Executions that ran (or were blocked by integrity verification) are audited in executeStoredCommand;
      // this records MCP calls refused before that point (revoked grant, hidden level, wrong tool, disabled command, ...).
      if(!(error instanceof ExecutionBlockedError))this.audit(context.userId,context.clientId,'command.execute_denied',{commandId,level:expectedLevel,error:error instanceof Error?error.message:String(error)},'failure');
      throw error;
    }
  }
  private async executeCommandChecked(context:ConnectorContext,commandId:string,expectedLevel:CommandLevel,confirmationToken?:string):Promise<CommandExecution|PendingConfirmation>{
    this.access.assertAllowed(context.userId);
    const grant=this.activeGrant(context.userId,context.clientId);
    if(!grant)throw new Error('This OAuth authorization has been revoked or does not exist.');
    const command=this.commands.get(context.userId,commandId);
    if(!command)throw new Error('Command not found.');
    if(!command.enabled)throw new Error('Command is disabled.');
    if(command.level!==expectedLevel)throw new Error('Command level does not match the selected execution tool.');
    if(!grant.visibleLevels.includes(command.level))throw new Error('This OAuth authorization does not expose this command.');
    this.grants.touch(context.userId,context.clientId);
    if(!confirmationToken)executionLimits().takeClientCall(context.userId,context.clientId);
    const confirmation=confirmationForLevel(command.level);
    if(confirmation!=='none'){
      if(confirmationToken){ const pending=this.ownPending(context,confirmationToken); if(!pending||pending.commandId!==commandId||pending.level!==command.level||pending.status==='expired'||pending.status==='consumed')throw new Error('Confirmation request not found or expired.'); if(pending.status==='completed'){const completed=this.pending.consumeCompleted(confirmationToken);if(!completed)throw new Error('Confirmation result is no longer available.');return {ok:true,commandId,level:command.level,...completed};} return this.pendingResponse(commandId,command.level,confirmation,confirmationToken,pending.expiresAt); }

      // No token: continue this client's open request for the command instead of starting a new one.
      const open=this.pending.findOpen(context.userId,context.clientId,commandId,command.level);
      if(open?.status==='completed'){const completed=this.pending.consumeCompleted(open.token);if(completed){this.audit(context.userId,context.clientId,'command.confirmation_result_delivered',{commandId,level:command.level,withoutToken:true});return {ok:true,commandId,level:command.level,...completed};}}
      else if(open)return this.pendingResponse(commandId,command.level,confirmation,open.token,open.expiresAt);
      const token=randomToken(); const now=Date.now(); const expiresAt=now+5*60_000;
      this.pending.create({token,userId:context.userId,clientId:context.clientId,commandId,level:command.level,createdAt:now,expiresAt});
      this.audit(context.userId,context.clientId,'command.confirmation_requested',{commandId,level:command.level,confirmation});
      return this.pendingResponse(commandId,command.level,confirmation,token,expiresAt);
    }
    return this.executeStoredCommand(context.userId,context.clientId,commandId,command.level);
  }
  async approvePending(userId:string,token:string,password?:string):Promise<CommandExecution>{
    const p=this.pending.get(token); if(!p||p.userId!==userId)throw new Error('Confirmation request not found or expired.');
    if(p.status!=='pending')throw new Error('This request was already approved, declined or has expired.');
    const audit=(event:string,details:Record<string,unknown>,outcome:AuditOutcome='success')=>this.audit(userId,p.clientId,event,{...details},outcome,'web');
    audit('command.confirmation_attempt',{commandId:p.commandId,level:p.level});
    // A request made before MCP was turned off must not run afterwards.
    const access=this.access.check(p.userId); if(!access.allowed){audit('command.execute_denied',{commandId:p.commandId,level:p.level,error:access.message},'failure');throw new Error(access.message);}
    const grant=this.activeGrant(p.userId,p.clientId); if(!grant||!grant.visibleLevels.includes(p.level))throw new Error('The OAuth authorization is no longer permitted.');
    const command=this.commands.get(p.userId,p.commandId); if(!command||!command.enabled||command.level!==p.level)throw new Error('The command is no longer available.');
    if(confirmationForLevel(p.level)==='password')await this.checkExecutionPassword(userId,p.clientId,p.commandId,password,'web');
    if(!this.pending.claim(token))throw new Error('This request was already approved, declined or has expired.');
    let result:CommandExecution;
    try{result=await this.executeStoredCommand(p.userId,p.clientId,p.commandId,p.level,'web');}catch(error){this.pending.release(token);throw error;}
    audit('command.confirmation_executed',{commandId:p.commandId,level:p.level}); this.pending.complete(token,{exitCode:result.exitCode,stdout:result.stdout,stderr:result.stderr,durationMs:result.durationMs,...(result.signal?{signal:result.signal}:{})}); notifyConfirmationChanged(token); return result;
  }
  private audit(userId:string,clientId:string,event:string,details:Record<string,unknown>,outcome:AuditOutcome='success',actor:AuditActor='mcp'):void{
    this.auditLog.record({event,actor,outcome,userId,clientId,...(typeof details.commandId==='string'?{targetType:'command',targetId:details.commandId}:{}),details});
  }
  private async executeStoredCommand(userId:string,clientId:string,commandId:string,level:CommandLevel,actor:AuditActor='mcp'):Promise<CommandExecution>{
    // Re-read: the command may have changed while the caller awaited (e.g. a password check).
    const command=this.commands.get(userId,commandId); if(!command||!command.enabled||command.level!==level)throw new Error('Command is no longer available.');
    const release=executionLimits().acquireSsh(command.targetId);
    try{return await this.executeStoredCommandNow(userId,clientId,command,actor);}finally{release();}
  }
  private async executeStoredCommandNow(userId:string,clientId:string,command:CommandRecord,actor:AuditActor):Promise<CommandExecution>{
    const commandId=command.id, level=command.level;
    const target=this.ssh.getTarget(userId,command.targetId); if(!target||!target.enabled)throw new Error('SSH target is unavailable.');
    if(!target.hostFingerprint)throw new Error('SSH target has no pinned host fingerprint.');
    const installation=this.installations.get(userId,commandId);
    if(!installation?.installedAt)throw new Error('This command has no installed SSH capability.');
    // Local consistency: the stored command definition and the stored capability baseline must agree.
    const expectedCommandHash=hashCommandContent(command.type,command.content);
    if(!installation.commandSha256||installation.commandSha256!==expectedCommandHash)throw new Error('Command capability integrity check failed: stored command definition does not match the installed capability.');
    if((installation.scriptContent!==undefined&&installation.scriptSha256&&sha256Hex(installation.scriptContent)!==installation.scriptSha256)||(installation.authorizedKeySha256&&sha256Hex(installation.authorizedKeyLine)!==installation.authorizedKeySha256))throw new Error('Command capability integrity check failed: stored capability baseline is inconsistent.');
    const privateKey=decryptSecret(installation.encryptedPrivateKey,commandInstallationKeyAad(userId,installation.id));
    const config={hostname:target.hostname,port:target.port,username:target.username,hostFingerprint:target.hostFingerprint};
    const startedAt=Date.now();
    let result:SshExecResult;
    if(requiresIntegrityVerification(command)){
      // Remote integrity verification immediately before execution. The execution connection is
      // authenticated concurrently (authentication runs nothing on the target), and its exec request is
      // sent only after verification succeeded, keeping the check-to-use window to one channel round trip.
      let sessionPromise:Promise<SshSession>|undefined;
      try{
        this.verifier.assertAvailable(userId,target);
        sessionPromise=openSshSession(config,{privateKey}); sessionPromise.catch(()=>undefined);
        await this.verifier.assertCommandIntact(userId,target,commandId);
      }
      catch(error){
        sessionPromise?.then(s=>s.close(),()=>undefined);
        const message=error instanceof Error?error.message:String(error);
        this.audit(userId,clientId,'integrity.verification_blocked',{commandId,level,error:message},'failure',actor);
        this.history.create({id:randomUUID(),userId,clientId,commandId,commandName:command.name,targetId:target.id,level,startedAt,endedAt:Date.now(),durationMs:Date.now()-startedAt,exitCode:null,stdout:'',stderr:'',status:'blocked',error:message});
        throw new ExecutionBlockedError(message);
      }
      this.audit(userId,clientId,'integrity.verification_passed',{commandId,level},'success',actor);
      try{result=await (await sessionPromise!).exec('true');}
      catch(error){result={exitCode:null,stdout:'',stderr:error instanceof Error?error.message:String(error),durationMs:Date.now()-startedAt};}
    } else {
      result=await executeSshCommand(config,{privateKey},'true');
    }
    const status=result.signal==='TIMEOUT'?'timeout':result.exitCode===0?'success':'failed';
    this.history.create({id:randomUUID(),userId,clientId,commandId,commandName:command.name,targetId:target.id,level,startedAt,endedAt:startedAt+result.durationMs,durationMs:result.durationMs,exitCode:result.exitCode,stdout:result.stdout,stderr:result.stderr,status});
    this.audit(userId,clientId,'command.execute',{commandId,commandName:command.name,level,targetId:target.id,status,exitCode:result.exitCode,durationMs:result.durationMs},status==='success'?'success':'failure',actor);
    return {ok:true,commandId,level,exitCode:result.exitCode,stdout:result.stdout,stderr:result.stderr,durationMs:result.durationMs,...(result.signal?{signal:result.signal}:{}),...(result.truncated?{truncated:true}:{})};
  }
  /**
   * Waits for a level 4/5 request to be approved in the web UI, then returns its result exactly as a
   * call with the confirmation token would. Returns undefined when the request expires or is declined,
   * or when signal aborts (the MCP client went away); the token then still works for a later call.
   */
  async awaitConfirmation(context:ConnectorContext,commandId:string,level:CommandLevel,token:string,signal:AbortSignal):Promise<CommandExecution|undefined>{
    while(!signal.aborted){
      const p=this.ownPending(context,token);
      if(!p||(p.status!=='pending'&&p.status!=='running'&&p.status!=='completed'))return undefined;
      if(p.status==='completed'){const r=await this.executeCommand(context,commandId,level,token);return 'pending' in r?undefined:r;}
      await new Promise<void>(resolve=>{
        const done=()=>{clearTimeout(timer);confirmationEvents.off(token,done);signal.removeEventListener('abort',done);resolve();};
        const timer=setTimeout(done,Math.max(0,Math.min(CONFIRMATION_POLL_MS,p.expiresAt-Date.now()+50)));
        confirmationEvents.on(token,done); signal.addEventListener('abort',done,{once:true});
      });
    }
    return undefined;
  }
  /** The person refused the approval link in their MCP client: the request can no longer be approved. */
  declinePending(context:ConnectorContext,token:string,reason:string):void{
    const p=this.ownPending(context,token); if(!p||p.status!=='pending')return;
    this.pending.expire(token); notifyConfirmationChanged(token);
    this.audit(context.userId,context.clientId,'command.confirmation_declined',{commandId:p.commandId,level:p.level,reason});
  }
  /**
   * Run a command from the web UI. The signed-in person is the human in the loop: level 4 needs an
   * explicit confirmation from the run dialog and level 5 the command's execution password. Integrity
   * verification, SSH limits, history and audit are the same as for MCP; the MCP access switch does not
   * apply, because this is not an MCP call.
   */
  async runFromWeb(userId:string,commandId:string,options:{password?:string;confirmed?:boolean}):Promise<CommandExecution>{
    const command=this.commands.get(userId,commandId);
    if(!command)throw new Error('Command not found.');
    if(!command.enabled)throw new Error('Command is disabled.');
    const confirmation=confirmationForLevel(command.level);
    if(confirmation==='human'&&options.confirmed!==true)throw new Error('Level 4 commands must be confirmed before they run.');
    if(confirmation==='password')await this.checkExecutionPassword(userId,WEB_CLIENT_ID,commandId,options.password,'web');
    executionLimits().takeClientCall(userId,WEB_CLIENT_ID);
    return this.executeStoredCommand(userId,WEB_CLIENT_ID,commandId,command.level,'web');
  }
}

/** Client id recorded in history and audit for runs started from the web UI. */
export const WEB_CLIENT_ID='web';
