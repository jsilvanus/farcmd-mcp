import type { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';
import { decryptSecret } from './crypto-at-rest.js';
import { executeSshCommand, openSshSession, sha256Hex, type SshExecResult, type SshSession } from './ssh.js';
import { CapabilityVerificationService } from './capability-verification.js';
import { AuditLog, type AuditActor, type AuditOutcome } from './audit.js';
import { SqliteSshStore } from './storage/ssh.js';
import { SqliteCommandStore, type CommandLevel, hashCommandContent } from './command-registry.js';
import { SqliteCommandInstallationStore } from './storage/command-installations.js';
import { SqliteOAuthGrantStore } from './oauth/grants.js';
import { SqliteExecutionStore, confirmationForLevel, type ConfirmationRequirement } from './execution.js';
import { randomToken } from './oauth/pkce.js';
import { SqliteExecutionHistoryStore } from './execution-history.js';

export interface ConnectorContext { userId:string; clientId:string; accessToken:string; }
export interface CommandSummary { id:string; name:string; description:string; level:CommandLevel; enabled:boolean; confirmation:ConfirmationRequirement; }
export interface CommandExecution { ok:true; commandId:string; level:CommandLevel; exitCode:number|null; stdout:string; stderr:string; durationMs:number; signal?:string; }
export interface PendingConfirmation {ok:true;pending:true;commandId:string;level:CommandLevel;confirmation:ConfirmationRequirement;approvalUrl:string;confirmationToken:string;expiresAt:number;}
export interface FarcmdConnector {
  health(context:ConnectorContext):Promise<{ok:true}>;
  listCommands(context:ConnectorContext):Promise<CommandSummary[]>;
  visibleLevels(context:ConnectorContext):CommandLevel[];
  executeCommand(context:ConnectorContext,commandId:string,expectedLevel:CommandLevel,confirmationToken?:string):Promise<CommandExecution|PendingConfirmation>;
  approvePending(userId:string,token:string,password?:string):Promise<CommandExecution>;
}

export class FarcmdConnectorImpl implements FarcmdConnector {
  private readonly ssh:SqliteSshStore; private readonly commands:SqliteCommandStore; private readonly grants:SqliteOAuthGrantStore; private readonly pending:SqliteExecutionStore;  private readonly history:SqliteExecutionHistoryStore; private readonly installations:SqliteCommandInstallationStore; private readonly verifier:CapabilityVerificationService;
  constructor(private readonly db:DatabaseSync,private readonly publicUrl:string){
    this.ssh=new SqliteSshStore(db); this.commands=new SqliteCommandStore(db); this.grants=new SqliteOAuthGrantStore(db); this.pending=new SqliteExecutionStore(db); this.pending.cleanup(); this.history=new SqliteExecutionHistoryStore(db); this.installations=new SqliteCommandInstallationStore(db); this.verifier=new CapabilityVerificationService(db,publicUrl);
  }
  async health(_context:ConnectorContext):Promise<{ok:true}>{return {ok:true};}
  visibleLevels(context:ConnectorContext):CommandLevel[]{const grant=this.grants.get(context.userId,context.clientId);return grant&&!grant.revokedAt?[...grant.visibleLevels]:[];}
  async listCommands(context:ConnectorContext):Promise<CommandSummary[]>{
    const grant=this.grants.get(context.userId,context.clientId);
    if(!grant||grant.revokedAt)return [];
    return this.commands.list(context.userId).filter(c=>c.enabled&&grant.visibleLevels.includes(c.level)).map(c=>({id:c.id,name:c.name,description:c.description,level:c.level,enabled:c.enabled,confirmation:confirmationForLevel(c.level)}));
  }
  async executeCommand(context:ConnectorContext,commandId:string,expectedLevel:CommandLevel,confirmationToken?:string):Promise<CommandExecution|PendingConfirmation>{
    try{
      const result=await this.executeCommandChecked(context,commandId,expectedLevel,confirmationToken);
      if('pending' in result&&!confirmationToken)this.audit(context.userId,context.clientId,'command.confirmation_requested',{commandId,level:expectedLevel,confirmation:result.confirmation});
      return result;
    }catch(error){
      // Executions that ran (or were blocked by integrity verification) are audited in executeStoredCommand;
      // this records MCP calls refused before that point (revoked grant, hidden level, wrong tool, disabled command, ...).
      const message=error instanceof Error?error.message:String(error);
      if(!/^Execution blocked:/.test(message))this.audit(context.userId,context.clientId,'command.execute_denied',{commandId,level:expectedLevel,error:message},'failure');
      throw error;
    }
  }
  private async executeCommandChecked(context:ConnectorContext,commandId:string,expectedLevel:CommandLevel,confirmationToken?:string):Promise<CommandExecution|PendingConfirmation>{
    const grant=this.grants.get(context.userId,context.clientId);
    if(!grant||grant.revokedAt)throw new Error('This OAuth authorization has been revoked or does not exist.');
    const command=this.commands.get(context.userId,commandId);
    if(!command)throw new Error('Command not found.');
    if(!command.enabled)throw new Error('Command is disabled.');
    if(command.level!==expectedLevel)throw new Error('Command level does not match the selected execution tool.');
    if(!grant.visibleLevels.includes(command.level))throw new Error('This OAuth authorization does not expose this command.');
    this.grants.touch(context.userId,context.clientId);
    const confirmation=confirmationForLevel(command.level);
    if(confirmation!=='none'){
      if(confirmationToken){ const pending=this.pending.get(confirmationToken); if(!pending||pending.userId!==context.userId||pending.clientId!==context.clientId||pending.commandId!==commandId||pending.level!==command.level)throw new Error('Confirmation request not found or expired.'); if(pending.status==='completed'){const completed=this.pending.consumeCompleted(confirmationToken);if(!completed)throw new Error('Confirmation result is no longer available.');return {ok:true,commandId,level:command.level,...completed};} return {ok:true,pending:true,commandId,level:command.level,confirmation,approvalUrl:this.publicUrl+'/?page=confirm&token='+encodeURIComponent(confirmationToken),confirmationToken,expiresAt:pending.expiresAt}; }

      const token=randomToken(); const now=Date.now(); const expiresAt=now+5*60_000;
      this.pending.create({token,userId:context.userId,clientId:context.clientId,commandId,level:command.level,createdAt:now,expiresAt});
      return {ok:true,pending:true,commandId,level:command.level,confirmation,approvalUrl:this.publicUrl+'/?page=confirm&token='+encodeURIComponent(token),confirmationToken:token,expiresAt};
    }
    return this.executeStoredCommand(context.userId,context.clientId,commandId,command.level);
  }
  async approvePending(userId:string,token:string,password?:string):Promise<CommandExecution>{
    const p=this.pending.get(token); if(!p||p.userId!==userId)throw new Error('Confirmation request not found or expired.');
    const audit=(event:string,details:Record<string,unknown>,outcome:AuditOutcome='success')=>this.audit(userId,p.clientId,event,{...details},outcome,'web');
    audit('command.confirmation_attempt',{commandId:p.commandId,level:p.level});
    const grant=this.grants.get(p.userId,p.clientId); if(!grant||grant.revokedAt||!grant.visibleLevels.includes(p.level))throw new Error('The OAuth authorization is no longer permitted.');
    const command=this.commands.get(p.userId,p.commandId); if(!command||!command.enabled||command.level!==p.level)throw new Error('The command is no longer available.');
    const confirmation=confirmationForLevel(p.level);
    if(confirmation==='password'){
      if(!password)throw new Error('Execution password required.');
      if(!await this.commands.verifyExecutionPassword(userId,p.commandId,password)){audit('command.level5_password_failed',{commandId:p.commandId},'failure');throw new Error('Invalid execution password.');}
      audit('command.level5_password_accepted',{commandId:p.commandId});
    }
    const result=await this.executeStoredCommand(p.userId,p.clientId,p.commandId,p.level); audit('command.confirmation_executed',{commandId:p.commandId,level:p.level}); this.pending.complete(token,{exitCode:result.exitCode,stdout:result.stdout,stderr:result.stderr,durationMs:result.durationMs,...(result.signal?{signal:result.signal}:{})}); return result;
  }
  private audit(userId:string,clientId:string,event:string,details:Record<string,unknown>,outcome:AuditOutcome='success',actor:AuditActor='mcp'):void{
    new AuditLog(this.db).record({event,actor,outcome,userId,clientId,...(typeof details.commandId==='string'?{targetType:'command',targetId:details.commandId}:{}),details});
  }
  private async executeStoredCommand(userId:string,clientId:string,commandId:string,level:CommandLevel):Promise<CommandExecution>{
    const command=this.commands.get(userId,commandId); if(!command||!command.enabled||command.level!==level)throw new Error('Command is no longer available.');
    const target=this.ssh.getTarget(userId,command.targetId); if(!target||!target.enabled)throw new Error('SSH target is unavailable.');
    if(!target.hostFingerprint)throw new Error('SSH target has no pinned host fingerprint.');
    const installation=this.installations.get(userId,commandId);
    if(!installation?.installedAt)throw new Error('This command has no installed SSH capability.');
    // Local consistency: the stored command definition and the stored capability baseline must agree.
    const expectedCommandHash=hashCommandContent(command.type,command.content);
    if(!installation.commandSha256||installation.commandSha256!==expectedCommandHash)throw new Error('Command capability integrity check failed: stored command definition does not match the installed capability.');
    if((installation.scriptContent!==undefined&&installation.scriptSha256&&sha256Hex(installation.scriptContent)!==installation.scriptSha256)||(installation.authorizedKeySha256&&sha256Hex(installation.authorizedKeyLine)!==installation.authorizedKeySha256))throw new Error('Command capability integrity check failed: stored capability baseline is inconsistent.');
    const privateKey=decryptSecret(installation.encryptedPrivateKey,'command-installation:'+userId+':'+installation.id);
    const config={hostname:target.hostname,port:target.port,username:target.username,hostFingerprint:target.hostFingerprint};
    const startedAt=Date.now();
    let result:SshExecResult;
    if(level>=3){
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
        this.audit(userId,clientId,'integrity.verification_blocked',{commandId,level,error:message},'failure');
        this.history.create({id:randomUUID(),userId,clientId,commandId,commandName:command.name,targetId:target.id,level,startedAt,endedAt:Date.now(),durationMs:Date.now()-startedAt,exitCode:null,stdout:'',stderr:'',status:'blocked',error:message});
        throw new Error('Execution blocked: '+message);
      }
      this.audit(userId,clientId,'integrity.verification_passed',{commandId,level});
      try{result=await (await sessionPromise!).exec('true');}
      catch(error){result={exitCode:null,stdout:'',stderr:error instanceof Error?error.message:String(error),durationMs:Date.now()-startedAt};}
    } else {
      result=await executeSshCommand(config,{privateKey},'true');
    }
    const status=result.signal==='TIMEOUT'?'timeout':result.exitCode===0?'success':'failed';
    this.history.create({id:randomUUID(),userId,clientId,commandId,commandName:command.name,targetId:target.id,level,startedAt,endedAt:startedAt+result.durationMs,durationMs:result.durationMs,exitCode:result.exitCode,stdout:result.stdout,stderr:result.stderr,status});
    this.audit(userId,clientId,'command.execute',{commandId,commandName:command.name,level,targetId:target.id,status,exitCode:result.exitCode,durationMs:result.durationMs},status==='success'?'success':'failure');
    return {ok:true,commandId,level,exitCode:result.exitCode,stdout:result.stdout,stderr:result.stderr,durationMs:result.durationMs,...(result.signal?{signal:result.signal}:{})};
  }
}
