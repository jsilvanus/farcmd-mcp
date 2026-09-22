import type { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';
import { decryptSecret } from './crypto-at-rest.js';
import { getSshPassphrase } from './ssh-key-cache.js';
import { executeSshCommand, inspectPrivateKey } from './ssh.js';
import { SqliteSshStore } from './storage/ssh.js';
import { SqliteCommandStore, type CommandLevel } from './command-registry.js';
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
  private readonly ssh:SqliteSshStore; private readonly commands:SqliteCommandStore; private readonly grants:SqliteOAuthGrantStore; private readonly pending:SqliteExecutionStore;  private readonly history:SqliteExecutionHistoryStore;
  constructor(private readonly db:DatabaseSync,private readonly publicUrl:string){
    this.ssh=new SqliteSshStore(db); this.commands=new SqliteCommandStore(db); this.grants=new SqliteOAuthGrantStore(db); this.pending=new SqliteExecutionStore(db); this.pending.cleanup(); this.history=new SqliteExecutionHistoryStore(db);
  }
  async health(_context:ConnectorContext):Promise<{ok:true}>{return {ok:true};}
  visibleLevels(context:ConnectorContext):CommandLevel[]{const grant=this.grants.get(context.userId,context.clientId);return grant&&!grant.revokedAt?[...grant.visibleLevels]:[];}
  async listCommands(context:ConnectorContext):Promise<CommandSummary[]>{
    const grant=this.grants.get(context.userId,context.clientId);
    if(!grant||grant.revokedAt)return [];
    return this.commands.list(context.userId).filter(c=>c.enabled&&grant.visibleLevels.includes(c.level)).map(c=>({id:c.id,name:c.name,description:c.description,level:c.level,enabled:c.enabled,confirmation:confirmationForLevel(c.level)}));
  }
  async executeCommand(context:ConnectorContext,commandId:string,expectedLevel:CommandLevel,confirmationToken?:string):Promise<CommandExecution|PendingConfirmation>{
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
    const audit=(event:string,details?:unknown)=>{try{this.db.prepare('INSERT INTO security_events (id,user_id,client_id,event,details,created_at) VALUES (?,?,?,?,?,?)').run(randomUUID(),userId,p.clientId,event,details===undefined?null:JSON.stringify(details),Date.now());}catch{}};
    audit('confirmation_attempt',{commandId:p.commandId,level:p.level});
    const grant=this.grants.get(p.userId,p.clientId); if(!grant||grant.revokedAt||!grant.visibleLevels.includes(p.level))throw new Error('The OAuth authorization is no longer permitted.');
    const command=this.commands.get(p.userId,p.commandId); if(!command||!command.enabled||command.level!==p.level)throw new Error('The command is no longer available.');
    const confirmation=confirmationForLevel(p.level);
    if(confirmation==='password'){
      if(!password)throw new Error('Execution password required.');
      if(!await this.commands.verifyExecutionPassword(userId,p.commandId,password)){audit('level5_password_failed',{commandId:p.commandId});throw new Error('Invalid execution password.');}
      audit('level5_password_accepted',{commandId:p.commandId});
    }
    const result=await this.executeStoredCommand(p.userId,p.clientId,p.commandId,p.level); audit('confirmation_executed',{commandId:p.commandId,level:p.level}); this.pending.complete(token,{exitCode:result.exitCode,stdout:result.stdout,stderr:result.stderr,durationMs:result.durationMs,...(result.signal?{signal:result.signal}:{})}); return result;
  }
  private async executeStoredCommand(userId:string,clientId:string,commandId:string,level:CommandLevel):Promise<CommandExecution>{
    const command=this.commands.get(userId,commandId); if(!command||!command.enabled||command.level!==level)throw new Error('Command is no longer available.');
    const target=this.ssh.getTarget(userId,command.targetId); if(!target||!target.enabled)throw new Error('SSH target is unavailable.');
    if(!target.hostFingerprint)throw new Error('SSH target has no pinned host fingerprint.');
    const key=this.ssh.getKey(userId,target.sshKeyId); if(!key)throw new Error('SSH key not found.');
    const privateKey=decryptSecret(key.encryptedPrivateKey,'ssh-key:'+userId+':'+key.id);
    const passphrase=getSshPassphrase(userId,key.id);
    const inspected=await inspectPrivateKey(privateKey,passphrase);
    if(!inspected.valid){
      if(inspected.encrypted&&!passphrase)throw new Error('SSH key is locked. Unlock it in the farcmd web UI.');
      throw new Error('Stored SSH key is invalid or the unlock passphrase is incorrect.');
    }
    const startedAt=Date.now();
    const result=await executeSshCommand({hostname:target.hostname,port:target.port,username:target.username,hostFingerprint:target.hostFingerprint},{privateKey,...(passphrase!==undefined?{passphrase}:{})},command.shellCommand);
    const status=result.signal==='TIMEOUT'?'timeout':result.exitCode===0?'success':'failed';
    this.history.create({id:randomUUID(),userId,clientId,commandId,commandName:command.name,targetId:target.id,level,startedAt,endedAt:startedAt+result.durationMs,durationMs:result.durationMs,exitCode:result.exitCode,stdout:result.stdout,stderr:result.stderr,status});
    return {ok:true,commandId,level,...result};
  }
}
