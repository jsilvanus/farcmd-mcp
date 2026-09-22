import type { DatabaseSync } from 'node:sqlite';
import { decryptSecret } from './crypto-at-rest.js';
import { getSshPassphrase } from './ssh-key-cache.js';
import { executeSshCommand } from './ssh.js';
import { SqliteSshStore } from './storage/ssh.js';
import { SqliteCommandStore, type CommandLevel } from './command-registry.js';

export interface ConnectorContext { userId:string; clientId:string; accessToken:string; allowedLevels?:CommandLevel[]; }
export interface CommandSummary { id:string; name:string; description:string; level:CommandLevel; enabled:boolean; }
export interface CommandExecution {
  ok:boolean; commandId:string; level:CommandLevel; exitCode:number|null; stdout:string; stderr:string; durationMs:number; signal?:string;
}
export interface UnlockRequired { ok:false; commandId:string; level:CommandLevel; error:'SSH key is locked'; unlockUrl:string; }
export interface FarcmdConnector {
  health(context:ConnectorContext):Promise<{ok:true}>;
  listCommands(context:ConnectorContext):Promise<CommandSummary[]>;
  executeCommand(context:ConnectorContext,commandId:string,expectedLevel:CommandLevel):Promise<CommandExecution|UnlockRequired>;
}

export class FarcmdConnectorImpl implements FarcmdConnector {
  private readonly ssh:SqliteSshStore;
  private readonly commands:SqliteCommandStore;
  constructor(private readonly db:DatabaseSync,private readonly publicUrl:string){
    this.ssh=new SqliteSshStore(db); this.commands=new SqliteCommandStore(db);
  }
  async health(_context:ConnectorContext):Promise<{ok:true}>{return {ok:true};}
  async listCommands(context:ConnectorContext):Promise<CommandSummary[]>{
    return this.commands.list(context.userId).map(c=>({id:c.id,name:c.name,description:c.description,level:c.level,enabled:c.enabled}));
  }
  async executeCommand(context:ConnectorContext,commandId:string,expectedLevel:CommandLevel):Promise<CommandExecution|UnlockRequired>{
    if(context.allowedLevels && !context.allowedLevels.includes(expectedLevel)) throw new Error('This OAuth authorization does not permit the requested command level.');
    const command=this.commands.get(context.userId,commandId);
    if(!command)throw new Error('Command not found.');
    if(!command.enabled)throw new Error('Command is disabled.');
    if(command.level!==expectedLevel)throw new Error('Command level does not match the selected execution tool.');
    const target=this.ssh.getTarget(context.userId,command.targetId);
    if(!target)throw new Error('SSH target not found.');
    if(!target.enabled)throw new Error('SSH target is disabled.');
    if(!target.hostFingerprint)throw new Error('SSH target has no pinned host fingerprint.');
    const key=this.ssh.getKey(context.userId,target.sshKeyId);
    if(!key)throw new Error('SSH key not found.');
    const privateKey=decryptSecret(key.encryptedPrivateKey,'ssh-key:'+context.userId+':'+key.id);
    const passphrase=getSshPassphrase(context.userId,key.id);
    const inspected=await import('./ssh.js').then(m=>m.inspectPrivateKey(privateKey,passphrase));
    if(!inspected.valid) {
      if(inspected.encrypted && !passphrase) return {ok:false,commandId,level:command.level,error:'SSH key is locked',unlockUrl:this.publicUrl+'/?page=unlock&key='+encodeURIComponent(key.id)};
      throw new Error('Stored SSH key is invalid or the unlock passphrase is incorrect.');
    }
    const result=await executeSshCommand({hostname:target.hostname,port:target.port,username:target.username,hostFingerprint:target.hostFingerprint},{privateKey,...(passphrase!==undefined?{passphrase}:{})},command.shellCommand);
    return {ok:true,commandId,level:command.level,...result};
  }
}
