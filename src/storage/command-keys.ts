import type { DatabaseSync } from 'node:sqlite';

export interface CommandKeyRecord {
  id:string;
  userId:string;
  commandId:string;
  targetId:string;
  masterKeyId:string;
  encryptedPrivateKey:string;
  publicKey:string;
  fingerprint:string;
  installedAt?:number;
  createdAt:number;
  updatedAt:number;
}

export class SqliteCommandKeyStore {
  constructor(private readonly db:DatabaseSync){}

  get(userId:string,commandId:string):CommandKeyRecord|undefined {
    return this.map(this.db.prepare('SELECT * FROM command_keys WHERE user_id=? AND command_id=?').get(userId,commandId) as any);
  }

  list(userId:string):CommandKeyRecord[] {
    const rows=this.db.prepare('SELECT * FROM command_keys WHERE user_id=? ORDER BY created_at DESC,id').all(userId) as any[];
    return rows.map(this.map).filter((k):k is CommandKeyRecord=>k!==undefined);
  }

  create(record:CommandKeyRecord):void {
    this.db.prepare('INSERT INTO command_keys (id,user_id,command_id,target_id,master_key_id,encrypted_private_key,public_key,fingerprint,installed_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)').run(
      record.id,record.userId,record.commandId,record.targetId,record.masterKeyId,record.encryptedPrivateKey,record.publicKey,record.fingerprint,record.installedAt??null,record.createdAt,record.updatedAt
    );
  }

  markInstalled(userId:string,id:string,installedAt:number):void {
    this.db.prepare('UPDATE command_keys SET installed_at=?,updated_at=? WHERE user_id=? AND id=?').run(installedAt,Date.now(),userId,id);
  }

  delete(userId:string,id:string):void {
    this.db.prepare('DELETE FROM command_keys WHERE user_id=? AND id=?').run(userId,id);
  }

  deleteForCommand(userId:string,commandId:string):void {
    this.db.prepare('DELETE FROM command_keys WHERE user_id=? AND command_id=?').run(userId,commandId);
  }

  private map=(r:any):CommandKeyRecord|undefined=>r?{
    id:r.id,userId:r.user_id,commandId:r.command_id,targetId:r.target_id,masterKeyId:r.master_key_id,
    encryptedPrivateKey:r.encrypted_private_key,publicKey:r.public_key,fingerprint:r.fingerprint,
    ...(r.installed_at!==null&&r.installed_at!==undefined?{installedAt:r.installed_at}:{}),
    createdAt:r.created_at,updatedAt:r.updated_at
  }:undefined;
}
