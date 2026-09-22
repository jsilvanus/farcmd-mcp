import type { DatabaseSync } from 'node:sqlite';

export interface SshKeyRecord {
  id: string;
  userId: string;
  name: string;
  encryptedPrivateKey: string;
  fingerprint?: string;
  createdAt: number;
  updatedAt: number;
}

export interface SshTargetRecord {
  id: string;
  userId: string;
  name: string;
  hostname: string;
  port: number;
  username: string;
  sshKeyId: string;
  hostFingerprint?: string;
  enabled: boolean;
  createdAt: number;
  updatedAt: number;
}

export class SqliteSshStore {
  constructor(private readonly db: DatabaseSync) {}

  listKeys(userId: string): SshKeyRecord[] {
    const rows = this.db.prepare('SELECT id,user_id,name,encrypted_private_key,fingerprint,created_at,updated_at FROM ssh_keys WHERE user_id=? ORDER BY name,id').all(userId) as Array<any>;
    return rows.map(this.mapKey);
  }

  getKey(userId: string, id: string): SshKeyRecord | undefined {
    return this.mapKey(this.db.prepare('SELECT id,user_id,name,encrypted_private_key,fingerprint,created_at,updated_at FROM ssh_keys WHERE user_id=? AND id=?').get(userId,id) as any);
  }

  createKey(record: SshKeyRecord): void {
    this.db.prepare('INSERT INTO ssh_keys (id,user_id,name,encrypted_private_key,fingerprint,created_at,updated_at) VALUES (?,?,?,?,?,?,?)').run(record.id,record.userId,record.name,record.encryptedPrivateKey,record.fingerprint??null,record.createdAt,record.updatedAt);
  }

  updateKey(record: SshKeyRecord): void {
    this.db.prepare('UPDATE ssh_keys SET name=?,encrypted_private_key=?,fingerprint=?,updated_at=? WHERE user_id=? AND id=?').run(record.name,record.encryptedPrivateKey,record.fingerprint??null,record.updatedAt,record.userId,record.id);
  }

  deleteKey(userId: string, id: string): void {
    this.db.prepare('DELETE FROM ssh_keys WHERE user_id=? AND id=?').run(userId,id);
  }

  listTargets(userId: string): SshTargetRecord[] {
    const rows = this.db.prepare('SELECT id,user_id,name,hostname,port,username,ssh_key_id,host_fingerprint,enabled,created_at,updated_at FROM ssh_targets WHERE user_id=? ORDER BY name,id').all(userId) as Array<any>;
    return rows.map(this.mapTarget);
  }

  getTarget(userId: string, id: string): SshTargetRecord | undefined {
    return this.mapTarget(this.db.prepare('SELECT id,user_id,name,hostname,port,username,ssh_key_id,host_fingerprint,enabled,created_at,updated_at FROM ssh_targets WHERE user_id=? AND id=?').get(userId,id) as any);
  }

  createTarget(record: SshTargetRecord): void {
    this.db.prepare('INSERT INTO ssh_targets (id,user_id,name,hostname,port,username,ssh_key_id,host_fingerprint,enabled,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)').run(record.id,record.userId,record.name,record.hostname,record.port,record.username,record.sshKeyId,record.hostFingerprint??null,record.enabled?1:0,record.createdAt,record.updatedAt);
  }

  updateTarget(record: SshTargetRecord): void {
    this.db.prepare('UPDATE ssh_targets SET name=?,hostname=?,port=?,username=?,ssh_key_id=?,host_fingerprint=?,enabled=?,updated_at=? WHERE user_id=? AND id=?').run(record.name,record.hostname,record.port,record.username,record.sshKeyId,record.hostFingerprint??null,record.enabled?1:0,record.updatedAt,record.userId,record.id);
  }

  deleteTarget(userId: string, id: string): void {
    this.db.prepare('DELETE FROM ssh_targets WHERE user_id=? AND id=?').run(userId,id);
  }

  private mapKey = (row:any): SshKeyRecord|undefined => row ? {
    id:row.id,userId:row.user_id,name:row.name,encryptedPrivateKey:row.encrypted_private_key,
    ...(row.fingerprint ? {fingerprint:row.fingerprint} : {}),createdAt:row.created_at,updatedAt:row.updated_at
  } : undefined;

  private mapTarget = (row:any): SshTargetRecord|undefined => row ? {
    id:row.id,userId:row.user_id,name:row.name,hostname:row.hostname,port:row.port,username:row.username,
    sshKeyId:row.ssh_key_id,...(row.host_fingerprint ? {hostFingerprint:row.host_fingerprint}:{}),
    enabled:!!row.enabled,createdAt:row.created_at,updatedAt:row.updated_at
  } : undefined;
}
