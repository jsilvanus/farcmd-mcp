import type { DatabaseSync } from 'node:sqlite';
import type { VerifierPrivilege } from '../verification.js';

/**
 * A per-target verification authority. This is intentionally NOT an ssh_keys row: it can never be
 * selected as a master key, it has its own at-rest encryption contexts (see the AAD helpers below)
 * and its lifecycle is independent of master-key deletion.
 *
 * status:
 *   pending — generated and (possibly) installed, but no authenticated response has been seen yet
 *   active  — an authenticated verifier response matched the installed program; L3–L5 may execute
 */
export type VerificationAuthorityStatus='pending'|'active';
export interface VerificationAuthorityRecord {
  id:string; userId:string; targetId:string; username:string; privilege:VerifierPrivilege;
  encryptedPrivateKey:string; publicKey:string; fingerprint:string; encryptedSecret:string;
  authorizedKeyLine:string; authorizedKeySha256:string; sudoersSha256?:string; pythonPath?:string; verifierSha256?:string;
  status:VerificationAuthorityStatus; installedAt?:number; lastVerifiedAt?:number; lastError?:string; createdAt:number; updatedAt:number;
}
export function verificationKeyAad(userId:string,id:string):string{return 'verification-key:'+userId+':'+id;}
export function verificationSecretAad(userId:string,id:string):string{return 'verification-secret:'+userId+':'+id;}

export class SqliteVerificationAuthorityStore {
  constructor(private readonly db:DatabaseSync){}
  getForTarget(userId:string,targetId:string):VerificationAuthorityRecord|undefined{
    return this.map(this.db.prepare('SELECT * FROM verification_authorities WHERE user_id=? AND target_id=?').get(userId,targetId) as any);
  }
  /** Insert or fully replace (repair/rotation) the authority for a target. */
  upsert(r:VerificationAuthorityRecord):void{
    this.db.prepare('INSERT INTO verification_authorities (id,user_id,target_id,username,privilege,encrypted_private_key,public_key,fingerprint,encrypted_secret,authorized_key_line,authorized_key_sha256,sudoers_sha256,python_path,verifier_sha256,status,installed_at,last_verified_at,last_error,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(user_id,target_id) DO UPDATE SET id=excluded.id,username=excluded.username,privilege=excluded.privilege,encrypted_private_key=excluded.encrypted_private_key,public_key=excluded.public_key,fingerprint=excluded.fingerprint,encrypted_secret=excluded.encrypted_secret,authorized_key_line=excluded.authorized_key_line,authorized_key_sha256=excluded.authorized_key_sha256,sudoers_sha256=excluded.sudoers_sha256,python_path=excluded.python_path,verifier_sha256=excluded.verifier_sha256,status=excluded.status,installed_at=excluded.installed_at,last_verified_at=excluded.last_verified_at,last_error=excluded.last_error,updated_at=excluded.updated_at')
      .run(r.id,r.userId,r.targetId,r.username,r.privilege,r.encryptedPrivateKey,r.publicKey,r.fingerprint,r.encryptedSecret,r.authorizedKeyLine,r.authorizedKeySha256,r.sudoersSha256??null,r.pythonPath??null,r.verifierSha256??null,r.status,r.installedAt??null,r.lastVerifiedAt??null,r.lastError??null,r.createdAt,r.updatedAt);
  }
  activate(userId:string,id:string,pythonPath:string,verifierSha256:string):void{
    const now=Date.now();
    this.db.prepare("UPDATE verification_authorities SET status='active',python_path=?,verifier_sha256=?,last_verified_at=?,last_error=NULL,updated_at=? WHERE user_id=? AND id=?").run(pythonPath,verifierSha256,now,now,userId,id);
  }
  recordResult(userId:string,id:string,error?:string):void{
    const now=Date.now();
    if(error)this.db.prepare('UPDATE verification_authorities SET last_error=?,updated_at=? WHERE user_id=? AND id=?').run(error.slice(0,2000),now,userId,id);
    else this.db.prepare('UPDATE verification_authorities SET last_verified_at=?,last_error=NULL,updated_at=? WHERE user_id=? AND id=?').run(now,now,userId,id);
  }
  delete(userId:string,id:string):void{ this.db.prepare('DELETE FROM verification_authorities WHERE user_id=? AND id=?').run(userId,id); }
  private map=(r:any):VerificationAuthorityRecord|undefined=>r?{
    id:r.id,userId:r.user_id,targetId:r.target_id,username:r.username,privilege:r.privilege==='root'?'root':'sudo',
    encryptedPrivateKey:r.encrypted_private_key,publicKey:r.public_key,fingerprint:r.fingerprint,encryptedSecret:r.encrypted_secret,
    authorizedKeyLine:r.authorized_key_line,authorizedKeySha256:r.authorized_key_sha256,
    ...(r.sudoers_sha256?{sudoersSha256:r.sudoers_sha256}:{}),...(r.python_path?{pythonPath:r.python_path}:{}),...(r.verifier_sha256?{verifierSha256:r.verifier_sha256}:{}),
    status:r.status==='active'?'active':'pending',
    ...(r.installed_at!=null?{installedAt:r.installed_at}:{}),...(r.last_verified_at!=null?{lastVerifiedAt:r.last_verified_at}:{}),...(r.last_error?{lastError:r.last_error}:{}),
    createdAt:r.created_at,updatedAt:r.updated_at,
  }:undefined;
}
