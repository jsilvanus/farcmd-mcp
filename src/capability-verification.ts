import type { DatabaseSync } from 'node:sqlite';
import { decryptSecret } from './crypto-at-rest.js';
import { openSshSession, publicKeyBlob, sha256Hex, safeMcpHost, farcmdScriptName, type SshTargetConfig } from './ssh.js';
import { SqliteCommandInstallationStore, SqliteRemoteCapabilityLedgerStore } from './storage/command-installations.js';
import { SqliteVerificationAuthorityStore, verificationKeyAad, verificationSecretAad, type VerificationAuthorityRecord } from './storage/verification-authorities.js';
import type { SshTargetRecord } from './storage/ssh.js';
import {
  blockingProblems, buildVerificationRequest, evaluateVerification, newVerificationNonce, parseVerificationResponse, renderVerifierTemplate,
  VerificationError, type ExpectedCapability, type VerificationEvaluation, type VerificationExpectations, type VerificationProblem, type VerificationReport,
} from './verification.js';

export class IntegrityVerificationUnavailable extends Error { constructor(message:string){super(message);this.name='IntegrityVerificationUnavailable';} }
export interface TargetVerificationResult { ok:boolean; evaluation?:VerificationEvaluation; report?:VerificationReport; error?:string; }

function targetConfig(target:SshTargetRecord):SshTargetConfig{
  if(!target.hostFingerprint)throw new IntegrityVerificationUnavailable('SSH target has no pinned host fingerprint.');
  return {hostname:target.hostname,port:target.port,username:target.username,hostFingerprint:target.hostFingerprint};
}

/**
 * Runs the challenge/response protocol against a target's verification authority and compares the
 * authenticated measurement with farcmd's own provisioning records. It uses only the verification
 * key and secret: the master key is neither needed nor consulted, so verification survives master
 * deletion.
 */
export class CapabilityVerificationService {
  private readonly authorities:SqliteVerificationAuthorityStore; private readonly installations:SqliteCommandInstallationStore; private readonly ledger:SqliteRemoteCapabilityLedgerStore;
  constructor(db:DatabaseSync,private readonly publicUrl:string){
    this.authorities=new SqliteVerificationAuthorityStore(db); this.installations=new SqliteCommandInstallationStore(db); this.ledger=new SqliteRemoteCapabilityLedgerStore(db);
  }

  expectations(authority:VerificationAuthorityRecord,target:SshTargetRecord):VerificationExpectations{
    const capabilities:ExpectedCapability[]=[];
    for(const i of this.installations.list(authority.userId).filter(i=>i.targetId===target.id)){
      const scriptName=farcmdScriptName(i.remoteScriptPath);
      // Rows without a complete baseline cannot be verified; they are reported as problems for that command.
      capabilities.push({commandId:i.commandId,scriptName:scriptName??'',scriptSha256:i.scriptSha256??'',authorizedKeySha256:i.authorizedKeySha256??'',blobSha256:sha256Hex(publicKeyBlob(i.publicKey))});
    }
    const staleScriptNames=this.ledger.pendingForTarget(authority.userId,target.id).map(e=>farcmdScriptName(e.remoteScriptPath)).filter((n):n is string=>!!n);
    return {
      verifierId:authority.id,username:authority.username,privilege:authority.privilege,template:renderVerifierTemplate(authority.id,authority.username,authority.privilege),
      ...(authority.status==='active'&&authority.pythonPath?{pythonPath:authority.pythonPath}:{}),
      verificationKey:{authorizedKeySha256:authority.authorizedKeySha256,blobSha256:sha256Hex(publicKeyBlob(authority.publicKey))},
      managedPrefix:safeMcpHost(this.publicUrl)+'-',capabilities,staleScriptNames,
    };
  }

  /** One fresh challenge against the target. Throws only for local configuration problems. */
  async challenge(authority:VerificationAuthorityRecord,target:SshTargetRecord):Promise<{report:VerificationReport;evaluation:VerificationEvaluation}>{
    if(target.username!==authority.username)throw new IntegrityVerificationUnavailable('The SSH target account changed since the verifier was installed; reinstall the verifier.');
    const config=targetConfig(target);
    let privateKey:string; let secret:Buffer;
    try{
      privateKey=decryptSecret(authority.encryptedPrivateKey,verificationKeyAad(authority.userId,authority.id));
      secret=Buffer.from(decryptSecret(authority.encryptedSecret,verificationSecretAad(authority.userId,authority.id)),'hex');
    }catch{throw new IntegrityVerificationUnavailable('Unable to decrypt the verification credentials.');}
    if(secret.length!==32)throw new IntegrityVerificationUnavailable('Stored verification secret is invalid.');
    const nonce=newVerificationNonce();
    let stdout:string; let stderr:string; let exitCode:number|null; let truncated:boolean|undefined;
    try{
      const session=await openSshSession(config,{privateKey});
      // The command string is ignored by the forced-command key; only the stdin challenge reaches the verifier.
      ({stdout,stderr,exitCode,truncated}=await session.exec('farcmd-verify',{stdin:buildVerificationRequest(nonce),timeoutMs:30_000}));
    }catch(error){throw new VerificationError('Verifier unreachable: '+(error instanceof Error?error.message:String(error)));}
    if(exitCode!==0)throw new VerificationError('Verifier failed'+(stderr.trim()?': '+stderr.trim().split('\n').slice(-1)[0]!.slice(0,300):' (exit '+exitCode+')')+'.');
    if(truncated)throw new VerificationError('Verifier response exceeded the output limit.');
    const report=parseVerificationResponse(stdout,secret,nonce);
    return {report,evaluation:evaluateVerification(report,this.expectations(authority,target))};
  }

  /** Human-triggered verification (web UI). Activates a pending authority on its first authenticated, matching response. */
  async verifyTarget(userId:string,target:SshTargetRecord):Promise<TargetVerificationResult>{
    const authority=this.authorities.getForTarget(userId,target.id);
    if(!authority)return {ok:false,error:'No verification authority is installed for this target.'};
    try{
      const {report,evaluation}=await this.challenge(authority,target);
      const verifierProblems=evaluation.problems.filter(p=>p.scope==='verifier');
      if(verifierProblems.length){this.authorities.recordResult(userId,authority.id,verifierProblems.map(p=>p.message).join(' '));return {ok:false,evaluation,report};}
      if(authority.status!=='active')this.authorities.activate(userId,authority.id,evaluation.pythonPath,evaluation.verifierSha256);
      const problems=evaluation.problems;
      this.authorities.recordResult(userId,authority.id,problems.length?problems.map(p=>p.message).join(' '):undefined);
      return {ok:problems.length===0,evaluation,report};
    }catch(error){
      const message=error instanceof Error?error.message:String(error);
      this.authorities.recordResult(userId,authority.id,message);
      return {ok:false,error:message};
    }
  }

  /**
   * Execution gate for L3–L5. Resolves only if an active verification authority returned a fresh,
   * authenticated measurement in which the verifier, the account-level state and this command's
   * capability all match farcmd's records. Any other outcome throws: there is no unverified fallback.
   */
  /** Cheap local pre-check so that nothing is sent to the target when verification cannot possibly succeed. */
  assertAvailable(userId:string,target:SshTargetRecord):VerificationAuthorityRecord{
    const authority=this.authorities.getForTarget(userId,target.id);
    if(!authority)throw new IntegrityVerificationUnavailable('Integrity verification is unavailable for this target (no verification authority installed); level 3–5 commands are blocked.');
    if(authority.status!=='active')throw new IntegrityVerificationUnavailable('The verification authority for this target has not been activated; run "Verify now" in the farcmd web UI.');
    return authority;
  }
  async assertCommandIntact(userId:string,target:SshTargetRecord,commandId:string):Promise<void>{
    const authority=this.assertAvailable(userId,target);
    let evaluation:VerificationEvaluation;
    try{({evaluation}=await this.challenge(authority,target));}
    catch(error){const message=error instanceof Error?error.message:String(error);this.authorities.recordResult(userId,authority.id,message);throw error;}
    const blocking:VerificationProblem[]=blockingProblems(evaluation,commandId);
    if(!this.installations.get(userId,commandId))blocking.push({scope:'command',commandId,message:'No installed capability.'});
    if(blocking.length){
      const message=blocking.map(p=>p.message).join(' ');
      this.authorities.recordResult(userId,authority.id,message);
      throw new VerificationError('Command capability integrity check failed: '+message);
    }
    this.authorities.recordResult(userId,authority.id);
  }
}
