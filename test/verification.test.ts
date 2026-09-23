import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import {
  blockingProblems, buildVerificationRequest, evaluateVerification, macVerificationBody, newVerificationNonce, parseVerificationResponse,
  renderSudoers, renderVerifierInstallScript, renderVerifierProgram, renderVerifierTemplate, verificationForcedCommand, verifierPaths,
  type VerificationExpectations,
} from '../src/verification.js';
import { buildCommandRestrictedAuthorizedKey, sha256Hex } from '../src/ssh.js';

const id=randomUUID(); const user='deploy'; const uid=1000; const secret=randomBytes(32);
const template=renderVerifierTemplate(id,user,'sudo'); const python='/usr/bin/python3.12';
const verifierSha=sha256Hex(renderVerifierProgram(template,python));
const vkeyBlob=randomBytes(51); const vkeyLine='restrict,command="'+verificationForcedCommand(id,'sudo')+'" ssh-ed25519 '+vkeyBlob.toString('base64')+' farcmd-verify:'+id;
const aBlob=randomBytes(51); const aLine='restrict,command="~/.ssh/farcmd/mcp.example.com-'+id+'.sh" ssh-ed25519 '+aBlob.toString('base64');
const aName='mcp.example.com-'+id+'.sh'; const aScript=sha256Hex('#!/usr/bin/env bash\necho a\n');
const expectations:VerificationExpectations={verifierId:id,username:user,privilege:'sudo',template,pythonPath:python,
  verificationKey:{authorizedKeySha256:sha256Hex(vkeyLine),blobSha256:sha256Hex(vkeyBlob)},managedPrefix:'mcp.example.com-',
  capabilities:[{commandId:'cmd-a',scriptName:aName,scriptSha256:aScript,authorizedKeySha256:sha256Hex(aLine),blobSha256:sha256Hex(aBlob)}],staleScriptNames:[]};

interface Body { nonce:string; self?:string; secretState?:string; script?:string; aLineSha?:string; extraCap?:string[]; extraAk?:string[]; }
function body(o:Body):string{
  return ['farcmd-verify 1','nonce '+o.nonce,'verifier '+id,'user '+user+' '+uid,'python '+python+' ok','self '+(o.self??verifierSha)+' ok','secret '+(o.secretState??'ok'),
    'sudoers '+sha256Hex(renderSudoers(id,user))+' ok','home ok '+uid+' 0750','capdir ok '+uid+' 0700',
    'cap '+aName+' f '+uid+' 0500 1 40 '+(o.script??aScript),...(o.extraCap??[]),
    'sshd ok none','akf 0 .ssh/authorized_keys ok '+'0'.repeat(64),
    'ak 0 1 '+sha256Hex(vkeyLine)+' '+sha256Hex(vkeyBlob),'ak 0 2 '+(o.aLineSha??sha256Hex(aLine))+' '+sha256Hex(aBlob),...(o.extraAk??[]),
    'akf 1 .ssh/authorized_keys2 absent -','end',''].join('\n');
}
const sign=(b:string,key=secret)=>b+'mac '+macVerificationBody(key,b)+'\n';

test('a genuine, fresh, matching response verifies',()=>{
  const nonce=newVerificationNonce();
  const report=parseVerificationResponse(sign(body({nonce})),secret,nonce);
  assert.deepEqual(evaluateVerification(report,expectations).problems,[]);
});

test('forged verifier: correct-looking state with a MAC under any other key is rejected',()=>{
  const nonce=newVerificationNonce();
  assert.throws(()=>parseVerificationResponse(sign(body({nonce}),randomBytes(32)),secret,nonce),/invalid MAC/);
  // Tampering with any single byte after signing is detected.
  const signed=sign(body({nonce}));
  assert.throws(()=>parseVerificationResponse(signed.replace(' 0500 ',' 0700 '),secret,nonce),/invalid MAC/);
});

test('replayed response (old nonce) and wrong nonce are rejected even with a valid MAC',()=>{
  const old=newVerificationNonce(); const replay=sign(body({nonce:old}));
  assert.throws(()=>parseVerificationResponse(replay,secret,newVerificationNonce()),/stale or replayed/);
});

test('missing challenge, missing MAC and malformed responses are rejected',()=>{
  const nonce=newVerificationNonce();
  const noNonce=sign(body({nonce}).replace(/^nonce .*\n/m,''));
  assert.throws(()=>parseVerificationResponse(noNonce,secret,nonce),/Malformed verifier response \(nonce\)/);
  assert.throws(()=>parseVerificationResponse(body({nonce}),secret,nonce),/missing its authentication tag/);
  assert.throws(()=>parseVerificationResponse(sign(body({nonce})+'extra\n'),secret,nonce),/Malformed|trailing/);
  assert.throws(()=>parseVerificationResponse(sign(body({nonce}).replace('end\n','')),secret,nonce),/Malformed/);
  assert.throws(()=>parseVerificationResponse(sign(body({nonce}))+'trailing',secret,nonce),/malformed authentication tag/);
  assert.throws(()=>parseVerificationResponse(sign(body({nonce}).replace('farcmd-verify 1','farcmd-verify 2')),secret,nonce),/version/);
  assert.throws(()=>parseVerificationResponse(sign(body({nonce})+'').replace('deploy','déploy'),secret,nonce),/non-canonical/);
  assert.throws(()=>parseVerificationResponse('',secret,nonce),/authentication tag/);
});

test('changed script, changed or duplicated authorized_keys entry and unexpected files are problems',()=>{
  const nonce=newVerificationNonce();
  const evalOf=(o:Omit<Body,'nonce'>)=>evaluateVerification(parseVerificationResponse(sign(body({nonce,...o})),secret,nonce),expectations);
  assert.match(blockingProblems(evalOf({script:'f'.repeat(64)}),'cmd-a')[0]!.message,/Remote script content changed/);
  assert.match(blockingProblems(evalOf({aLineSha:'e'.repeat(64)}),'cmd-a')[0]!.message,/entry was modified/);
  assert.match(blockingProblems(evalOf({extraAk:['ak 0 3 '+'d'.repeat(64)+' '+sha256Hex(aBlob)]}),'cmd-a')[0]!.message,/appears in 2/);
  assert.match(blockingProblems(evalOf({extraCap:['cap mcp.example.com-'+randomUUID()+'.sh f '+uid+' 0700 1 3 '+'c'.repeat(64)]}),'other')[0]!.message,/Unexpected file/);
  // Script problems are scoped to their command; verifier/global problems block everything.
  assert.equal(blockingProblems(evalOf({script:'f'.repeat(64)}),'cmd-b').length,0);
  assert.match(blockingProblems(evalOf({self:'a'.repeat(64)}),'cmd-b')[0]!.message,/differs from the program farcmd installed/);
  assert.match(blockingProblems(evalOf({secretState:'bad:mode'}),'cmd-b')[0]!.message,/not root-only/);
  // Missing expected file.
  const missing=body({nonce}).replace(/^cap .*\n/m,'');
  assert.match(blockingProblems(evaluateVerification(parseVerificationResponse(sign(missing),secret,nonce),expectations),'cmd-a')[0]!.message,/missing/);
});

test('verifier installation artifacts: forced command, argument-free sudo rule, secret only on stdin',()=>{
  assert.equal(verificationForcedCommand(id,'sudo'),'sudo -n /usr/local/libexec/farcmd/verify-'+id);
  const line=buildCommandRestrictedAuthorizedKey('ssh-ed25519 '+vkeyBlob.toString('base64')+' farcmd-verify:'+id,verificationForcedCommand(id,'sudo'));
  assert.match(line,/^restrict,command="sudo -n \/usr\/local\/libexec\/farcmd\/verify-[0-9a-f-]{36}" ssh-ed25519 /);
  assert.match(renderSudoers(id,user),new RegExp('^deploy ALL=\\(root\\) NOPASSWD: /usr/local/libexec/farcmd/verify-'+id+' ""$','m'));
  const script=renderVerifierInstallScript({id,username:user,privilege:'sudo',secret,authorizedKeyLine:line});
  assert.ok(script.includes(secret.toString('hex')));
  assert.match(script,/printf '%s\\n' '[0-9a-f]{64}' > "\$tmp"/,'secret is written by the printf builtin');
  assert.match(script,/chmod 0600 "\$tmp"/); assert.match(script,/visudo -cf/); assert.match(script,/runuser -u 'deploy'/);
  assert.throws(()=>renderVerifierTemplate(id,'bad user','sudo'));
  assert.throws(()=>renderVerifierTemplate(id,"x';rm",'sudo'));
  assert.throws(()=>verifierPaths('../../etc/passwd'));
  assert.throws(()=>renderVerifierProgram(template,'/home/deploy/python3'),/interpreter/);
});

test('the verifier program accepts nothing but a well-formed challenge on stdin',{skip:spawnSync('python3',['--version']).status!==0?'python3 not available':false},()=>{
  const dir=mkdtempSync(join(tmpdir(),'farcmd-verifier-'));
  try{
    const file=join(dir,'verify.py'); writeFileSync(file,renderVerifierProgram(template,'/usr/bin/python3'));
    const run=(input:string,args:string[]=[])=>spawnSync('python3',['-I','-S',file,...args],{input,encoding:'utf8'});
    for(const bad of ['','VERIFY\n','FARCMD-VERIFY 1 '+'0'.repeat(63)+'\n','FARCMD-VERIFY 1 '+'0'.repeat(64)+' ; id\n','FARCMD-VERIFY 1 '+'A'.repeat(64)+'\n','FARCMD-VERIFY 2 '+'0'.repeat(64)+'\n','FARCMD-VERIFY 1 '+'0'.repeat(64)+'\nextra','$(id)\n']){
      const r=run(bad); assert.equal(r.status,2,JSON.stringify(bad)); assert.equal(r.stdout,''); assert.match(r.stderr,/malformed request/);
    }
    if(process.getuid?.()!==0){
      const r=run(buildVerificationRequest(newVerificationNonce()),['/etc/shadow']);
      assert.equal(r.status,3); assert.equal(r.stdout,''); assert.match(r.stderr,/not running as root/);
    }
  }finally{rmSync(dir,{recursive:true,force:true});}
});
