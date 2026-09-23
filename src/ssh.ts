import { Client, utils, type ConnectConfig } from 'ssh2';
import { createHash } from 'node:crypto';

export interface SshKeyMaterial { privateKey: string; passphrase?: string; }
export interface SshTargetConfig { hostname:string; port:number; username:string; hostFingerprint?:string; }
export interface SshTestResult { ok:boolean; fingerprint?:string; error?:string; }
export interface SshExecResult { exitCode:number|null; signal?:string; stdout:string; stderr:string; durationMs:number; truncated?:boolean; }
const MAX_OUTPUT_BYTES=Number(process.env.FARCMD_MAX_OUTPUT_BYTES??'262144');
if(!Number.isSafeInteger(MAX_OUTPUT_BYTES)||MAX_OUTPUT_BYTES<4096||MAX_OUTPUT_BYTES>10_485_760)throw new Error('FARCMD_MAX_OUTPUT_BYTES must be 4096-10485760');

function privateKeyFingerprint(privateKey:string, passphrase?:string):string|undefined {
  const parsed=utils.parseKey(privateKey,passphrase);
  if(parsed instanceof Error)return undefined;
  const keys=Array.isArray(parsed)?parsed:[parsed];
  const key=keys.find(k=>typeof k.isPrivateKey==='function'&&k.isPrivateKey());
  if(!key)return undefined;
  const publicSsh=key.getPublicSSH();
  const body=publicSsh.trim().split(/\s+/).slice(1,2)[0];
  if(!body)return undefined;
  return 'sha256:'+createHash('sha256').update(Buffer.from(body,'base64')).digest('base64url');
}

export function inspectPrivateKey(privateKey:string,passphrase?:string):{valid:boolean;encrypted:boolean;fingerprint?:string}{
  const withoutPassphrase=utils.parseKey(privateKey);
  if(!(withoutPassphrase instanceof Error)){
    const fingerprint=privateKeyFingerprint(privateKey);
    return {valid:true,encrypted:false,...(fingerprint?{fingerprint}:{})};
  }
  if(passphrase!==undefined){
    const withPassphrase=utils.parseKey(privateKey,passphrase);
    if(!(withPassphrase instanceof Error)){
      const fingerprint=privateKeyFingerprint(privateKey,passphrase);
      return {valid:true,encrypted:true,...(fingerprint?{fingerprint}:{})};
    }
  }
  const encrypted=privateKey.includes('BEGIN OPENSSH PRIVATE KEY')||privateKey.includes('BEGIN ENCRYPTED PRIVATE KEY')||privateKey.includes('Proc-Type: 4,ENCRYPTED');
  return {valid:encrypted,encrypted};
}

function makeSshConfig(target:SshTargetConfig,key:SshKeyMaterial,hostVerifier:(fingerprint:string)=>boolean):ConnectConfig {
  let presented:string|undefined;
  return {
    host:target.hostname,port:target.port,username:target.username,
    privateKey:key.privateKey,...(key.passphrase!==undefined?{passphrase:key.passphrase}:{}),
    readyTimeout:10_000,hostHash:'sha256',
    hostVerifier:(fingerprint:string)=>{ presented='sha256:'+fingerprint; return hostVerifier(presented); },
  };
}

export async function testSshConnection(target:SshTargetConfig,key:SshKeyMaterial):Promise<SshTestResult>{
  return new Promise(resolve=>{
    const client=new Client(); let presented:string|undefined; let settled=false;
    const finish=(result:SshTestResult)=>{if(settled)return;settled=true;client.end();resolve(result);};
    const config=makeSshConfig(target,key,f=>!!target.hostFingerprint&&target.hostFingerprint===f);
    config.hostVerifier=f=>{presented='sha256:'+f;return !!target.hostFingerprint&&target.hostFingerprint===presented;};
    client.once('ready',()=>finish({ok:true,...(presented?{fingerprint:presented}:{})}));
    client.once('error',err=>finish({ok:false,...(presented?{fingerprint:presented}:{}),error:target.hostFingerprint&&presented&&target.hostFingerprint!==presented?'Host key fingerprint does not match the configured fingerprint':(err.message||'SSH connection failed')}));
    client.connect(config);
  });
}

export async function executeSshCommand(target:SshTargetConfig,key:SshKeyMaterial,command:string,timeoutMs=30_000):Promise<SshExecResult>{
  return new Promise((resolve,reject)=>{
    const client=new Client(); let presented:string|undefined; let settled=false; const started=Date.now();
    const finish=(result:SshExecResult)=>{if(settled)return;settled=true;clearTimeout(timer);client.end();resolve(result);};
    const timer=setTimeout(()=>finish({exitCode:null,signal:'TIMEOUT',stdout,stderr:stderr+'\nCommand timed out.',durationMs:Date.now()-started}),timeoutMs);
    let stdout=''; let stderr=''; let truncated=false;
    const config=makeSshConfig(target,key,f=>!!target.hostFingerprint&&target.hostFingerprint===f);
    config.hostVerifier=f=>{presented='sha256:'+f;return !!target.hostFingerprint&&target.hostFingerprint===presented;};
    client.once('ready',()=>{
      client.exec(command,(err,stream)=>{
        if(err){finish({exitCode:null,stdout,stderr:stderr+'\n'+err.message,durationMs:Date.now()-started});return;}
        stream.on('data',(chunk:Buffer)=>{stdout+=chunk.toString();});
        stream.stderr.on('data',(chunk:Buffer)=>{stderr+=chunk.toString();});
        stream.on('close',(code:number|null,signal:string|undefined)=>finish({exitCode:typeof code==='number'?code:null,...(signal?{signal}:{ }),stdout,stderr,durationMs:Date.now()-started,truncated}));
      });
    });
    client.once('error',err=>{if(!settled)finish({exitCode:null,stdout,stderr:stderr+'\n'+err.message,durationMs:Date.now()-started});});
    try{client.connect(config);}catch(error){reject(error);}
  });
}


export function buildCommandRestrictedAuthorizedKey(publicKey:string,command:string):string {
  if(/\r|\n/.test(publicKey)||/\r|\n/.test(command))throw new Error('SSH public key and command must be single-line values.');
  if(!/^ssh-(?:ed25519|rsa)\s+\S+/.test(publicKey))throw new Error('Unsupported generated SSH public key.');
  const escapedCommand=command.replaceAll('\\','\\\\').replaceAll('"','\\"');
  return 'restrict,command="'+escapedCommand+'" '+publicKey.trim();
}

async function executeAsMaster(target:SshTargetConfig,key:SshKeyMaterial,command:string):Promise<SshExecResult>{
  const result=await executeSshCommand(target,key,command,30_000);
  if(result.exitCode!==0)throw new Error(result.stderr.trim()||'Remote SSH operation failed.');
  return result;
}

export async function installCommandRestrictedKey(target:SshTargetConfig,masterKey:SshKeyMaterial,authorizedKey:string):Promise<void>{
  const encoded=Buffer.from(authorizedKey,'utf8').toString('base64');
  const script='set -eu; umask 077; mkdir -p ~/.ssh; chmod 700 ~/.ssh; touch ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys; line=$(printf %s '+encoded+' | base64 -d); if ! grep -Fqx -- "$line" ~/.ssh/authorized_keys; then printf "%s\\n" "$line" >> ~/.ssh/authorized_keys; fi';
  await executeAsMaster(target,masterKey,script);
}

export async function removeCommandRestrictedKey(target:SshTargetConfig,masterKey:SshKeyMaterial,authorizedKey:string):Promise<void>{
  const encoded=Buffer.from(authorizedKey,'utf8').toString('base64');
  const script='set -eu; if [ -f ~/.ssh/authorized_keys ]; then line=$(printf %s '+encoded+' | base64 -d); tmp=$(mktemp ~/.ssh/authorized_keys.farcmd.XXXXXX); trap "rm -f \"$tmp\"" EXIT; if grep -Fvx -- "$line" ~/.ssh/authorized_keys > "$tmp"; then :; else code=$?; [ "$code" -eq 1 ]; fi; chmod 600 "$tmp"; mv "$tmp" ~/.ssh/authorized_keys; trap - EXIT; fi';
  await executeAsMaster(target,masterKey,script);
}
