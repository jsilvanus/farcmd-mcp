import ssh2, { type ConnectConfig } from 'ssh2';
// ssh2 is CommonJS; only some of its exports are visible as ESM named exports (utils is not).
const { Client, utils }=ssh2;
import { createHash } from 'node:crypto';

export interface SshKeyMaterial { privateKey: string; passphrase?: string; }
export interface SshTargetConfig { hostname:string; port:number; username:string; hostFingerprint?:string; }
export interface SshTestResult { ok:boolean; fingerprint?:string; error?:string; }
export interface SshExecResult { exitCode:number|null; signal?:string; stdout:string; stderr:string; durationMs:number; truncated?:boolean; }
export interface SshExecOptions { timeoutMs?:number; stdin?:string|Buffer; }
/** An authenticated SSH connection on which exactly one command may be executed. */
export interface SshSession { exec(command:string,options?:SshExecOptions):Promise<SshExecResult>; close():void; }
export function sha256Hex(value:string|Buffer):string{return createHash('sha256').update(value).digest('hex');}
const MAX_OUTPUT_BYTES=Number(process.env.FARCMD_MAX_OUTPUT_BYTES??'262144');
if(!Number.isSafeInteger(MAX_OUTPUT_BYTES)||MAX_OUTPUT_BYTES<4096||MAX_OUTPUT_BYTES>10_485_760)throw new Error('FARCMD_MAX_OUTPUT_BYTES must be 4096-10485760');

type ParsedKey=Exclude<ReturnType<typeof utils.parseKey>,Error|unknown[]>;
/** Parses an SSH key: an Error when it cannot be parsed (with this passphrase), else its private key, if any. */
export function parsePrivateKey(privateKey:string,passphrase?:string):Error|ParsedKey|undefined{
  const parsed=utils.parseKey(privateKey,passphrase);
  if(parsed instanceof Error)return parsed;
  return (Array.isArray(parsed)?parsed:[parsed]).find(k=>typeof k.isPrivateKey==='function'&&k.isPrivateKey());
}

function fingerprintOf(key:ParsedKey|undefined):string|undefined {
  if(!key)return undefined;
  // getPublicSSH() returns the SSH wire-format public key blob (a Buffer), not an OpenSSH text line.
  const blob=key.getPublicSSH() as Buffer|string;
  let raw:Buffer; try{raw=typeof blob==='string'?publicKeyBlob(blob):blob;}catch{return undefined;}
  if(!raw.length)return undefined;
  return 'sha256:'+createHash('sha256').update(raw).digest('base64url');
}

export function inspectPrivateKey(privateKey:string,passphrase?:string):{valid:boolean;encrypted:boolean;fingerprint?:string}{
  const withoutPassphrase=parsePrivateKey(privateKey);
  if(!(withoutPassphrase instanceof Error)){
    const fingerprint=fingerprintOf(withoutPassphrase);
    return {valid:true,encrypted:false,...(fingerprint?{fingerprint}:{})};
  }
  if(passphrase!==undefined){
    const withPassphrase=parsePrivateKey(privateKey,passphrase);
    if(!(withPassphrase instanceof Error)){
      const fingerprint=fingerprintOf(withPassphrase);
      return {valid:true,encrypted:true,...(fingerprint?{fingerprint}:{})};
    }
  }
  const encrypted=privateKey.includes('BEGIN OPENSSH PRIVATE KEY')||privateKey.includes('BEGIN ENCRYPTED PRIVATE KEY')||privateKey.includes('Proc-Type: 4,ENCRYPTED');
  return {valid:encrypted,encrypted};
}

/** Raw base64 key blob of an OpenSSH public key line ("ssh-ed25519 AAAA... comment"). */
export function publicKeyBlob(publicKey:string):Buffer{
  const body=publicKey.trim().split(/\s+/)[1];
  if(!body)throw new Error('Invalid SSH public key.');
  return Buffer.from(body,'base64');
}

function makeSshConfig(target:SshTargetConfig,key:SshKeyMaterial,onPresented:(fingerprint:string)=>void):ConnectConfig {
  return {
    host:target.hostname,port:target.port,username:target.username,
    privateKey:key.privateKey,...(key.passphrase!==undefined?{passphrase:key.passphrase}:{}),
    readyTimeout:10_000,hostHash:'sha256',
    // No agent, no agent forwarding, no PTY: farcmd never needs them.
    hostVerifier:(fingerprint:string)=>{ const presented='sha256:'+fingerprint; onPresented(presented); return !!target.hostFingerprint&&target.hostFingerprint===presented; },
  };
}

export async function testSshConnection(target:SshTargetConfig,key:SshKeyMaterial):Promise<SshTestResult>{
  return new Promise(resolve=>{
    const client=new Client(); let presented:string|undefined; let settled=false;
    const finish=(result:SshTestResult)=>{if(settled)return;settled=true;client.end();resolve(result);};
    client.once('ready',()=>finish({ok:true,...(presented?{fingerprint:presented}:{})}));
    client.once('error',err=>finish({ok:false,...(presented?{fingerprint:presented}:{}),error:target.hostFingerprint&&presented&&target.hostFingerprint!==presented?'Host key fingerprint does not match the configured fingerprint':(err.message||'SSH connection failed')}));
    client.connect(makeSshConfig(target,key,f=>{presented=f;}));
  });
}

/**
 * Connect and authenticate, but do not execute anything yet. Used to authenticate the execution
 * connection concurrently with integrity verification, so the time between measurement and
 * execution is one channel round trip instead of a whole SSH handshake.
 */
export async function openSshSession(target:SshTargetConfig,key:SshKeyMaterial):Promise<SshSession>{
  const client=new Client();
  await new Promise<void>((resolve,reject)=>{
    let presented:string|undefined;
    client.once('ready',()=>resolve());
    client.once('error',err=>reject(new Error(target.hostFingerprint&&presented&&target.hostFingerprint!==presented?'Host key fingerprint does not match the configured fingerprint':(err.message||'SSH connection failed'))));
    try{client.connect(makeSshConfig(target,key,f=>{presented=f;}));}catch(error){reject(error);}
  });
  let used=false; let closed=false;
  client.on('error',()=>undefined);
  const close=()=>{if(!closed){closed=true;client.end();}};
  return {close,exec(command,options={}){
    if(used||closed)return Promise.reject(new Error('SSH session already used.'));
    used=true;
    const timeoutMs=options.timeoutMs??30_000; const started=Date.now();
    return new Promise(resolve=>{
      const out:Buffer[]=[]; const err:Buffer[]=[]; let outBytes=0; let errBytes=0; let truncated=false; let settled=false;
      const text=(chunks:Buffer[])=>Buffer.concat(chunks).toString('utf8');
      const finish=(result:Omit<SshExecResult,'stdout'|'stderr'|'durationMs'>&{extraErr?:string})=>{
        if(settled)return;settled=true;clearTimeout(timer);close();
        const {extraErr,...rest}=result;
        resolve({...rest,stdout:text(out),stderr:text(err)+(extraErr??''),durationMs:Date.now()-started,...(truncated?{truncated:true}:{})});
      };
      const timer=setTimeout(()=>finish({exitCode:null,signal:'TIMEOUT',extraErr:'\nCommand timed out.'}),timeoutMs);
      const collect=(chunks:Buffer[],chunk:Buffer,used:number):number=>{
        const room=MAX_OUTPUT_BYTES-used;
        if(room<=0){truncated=true;return used;}
        if(chunk.length>room){chunks.push(chunk.subarray(0,room));truncated=true;return MAX_OUTPUT_BYTES;}
        chunks.push(chunk);return used+chunk.length;
      };
      client.exec(command,(error,stream)=>{
        if(error){finish({exitCode:null,extraErr:'\n'+error.message});return;}
        stream.on('data',(chunk:Buffer)=>{outBytes=collect(out,chunk,outBytes);});
        stream.stderr.on('data',(chunk:Buffer)=>{errBytes=collect(err,chunk,errBytes);});
        stream.on('close',(code:number|null,signal:string|undefined)=>finish({exitCode:typeof code==='number'?code:null,...(signal?{signal}:{})}));
        if(options.stdin!==undefined)stream.end(options.stdin); else stream.end();
      });
    });
  }};
}

export async function executeSshCommand(target:SshTargetConfig,key:SshKeyMaterial,command:string,timeoutMs=30_000,stdin?:string|Buffer):Promise<SshExecResult>{
  const started=Date.now();
  let session:SshSession;
  try{session=await openSshSession(target,key);}
  catch(error){return {exitCode:null,stdout:'',stderr:'\n'+(error instanceof Error?error.message:String(error)),durationMs:Date.now()-started};}
  return session.exec(command,{timeoutMs,...(stdin!==undefined?{stdin}:{})});
}


export function buildCommandRestrictedAuthorizedKey(publicKey:string,command:string):string {
  if(/\r|\n/.test(publicKey)||/\r|\n/.test(command))throw new Error('SSH public key and command must be single-line values.');
  if(!/^ssh-(?:ed25519|rsa)\s+\S+/.test(publicKey))throw new Error('Unsupported generated SSH public key.');
  const escapedCommand=command.replaceAll('\\','\\\\').replaceAll('"','\\\"');
  return 'restrict,command="'+escapedCommand+'" '+publicKey.trim();
}

export function safeMcpHost(publicUrl:string):string {
  try { const host=new URL(publicUrl).hostname.toLowerCase().replace(/[^a-z0-9.-]/g,'-'); if(host)return host; } catch {}
  return 'localhost';
}
export const FARCMD_CAPABILITY_DIR='.ssh/farcmd';
export function farcmdScriptPath(publicUrl:string,commandId:string):string {
  if(!/^[0-9a-fA-F-]{36}$/.test(commandId))throw new Error('Invalid command ID.');
  return '~/'+FARCMD_CAPABILITY_DIR+'/'+safeMcpHost(publicUrl)+'-'+commandId+'.sh';
}
/** Basename of a farcmd-managed script path, or undefined for anything that is not one (e.g. legacy rows). */
export function farcmdScriptName(remoteScriptPath:string):string|undefined {
  const prefix='~/'+FARCMD_CAPABILITY_DIR+'/';
  if(!remoteScriptPath.startsWith(prefix))return undefined;
  const name=remoteScriptPath.slice(prefix.length);
  return /^[a-z0-9.-]+-[0-9a-fA-F-]{36}\.sh$/.test(name)?name:undefined;
}
export function buildFarcmdScript(publicUrl:string,commandId:string,type:'shell'|'bash_script',content:string):string {
  if(/\r/.test(content))throw new Error('Command content must not contain carriage returns.');
  const header=['#!/usr/bin/env bash','# farcmd managed capability','# mcp: '+safeMcpHost(publicUrl),'# command-id: '+commandId,'# command-type: '+type,'set -euo pipefail',''].join('\n');
  return header+(type==='bash_script'?content:content.trim())+'\n';
}
export async function executeAsMaster(target:SshTargetConfig,key:SshKeyMaterial,command:string,stdin?:string|Buffer):Promise<SshExecResult>{
  const result=await executeSshCommand(target,key,command,30_000,stdin);
  if(result.exitCode!==0)throw new Error(result.stderr.trim()||'Remote SSH operation failed.');
  return result;
}
function b64(value:string):string{return Buffer.from(value,'utf8').toString('base64');}
/** Shell fragment appending one exact line to ~/.ssh/authorized_keys (run from $HOME). */
function appendAuthorizedKeyShell(authorizedKey:string):string{
  return ['mkdir -p .ssh','chmod 700 .ssh','touch .ssh/authorized_keys','chmod 600 .ssh/authorized_keys','key=$(printf %s '+b64(authorizedKey)+' | base64 -d)','if ! grep -Fqx -- "$key" .ssh/authorized_keys; then if [ -s .ssh/authorized_keys ] && [ -n "$(tail -c 1 .ssh/authorized_keys)" ]; then printf "\\n" >> .ssh/authorized_keys; fi; printf "%s\\n" "$key" >> .ssh/authorized_keys; fi'].join('; ');
}
export async function installCommandCapability(target:SshTargetConfig,masterKey:SshKeyMaterial,authorizedKey:string,remoteScriptPath:string,script:string):Promise<void>{
  const name=farcmdScriptName(remoteScriptPath);
  if(!name)throw new Error('Invalid farcmd script path.');
  // The script travels on stdin so that its exact bytes (including trailing newlines) are installed
  // and large scripts do not hit the per-argument length limit.
  const command=['set -eu','umask 077','cd','mkdir -p '+FARCMD_CAPABILITY_DIR,'chmod 700 .ssh '+FARCMD_CAPABILITY_DIR,'tmp=$(mktemp '+FARCMD_CAPABILITY_DIR+'/.install.XXXXXX)','cat > "$tmp"','chmod 500 "$tmp"','mv -f "$tmp" '+FARCMD_CAPABILITY_DIR+'/'+name,appendAuthorizedKeyShell(authorizedKey)].join('; ');
  await executeAsMaster(target,masterKey,command,script);
}
export async function removeCommandCapability(target:SshTargetConfig,masterKey:SshKeyMaterial,authorizedKey:string,remoteScriptPath:string):Promise<void>{
  const encodedKey=b64(authorizedKey);
  const name=farcmdScriptName(remoteScriptPath);
  const legacyPublicKey=/^ssh-(?:ed25519|rsa)\s+\S+/.test(authorizedKey);
  const filter=legacyPublicKey?'grep -Fv -- " $key"':'grep -Fvx -- "$key"';
  const command='set -eu; cd; key=$(printf %s '+encodedKey+' | base64 -d); if [ -f .ssh/authorized_keys ]; then tmp=$(mktemp .ssh/authorized_keys.farcmd.XXXXXX); '+filter+' .ssh/authorized_keys > "$tmp" || test $? -eq 1; chmod 600 "$tmp"; mv "$tmp" .ssh/authorized_keys; fi'+(name?'; rm -f -- '+FARCMD_CAPABILITY_DIR+'/'+name:'');
  await executeAsMaster(target,masterKey,command);
}
