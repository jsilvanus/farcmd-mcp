import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { b64, sha256Hex } from './ssh.js';
import { VERIFIER_PROGRAM_TEMPLATE } from './verifier-program.js';

/**
 * Capability integrity verification protocol (farcmd side).
 *
 * The verification authority is a per-target root-owned verifier plus a root-only HMAC secret that
 * farcmd also holds (encrypted at rest). The verification SSH key is a forced-command capability
 * that can only start the verifier. farcmd sends a fresh 256-bit nonce, the verifier returns its
 * measurement of the remote state and HMAC-SHA256(secret, measurement). farcmd accepts the
 * measurement only if the MAC is valid and the nonce is the one it just generated, and then
 * compares every measured value with what farcmd itself provisioned.
 *
 * A verifier replaced by the target account cannot produce a valid MAC (it cannot read the
 * secret), and an old valid response cannot be replayed (it carries an old nonce).
 */

export const VERIFIER_PROTOCOL_VERSION=1;
export const VERIFIER_DIR='/usr/local/libexec/farcmd';
export const VERIFIER_SECRET_DIR='/etc/farcmd';
export const SUDOERS_DIR='/etc/sudoers.d';
const PYTHON_PLACEHOLDER='@@PYTHON@@';
const ALLOWED_PYTHON=/^\/(?:usr\/(?:local\/)?)?(?:bin|libexec)\/(?:python3(?:\.\d{1,2})?|platform-python(?:3(?:\.\d{1,2})?)?)$/;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HEX64=/^[0-9a-f]{64}$/;
const MAX_RESPONSE_BYTES=4*1024*1024;

export type VerifierPrivilege='sudo'|'root';
export class VerificationError extends Error { constructor(message:string){super(message);this.name='VerificationError';} }

export function assertVerifierId(id:string):void{ if(!UUID.test(id))throw new Error('Invalid verifier ID.'); }
/** Conservative POSIX account name check: the name is embedded in sudoers and in the root-owned verifier. */
export function isSafeTargetUsername(username:string):boolean{ return /^[a-z_][a-z0-9_-]{0,31}$/.test(username); }
function assertSafeTargetUsername(username:string):void{ if(!isSafeTargetUsername(username))throw new Error('Unsupported target username for the verifier.'); }
/** A sudo password farcmd can pass on stdin: one line, at most 1024 characters. */
export function isValidSudoPassword(password:string):boolean{ return password.length<=1024&&!/[\r\n\0]/.test(password); }
export function verifierPrivilegeFor(username:string):VerifierPrivilege{ return username==='root'?'root':'sudo'; }
/** sudoers applies the LAST matching rule and reads /etc/sudoers.d in lexical order, so the argument-free
 * NOPASSWD rule is named to sort after typical rules (e.g. a password-requiring "user ALL=(ALL) ALL"). */
export function verifierPaths(id:string){
  assertVerifierId(id);
  return {program:VERIFIER_DIR+'/verify-'+id,secret:VERIFIER_SECRET_DIR+'/verify-'+id+'.key',sudoers:SUDOERS_DIR+'/zz-farcmd-verify-'+id};
}
export function verificationKeyComment(id:string):string{ assertVerifierId(id); return 'farcmd-verify:'+id; }
/** The forced command bound to the verification key. It accepts no client input except the stdin challenge. */
export function verificationForcedCommand(id:string,privilege:VerifierPrivilege):string{
  const {program}=verifierPaths(id);
  return privilege==='root'?program:'sudo -n '+program;
}
export function renderVerifierTemplate(id:string,username:string,privilege:VerifierPrivilege):string{
  assertVerifierId(id);
  assertSafeTargetUsername(username);
  return VERIFIER_PROGRAM_TEMPLATE.replaceAll('@@ID@@',id).replaceAll('@@USER@@',username).replaceAll('@@SUDOERS@@',privilege==='sudo'?verifierPaths(id).sudoers:'');
}
export function isAllowedPythonPath(path:string):boolean{ return ALLOWED_PYTHON.test(path); }
/** Exact bytes the installer writes on the target once it has chosen the interpreter. */
export function renderVerifierProgram(template:string,pythonPath:string):string{
  if(!isAllowedPythonPath(pythonPath))throw new Error('Unsupported verifier interpreter path.');
  const newline=template.indexOf('\n');
  return template.slice(0,newline).replace(PYTHON_PLACEHOLDER,pythonPath)+template.slice(newline);
}
export function renderSudoers(id:string,username:string):string{
  const {program}=verifierPaths(id);
  assertSafeTargetUsername(username);
  // The empty-string argument list ("") means sudo refuses the rule if any argument is supplied.
  return ['# farcmd verification authority '+id+' (managed by farcmd; do not edit)','Defaults!'+program+' !requiretty',username+' ALL=(root) NOPASSWD: '+program+' ""',''].join('\n');
}
export function generateVerificationSecret():Buffer{ return randomBytes(32); }

function shq(value:string):string{ return "'"+value.replaceAll("'","'\\''")+"'"; }

/** Shell run as the target account (never as root) to (re)place this verifier's authorized_keys line. */
function userAuthorizedKeysScript(id:string,username:string,authorizedKeyLine:string|undefined):string{
  const marker=' '+verificationKeyComment(id);
  return [
    'set -eu','umask 077','[ "$(id -un)" = '+shq(username)+' ] || exit 1','cd',
    'mkdir -p .ssh','chmod 700 .ssh','touch .ssh/authorized_keys','chmod 600 .ssh/authorized_keys',
    'tmp=$(mktemp .ssh/authorized_keys.farcmd.XXXXXX)',
    'grep -v -- '+shq(marker+'$')+' .ssh/authorized_keys > "$tmp" || test $? -eq 1',
    ...(authorizedKeyLine?['printf "%s\\n" '+shq(authorizedKeyLine)+' >> "$tmp"']:[]),
    'chmod 600 "$tmp"','mv -f "$tmp" .ssh/authorized_keys',
  ].join('\n');
}
function asTargetUser(username:string,script:string):string{
  // Root never writes into the account's home directly: that would follow symlinks planted by the account.
  const decoded='printf %s '+shq(b64(script))+' | base64 -d | ';
  return ['if command -v runuser >/dev/null 2>&1; then','  '+decoded+'runuser -u '+shq(username)+' -- /bin/sh -s','else','  '+decoded+'su -s /bin/sh '+shq(username)+' -c "/bin/sh -s"','fi'].join('\n');
}

/**
 * How farcmd obtains root for installing/removing the verifier over the master key's SSH session.
 * The installer script is always sent on stdin. With a sudo password, the password is the first stdin
 * line: the target shell reads it with the `read` builtin and feeds it to `sudo -S -v` through the
 * `printf` builtin, so it never appears in any argument list. Only after sudo accepted it is the rest of
 * stdin (the script) read by `sudo -n sh -s`; a rejected password stops before the script is consumed.
 * The sudo timestamp (keyed to this shell when there is no terminal) is dropped again with `sudo -k`.
 */
export function rootInstallInvocation(privilege:VerifierPrivilege,sudoPassword?:string):{command:string;stdinPrefix:string}{
  if(privilege==='root')return {command:'sh -s',stdinPrefix:''};
  if(sudoPassword===undefined||sudoPassword==='')return {command:'sudo -n sh -s',stdinPrefix:''};
  if(!isValidSudoPassword(sudoPassword))throw new Error('Invalid sudo password.');
  return {
    command:"IFS= read -r farcmd_pw || exit 1; printf '%s\\n' \"$farcmd_pw\" | command sudo -S -p '' -v 2>/dev/null || { echo 'farcmd: sudo rejected the password (or the account may not use sudo)' >&2; exit 1; }; unset farcmd_pw; command sudo -n sh -s; rc=$?; command sudo -k; exit $rc",
    stdinPrefix:sudoPassword+'\n',
  };
}

interface VerifierInstallParams { id:string; username:string; privilege:VerifierPrivilege; secret:Buffer; authorizedKeyLine:string; }
/**
 * POSIX sh installer that must run as root on the target (farcmd pipes it into sudo via the master key,
 * see rootInstallInvocation, or an administrator runs it manually). It contains the verification secret: it is only
 * ever sent on stdin, never on a command line, and must not be stored on the target.
 */
export function renderVerifierInstallScript(p:VerifierInstallParams):string{
  const paths=verifierPaths(p.id);
  const template=renderVerifierTemplate(p.id,p.username,p.privilege);
  if(p.secret.length!==32)throw new Error('Verification secret must be 32 bytes.');
  if(/[\r\n']/.test(p.authorizedKeyLine))throw new Error('Invalid verification authorized key line.');
  return [
    '#!/bin/sh',
    '# farcmd verification authority installer ('+p.id+'). Run as root on the target. Contains a secret: do not keep a copy.',
    'set -eu','umask 077',
    'fail() { echo "farcmd: $*" >&2; exit 1; }',
    '[ "$(id -u)" -eq 0 ] || fail "the verifier installer must run as root"',
    'user='+shq(p.username),
    'getent passwd "$user" >/dev/null || fail "unknown account $user"',
    'py=',
    'for c in /usr/bin/python3 /usr/libexec/platform-python /usr/local/bin/python3 /bin/python3; do if [ -x "$c" ]; then py=$(readlink -f "$c"); break; fi; done',
    '[ -n "$py" ] || fail "python3 is required on the target for the farcmd verifier"',
    'case "$py" in /usr/bin/python3*|/usr/local/bin/python3*|/bin/python3*|/usr/libexec/platform-python*) ;; *) fail "unsupported python3 location $py";; esac',
    'install -d -o root -g root -m 0755 '+VERIFIER_DIR,
    'install -d -o root -g root -m 0700 '+VERIFIER_SECRET_DIR,
    'tmp=$(mktemp '+VERIFIER_DIR+'/.verify.XXXXXX)',
    'printf %s '+shq(b64(template))+' | base64 -d | sed "1s|'+PYTHON_PLACEHOLDER+'|$py|" > "$tmp"',
    'chown root:root "$tmp"','chmod 0755 "$tmp"','mv -f "$tmp" '+paths.program,
    'tmp=$(mktemp '+VERIFIER_SECRET_DIR+'/.key.XXXXXX)',
    // printf is a shell builtin: the secret never appears in any process argument list.
    "printf '%s\\n' "+shq(p.secret.toString('hex'))+' > "$tmp"',
    'chown root:root "$tmp"','chmod 0600 "$tmp"','mv -f "$tmp" '+paths.secret,
    ...(p.privilege==='sudo'?[
      'command -v visudo >/dev/null 2>&1 || fail "sudo/visudo is required on the target"',
      '[ -d '+SUDOERS_DIR+' ] || install -d -o root -g root -m 0750 '+SUDOERS_DIR,
      'tmp=$(mktemp '+SUDOERS_DIR+'/.farcmd.XXXXXX)',
      'printf %s '+shq(b64(renderSudoers(p.id,p.username)))+' | base64 -d > "$tmp"',
      'chown root:root "$tmp"','chmod 0440 "$tmp"',
      'visudo -cf "$tmp" >/dev/null || { rm -f "$tmp"; fail "generated sudoers rule failed validation"; }',
      'mv -f "$tmp" '+paths.sudoers,
    ]:[]),
    asTargetUser(p.username,userAuthorizedKeysScript(p.id,p.username,p.authorizedKeyLine)),
    'echo "farcmd verifier installed: '+paths.program+' ($py)"',
    '',
  ].join('\n');
}
export function renderVerifierUninstallScript(id:string,username:string):string{
  const paths=verifierPaths(id);
  assertSafeTargetUsername(username);
  return ['#!/bin/sh','# farcmd verification authority removal ('+id+'). Run as root on the target.','set -eu','[ "$(id -u)" -eq 0 ] || { echo "farcmd: must run as root" >&2; exit 1; }',
    'rm -f -- '+paths.sudoers+' '+paths.program+' '+paths.secret,
    'if getent passwd '+shq(username)+' >/dev/null; then',asTargetUser(username,userAuthorizedKeysScript(id,username,undefined)),'fi',''].join('\n');
}

// ---------------------------------------------------------------------------------------------
// Request / response

export function newVerificationNonce():string{ return randomBytes(32).toString('hex'); }
export function buildVerificationRequest(nonce:string):string{
  if(!HEX64.test(nonce))throw new Error('Invalid verification nonce.');
  return 'FARCMD-VERIFY '+VERIFIER_PROTOCOL_VERSION+' '+nonce+'\n';
}
export function macVerificationBody(secret:Buffer,body:string):string{ return createHmac('sha256',secret).update(Buffer.from(body,'ascii')).digest('hex'); }

export interface VerifiedEntry { name:string; type:'f'|'d'|'l'|'o'; uid:number; mode:number; nlink:number; size:number; sha256:string; }
export interface VerifiedAuthorizedKeysFile { index:number; path:string; state:string; sha256:string|null; }
export interface VerifiedAuthorizedKeyLine { file:number; line:number; sha256:string; blobs:string[]; }
export interface VerificationReport {
  nonce:string; verifierId:string; user:string; uid:number;
  python:{path:string;trust:string}; self:{sha256:string;trust:string}; secret:string;
  sudoers:{sha256:string;state:string};
  home:{state:string;uid:number|null;mode:number|null}; capdir:{state:string;uid:number|null;mode:number|null};
  capdirOverflow:boolean; entries:VerifiedEntry[];
  sshd:{state:string;authorizedKeysCommand:string};
  authorizedKeysFiles:VerifiedAuthorizedKeysFile[]; authorizedKeyLines:VerifiedAuthorizedKeyLine[];
}

const TOKEN='[A-Za-z0-9._/~+%-]+';
const STATE='(?:ok|absent|unavailable|-|bad:[A-Za-z0-9._/~+%:-]+)';
function decodeName(value:string):string{ return Buffer.from(value.replace(/%([0-9A-F]{2})/g,(_m,h:string)=>String.fromCharCode(parseInt(h,16))),'latin1').toString('latin1'); }
function num(value:string):number|null{ return value==='-'?null:Number(value); }

/**
 * Authenticate and parse a verifier response. The MAC is checked over the exact received bytes
 * before any field is interpreted; the nonce must equal the one farcmd generated for this request.
 */
export function parseVerificationResponse(raw:string,secret:Buffer,expectedNonce:string):VerificationReport{
  if(!HEX64.test(expectedNonce))throw new VerificationError('Invalid verification nonce.');
  if(raw.length>MAX_RESPONSE_BYTES)throw new VerificationError('Verifier response is too large.');
  if(!/^[\x20-\x7e\n]*$/.test(raw))throw new VerificationError('Verifier response contains non-canonical bytes.');
  const macAt=raw.lastIndexOf('\nmac ');
  if(macAt<0)throw new VerificationError('Verifier response is missing its authentication tag.');
  const body=raw.slice(0,macAt+1); const macLine=raw.slice(macAt+1);
  const macMatch=/^mac ([0-9a-f]{64})\n$/.exec(macLine);
  if(!macMatch)throw new VerificationError('Verifier response has a malformed authentication tag.');
  const expected=Buffer.from(macVerificationBody(secret,body),'hex'); const received=Buffer.from(macMatch[1]!,'hex');
  if(expected.length!==received.length||!timingSafeEqual(expected,received))throw new VerificationError('Verifier response authentication failed (invalid MAC).');
  const lines=body.slice(0,-1).split('\n'); let i=0;
  const take=(re:RegExp,what:string):RegExpExecArray=>{ const line=lines[i]; const m=line===undefined?null:re.exec(line); if(!m)throw new VerificationError('Malformed verifier response ('+what+').'); i++; return m; };
  const peek=(prefix:string)=>lines[i]?.startsWith(prefix)??false;
  take(new RegExp('^farcmd-verify '+VERIFIER_PROTOCOL_VERSION+'$'),'version');
  const nonce=take(/^nonce ([0-9a-f]{64})$/,'nonce')[1]!;
  if(nonce!==expectedNonce)throw new VerificationError('Verifier response does not answer the current challenge (stale or replayed response).');
  const verifierId=take(/^verifier ([0-9a-f-]{36})$/,'verifier')[1]!;
  const user=take(/^user ([a-z_][a-z0-9_-]{0,31}) (\d+)$/,'user');
  const python=take(new RegExp('^python ('+TOKEN+') ('+STATE+')$'),'python');
  const self=take(new RegExp('^self ([0-9a-f]{64}|-|toolarge) ('+STATE+')$'),'self');
  const secretState=take(new RegExp('^secret ('+STATE+')$'),'secret')[1]!;
  const sudoers=take(new RegExp('^sudoers ([0-9a-f]{64}|-|absent|toolarge) ('+STATE+')$'),'sudoers');
  const dirRe=(label:string)=>new RegExp('^'+label+' ('+STATE+') (\\d+|-) ([0-7]{4}|-)$');
  const home=take(dirRe('home'),'home'); const capdir=take(dirRe('capdir'),'capdir');
  let capdirOverflow=false;
  if(peek('capdir-overflow ')){take(/^capdir-overflow \d+$/,'capdir-overflow');capdirOverflow=true;}
  const entries:VerifiedEntry[]=[];
  while(peek('cap ')){
    const m=take(new RegExp('^cap ('+TOKEN+') ([fdlo]) (\\d+) ([0-7]{4}) (\\d+) (\\d+) ([0-9a-f]{64}|-|changed|toolarge)$'),'cap');
    entries.push({name:decodeName(m[1]!),type:m[2] as VerifiedEntry['type'],uid:Number(m[3]),mode:parseInt(m[4]!,8),nlink:Number(m[5]),size:Number(m[6]),sha256:m[7]!});
  }
  const sshd=take(new RegExp('^sshd (ok|unavailable) ('+TOKEN+')$'),'sshd');
  const files:VerifiedAuthorizedKeysFile[]=[]; const keyLines:VerifiedAuthorizedKeyLine[]=[];
  while(peek('akf ')||peek('ak ')){
    if(peek('akf ')){const m=take(new RegExp('^akf (\\d+) ('+TOKEN+') ('+STATE+') ([0-9a-f]{64}|-)$'),'akf');files.push({index:Number(m[1]),path:decodeName(m[2]!),state:m[3]!,sha256:m[4]==='-'?null:m[4]!});}
    else{const m=take(/^ak (\d+) (\d+) ([0-9a-f]{64}) ((?:[0-9a-f]{64})(?:,[0-9a-f]{64})*|-)$/,'ak');if(!files.some(f=>f.index===Number(m[1])))throw new VerificationError('Malformed verifier response (ak without akf).');keyLines.push({file:Number(m[1]),line:Number(m[2]),sha256:m[3]!,blobs:m[4]==='-'?[]:m[4]!.split(',')});}
  }
  take(/^end$/,'end');
  if(i!==lines.length)throw new VerificationError('Malformed verifier response (trailing data).');
  return {
    nonce,verifierId,user:user[1]!,uid:Number(user[2]),python:{path:decodeName(python[1]!),trust:python[2]!},self:{sha256:self[1]!,trust:self[2]!},secret:secretState,
    sudoers:{sha256:sudoers[1]!,state:sudoers[2]!},
    home:{state:home[1]!,uid:num(home[2]!),mode:home[3]==='-'?null:parseInt(home[3]!,8)},capdir:{state:capdir[1]!,uid:num(capdir[2]!),mode:capdir[3]==='-'?null:parseInt(capdir[3]!,8)},
    capdirOverflow,entries,sshd:{state:sshd[1]!,authorizedKeysCommand:decodeName(sshd[2]!)},authorizedKeysFiles:files,authorizedKeyLines:keyLines,
  };
}

// ---------------------------------------------------------------------------------------------
// Expected-state comparison

export interface ExpectedCapability { commandId:string; scriptName:string; scriptSha256:string; authorizedKeySha256:string; blobSha256:string; }
export interface VerificationExpectations {
  verifierId:string; username:string; privilege:VerifierPrivilege; template:string;
  /** Interpreter recorded at activation. Undefined while activating: any allow-listed interpreter is accepted once. */
  pythonPath?:string;
  verificationKey:{authorizedKeySha256:string;blobSha256:string};
  /** Filename prefix of this farcmd instance's scripts in ~/.ssh/farcmd (e.g. "mcp.example.com-"). */
  managedPrefix:string;
  capabilities:ExpectedCapability[];
  /** Capabilities removed locally but still awaiting remote cleanup (remote capability ledger). */
  staleScriptNames:string[];
}
export interface VerificationProblem { scope:'verifier'|'global'|'command'; commandId?:string; message:string; }
export interface VerificationEvaluation { problems:VerificationProblem[]; pythonPath:string; verifierSha256:string; }

/** Problems that block execution of commandId (verifier/global problems block every command). */
export function blockingProblems(evaluation:VerificationEvaluation,commandId?:string):VerificationProblem[]{
  return evaluation.problems.filter(p=>p.scope!=='command'||p.commandId===commandId);
}

export function evaluateVerification(report:VerificationReport,x:VerificationExpectations):VerificationEvaluation{
  const problems:VerificationProblem[]=[];
  const verifier=(message:string)=>problems.push({scope:'verifier',message});
  const global=(message:string)=>problems.push({scope:'global',message});
  const command=(commandId:string,message:string)=>problems.push({scope:'command',commandId,message});
  // --- verification authority itself
  if(report.verifierId!==x.verifierId)verifier('Verifier identity does not match this target.');
  if(report.user!==x.username)verifier('Verifier measured a different account ('+report.user+').');
  const pythonPath=report.python.path;
  if(!isAllowedPythonPath(pythonPath))verifier('Verifier runs under an unexpected interpreter.');
  else if(x.pythonPath!==undefined&&x.pythonPath!==pythonPath)verifier('Verifier interpreter changed since activation.');
  if(report.python.trust!=='ok')verifier('Verifier interpreter is not root-protected ('+report.python.trust+').');
  let verifierSha256='';
  try{verifierSha256=sha256Hex(renderVerifierProgram(x.template,pythonPath));}catch{}
  if(report.self.trust!=='ok')verifier('Verifier program is not root-protected ('+report.self.trust+').');
  if(!verifierSha256||report.self.sha256!==verifierSha256)verifier('Verifier program differs from the program farcmd installed.');
  if(report.secret!=='ok')verifier('Verification secret is not root-only ('+report.secret+').');
  if(x.privilege==='sudo'){
    if(report.sudoers.state!=='ok')verifier('Verifier sudoers rule is not root-protected ('+report.sudoers.state+').');
    if(report.sudoers.sha256!==sha256Hex(renderSudoers(x.verifierId,x.username)))verifier('Verifier sudoers rule differs from the rule farcmd installed.');
  } else if(report.sudoers.sha256!=='absent')verifier('Unexpected sudoers measurement for a root verifier.');
  // --- account-level state
  if(report.home.state!=='ok')global('Home directory could not be measured ('+report.home.state+').');
  else if((report.home.uid!==report.uid&&report.home.uid!==0)||report.home.mode===null||(report.home.mode&0o022))global('Home directory is writable by other accounts.');
  const allLines=report.authorizedKeyLines;
  for(const f of report.authorizedKeysFiles)if(f.state!=='ok'&&f.state!=='absent')global('authorized_keys file '+f.path+' is unsafe or unreadable ('+f.state+').');
  if(!report.authorizedKeysFiles.some(f=>f.state==='ok'))global('No readable authorized_keys file was measured.');
  const checkKey=(blob:string,lineSha:string,label:string,report_:(m:string)=>void)=>{
    const matches=allLines.filter(l=>l.blobs.includes(blob));
    if(matches.length===0)report_(label+' authorized_keys entry is missing.');
    else if(matches.length>1)report_(label+' key appears in '+matches.length+' authorized_keys entries (duplicate or unrestricted copy).');
    else if(matches[0]!.sha256!==lineSha)report_(label+' authorized_keys entry was modified.');
  };
  checkKey(x.verificationKey.blobSha256,x.verificationKey.authorizedKeySha256,'Verification',verifier);
  // --- capability directory
  const expectedByName=new Map(x.capabilities.map(c=>[c.scriptName,c]));
  const stale=new Set(x.staleScriptNames);
  if(report.capdir.state==='ok'){
    if(report.capdir.uid!==report.uid||report.capdir.mode===null||(report.capdir.mode&0o022))global('~/.ssh/farcmd is not owned by the account or is writable by others.');
  } else if(report.capdir.state!=='absent'||x.capabilities.length>0)global('~/.ssh/farcmd could not be measured ('+report.capdir.state+').');
  if(report.capdirOverflow)global('~/.ssh/farcmd contains too many entries to measure.');
  for(const e of report.entries){
    if(!e.name.startsWith(x.managedPrefix)||expectedByName.has(e.name)||stale.has(e.name))continue;
    global('Unexpected file in the farcmd capability namespace: '+e.name+'.');
  }
  for(const c of x.capabilities){
    const e=report.entries.find(v=>v.name===c.scriptName);
    if(!e)command(c.commandId,'Remote script is missing.');
    else if(e.type!=='f')command(c.commandId,'Remote script is not a regular file.');
    else if(e.uid!==report.uid)command(c.commandId,'Remote script is not owned by the account.');
    else if(e.nlink!==1)command(c.commandId,'Remote script has additional hard links.');
    else if(e.mode&0o022)command(c.commandId,'Remote script is writable by other accounts.');
    else if(e.sha256!==c.scriptSha256)command(c.commandId,'Remote script content changed.');
    checkKey(c.blobSha256,c.authorizedKeySha256,'Command',m=>command(c.commandId,m));
  }
  return {problems,pythonPath,verifierSha256};
}
