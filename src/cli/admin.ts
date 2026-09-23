#!/usr/bin/env -S node --disable-warning=ExperimentalWarning
/**
 * farcmd-admin: operator CLI for user accounts and instance settings.
 *
 * Works directly on the farcmd database (STORAGE_PATH, default ./data/app.sqlite). FARCMD_ENCRYPTION_KEY
 * must be set so that every change is written to the tamper-evident audit log. Passwords are never
 * accepted as command-line arguments (they would end up in shell history and the process list): they
 * are read from a hidden prompt, or from the first line of stdin with --password-stdin.
 */
import { parseArgs } from 'node:util';
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { SqliteAuthStore } from '../storage/sqlite.js';
import { UserAdmin, UserAdminError } from '../user-admin.js';

const USAGE=`farcmd-admin — manage farcmd users and settings

Usage:
  farcmd-admin user list [--json]
  farcmd-admin user create --email <email> --name <name> [--password-stdin]
  farcmd-admin user password --email <email> [--password-stdin]
  farcmd-admin user disable --email <email>
  farcmd-admin user enable --email <email>
  farcmd-admin user logout --email <email>
  farcmd-admin user delete --email <email> [--yes] [--force]
  farcmd-admin registration status|enable|disable

Environment:
  STORAGE_PATH            database file (default ./data/app.sqlite)
  FARCMD_ENCRYPTION_KEY   required (audit log)

Examples:
  node --env-file=.env dist/cli/admin.js user create --email alice@example.org --name Alice
  printf '%s\\n' "$PASSWORD" | farcmd-admin user password --email alice@example.org --password-stdin

user disable   blocks sign-in, web sessions, OAuth tokens and MCP access immediately (reversible).
user logout    ends all web sessions and OAuth refresh tokens of the user.
user delete    removes the user and all their farcmd data; refused while capabilities or verifiers
               remain installed on remote hosts unless --force (remove them in the web UI first).`;

class UsageError extends Error {}

async function readHidden(prompt:string):Promise<string>{
  const stdin=process.stdin; const out=process.stderr;
  out.write(prompt); stdin.setRawMode(true); stdin.resume(); stdin.setEncoding('utf8');
  return new Promise((resolve,reject)=>{
    let value='';
    const done=(error?:Error)=>{stdin.setRawMode(false);stdin.pause();stdin.removeListener('data',onData);out.write('\n');error?reject(error):resolve(value);};
    const onData=(chunk:string)=>{
      for(const ch of chunk){
        if(ch==='\r'||ch==='\n'){done();return;}
        if(ch==='\u0003'){done(new UsageError('Aborted.'));return;}
        if(ch==='\u007f'||ch==='\b'){value=value.slice(0,-1);continue;}
        if(ch>=' ')value+=ch;
      }
    };
    stdin.on('data',onData);
  });
}
async function readStdinLine():Promise<string>{
  const chunks:Buffer[]=[]; for await(const chunk of process.stdin)chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString('utf8').split(/\r?\n/)[0]??'';
}
async function readPassword(fromStdin:boolean):Promise<string>{
  if(fromStdin)return readStdinLine();
  if(!process.stdin.isTTY)throw new UsageError('No terminal for a password prompt: use --password-stdin.');
  const first=await readHidden('New password: '); const second=await readHidden('Repeat password: ');
  if(first!==second)throw new UsageError('Passwords do not match.');
  return first;
}
async function confirm(question:string,expected:string):Promise<boolean>{
  if(!process.stdin.isTTY)return false;
  process.stderr.write(question);
  const { createInterface }=await import('node:readline/promises');
  const rl=createInterface({input:process.stdin,output:process.stderr,terminal:false});
  try{return (await rl.question('')).trim()===expected;}finally{rl.close();}
}
const date=(ms?:number)=>ms===undefined?'':new Date(ms).toISOString().replace('T',' ').slice(0,16);

export async function main(argv:string[]):Promise<number>{
  const {values,positionals}=parseArgs({args:argv,allowPositionals:true,strict:true,options:{
    email:{type:'string'},name:{type:'string'},'password-stdin':{type:'boolean'},yes:{type:'boolean'},force:{type:'boolean'},json:{type:'boolean'},help:{type:'boolean',short:'h'}}});
  const [area,action]=positionals;
  if(values.help||!area){process.stdout.write(USAGE+'\n');return values.help?0:2;}
  // Must be the server's key: it keys the audit log's hash chain (and protects stored credentials).
  if(Buffer.from(process.env.FARCMD_ENCRYPTION_KEY??'','base64').length!==32)throw new UsageError('FARCMD_ENCRYPTION_KEY must be set to the server\'s base64 32-byte key (it keys the audit log). Tip: node --env-file=.env …');
  const store=new SqliteAuthStore(process.env.STORAGE_PATH??'./data/app.sqlite');
  const admin=new UserAdmin(store.getDatabase());
  const email=()=>{if(!values.email)throw new UsageError('--email is required.');return values.email;};

  if(area==='registration'){
    if(action==='enable'||action==='disable')admin.setRegistration(action==='enable');
    else if(action!=='status'&&action!==undefined)throw new UsageError('Unknown registration action: '+action);
    process.stdout.write('Self-service registration is '+(admin.registrationEnabled()?'ENABLED':'disabled')+'.\n');
    return 0;
  }
  if(area!=='user')throw new UsageError('Unknown command: '+area);
  switch(action){
    case 'list':{
      const users=admin.list();
      if(values.json){process.stdout.write(JSON.stringify(users,null,2)+'\n');return 0;}
      if(!users.length){process.stdout.write('No users.\n');return 0;}
      for(const u of users)process.stdout.write([u.email??'(no email)',u.name,u.disabledAt!==undefined?'DISABLED '+date(u.disabledAt):'active','created '+date(u.createdAt),u.commands+' commands',u.targets+' targets',u.installedCapabilities+' installed capabilities',u.verifiers+' verifiers'].join('  |  ')+'\n');
      return 0;
    }
    case 'create':{
      if(!values.name)throw new UsageError('--name is required.');
      const user=await admin.create({email:email(),name:values.name,password:await readPassword(!!values['password-stdin'])});
      process.stdout.write('Created user '+user.email+' ('+user.id+').\n'); return 0;
    }
    case 'password':{
      admin.find(email());
      await admin.setPassword(email(),await readPassword(!!values['password-stdin']));
      process.stdout.write('Password changed; all web sessions and OAuth refresh tokens of '+email()+' were ended.\n'); return 0;
    }
    case 'disable': case 'enable':{
      admin.setDisabled(email(),action==='disable');
      process.stdout.write(action==='disable'?'Disabled '+email()+': sign-in, sessions, OAuth tokens and MCP access are refused.\n':'Enabled '+email()+'.\n'); return 0;
    }
    case 'logout':{
      const r=admin.logoutEverywhere(email());
      process.stdout.write('Ended '+r.sessions+' web session(s) and '+r.refreshTokens+' OAuth refresh token(s).\n'); return 0;
    }
    case 'delete':{
      const u=admin.find(email());
      if(!values.yes&&!await confirm('Delete '+u.email+' and ALL of their farcmd data? Type the email to confirm: ',u.email??'')){
        process.stderr.write('Not deleted (confirmation missing; use --yes in scripts).\n'); return 1;
      }
      const s=admin.delete(email(),!!values.force);
      process.stdout.write('Deleted '+u.email+' ('+s.commands+' commands, '+s.targets+' targets).\n');
      if(s.installedCapabilities||s.verifiers)process.stdout.write('WARNING: '+s.installedCapabilities+' capabilities and '+s.verifiers+' verifier(s) remain installed on remote hosts; remove them manually.\n');
      return 0;
    }
    default: throw new UsageError('Unknown user action: '+(action??'(none)'));
  }
}

function isMainModule():boolean{
  // Resolves the npm bin symlink (farcmd-admin -> dist/cli/admin.js) before comparing.
  try{return !!process.argv[1]&&realpathSync(process.argv[1])===realpathSync(fileURLToPath(import.meta.url));}catch{return false;}
}
if(isMainModule()){
  main(process.argv.slice(2)).then(code=>{process.exitCode=code;},error=>{
    if(error instanceof UserAdminError){process.stderr.write('farcmd-admin: '+error.message+'\n');process.exitCode=1;}
    else if(error instanceof UsageError||String((error as any)?.code).startsWith('ERR_PARSE_ARGS')){process.stderr.write('farcmd-admin: '+(error as Error).message+'\n\n'+USAGE+'\n');process.exitCode=2;}
    else{process.stderr.write('farcmd-admin: '+((error as Error)?.stack??String(error))+'\n');process.exitCode=1;}
  });
}
