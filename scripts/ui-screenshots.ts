/**
 * Screenshots of every page of the built web UI with realistic example data, for docs and design review.
 *
 *   npm run build && npm run screenshots [-- <output dir>]     (default: screenshots/)
 *
 * Runs the web API on a throwaway SQLite database. State that needs a real SSH host (installed
 * capabilities, an active verifier), an OAuth grant, history and audit entries is written directly
 * into that database. Uses Playwright's Chromium; set FARCMD_CHROMIUM to use a different binary.
 */
import { mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:net';
import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import formbody from '@fastify/formbody';
import fastifyStatic from '@fastify/static';
import { chromium } from 'playwright';
import { SqliteAuthStore, SqliteUserStore } from '../src/storage/sqlite.js';
import { UserAdmin } from '../src/user-admin.js';
import { mountWebApi } from '../src/web-api.js';
import { SqliteExecutionHistoryStore } from '../src/execution-history.js';
import { AuditLog } from '../src/audit.js';

process.env.FARCMD_ENCRYPTION_KEY??=randomBytes(32).toString('base64');
const WEB_ROOT=fileURLToPath(new URL('../dist/web/',import.meta.url));
const OUT=process.argv[2]??'screenshots'; mkdirSync(OUT,{recursive:true});
const dir=mkdtempSync(join(tmpdir(),'farcmd-shots-'));
const store=new SqliteAuthStore(join(dir,'app.sqlite')); const db=store.getDatabase();
// The API's allowed Origin must be known when it is mounted, so reserve the port first.
const port=await new Promise<number>(resolve=>{const s=createServer();s.listen(0,'127.0.0.1',()=>{const p=(s.address() as any).port;s.close(()=>resolve(p));});});
const address='http://127.0.0.1:'+port;
const app=Fastify(); await app.register(formbody); await app.register(cookie); await mountWebApi(app,new SqliteUserStore(db),store,address);
await app.register(fastifyStatic,{root:WEB_ROOT,prefix:'/'});
await app.listen({host:'127.0.0.1',port});
const PASSWORD='correct horse battery staple';
const user=await new UserAdmin(db).create({email:'ops@example.org',name:'Ops',password:PASSWORD});
const uid=user.id;

const browser=await chromium.launch(process.env.FARCMD_CHROMIUM?{executablePath:process.env.FARCMD_CHROMIUM}:{});
const page=await browser.newPage({viewport:{width:1100,height:760},deviceScaleFactor:2});
page.on('dialog',d=>d.accept());
const api=(path:string,method='GET',body?:unknown)=>page.evaluate(async([p,m,b])=>{const r=await fetch(p,{method:m,headers:{'content-type':'application/json','x-farcmd-request':'1'},...(b!==undefined?{body:JSON.stringify(b)}:{})});return r.json();},[path,method,body] as const);
const shot=async(name:string,full=true)=>{await page.waitForTimeout(250);await page.screenshot({path:join(OUT,name+'.png'),fullPage:full});};
const nav=async(link:string)=>{await page.locator('nav').getByRole('link',{name:link,exact:true}).click();await page.waitForTimeout(400);};

await page.goto(address+'/'); await page.waitForSelector('#login');
await shot('login',false);
await page.fill('input[name=email]','ops@example.org'); await page.fill('input[name=password]',PASSWORD); await page.click('#login button');
await page.getByRole('heading',{name:'Commands'}).waitFor();
await shot('commands-empty',false);

// Seed through the API: a master key, two targets, commands.
const key=(await api('/api/ssh/keys/generate','POST',{name:'ops-master'})).key;
const web=(await api('/api/ssh/targets','POST',{name:'web-01',hostname:'web-01.example.org',port:22,username:'farcmd',sshKeyId:key.id})).target;
const db1=(await api('/api/ssh/targets','POST',{name:'db-01',hostname:'db-01.example.org',port:22,username:'farcmd',sshKeyId:key.id})).target;
await api('/api/ssh/targets/'+web.id,'PATCH',{hostFingerprint:'sha256:Qm9vdHN0cmFwcGVkLWZpbmdlcnByaW50LWV4YW1wbGU'});
const mk=async(name:string,description:string,targetId:string,level:number,content:string,type='shell')=>(await api('/api/commands','POST',{name,description,targetId,level,content,type,showOutputOnApproval:false})).command;
const disk=await mk('Disk usage','Free space on all mounted filesystems.',web.id,1,'df -h');
const restart=await mk('Restart web service','Restarts nginx and checks that it came back.',web.id,3,'sudo systemctl restart nginx\nsystemctl is-active nginx','bash_script');
const deploy=await mk('Deploy release','Pulls and activates the latest tagged release.',web.id,4,'/opt/app/bin/deploy --latest');
await mk('Drop cache tables','Truncates the application cache tables.',db1.id,5,'psql -c "TRUNCATE cache_entries"');
await mk('Tail error log','Last 100 lines of the nginx error log.',web.id,1,'tail -n 100 /var/log/nginx/error.log');

// Seed state the UI can't reach without a real SSH host: installed capabilities, an active verifier, a grant, history.
const now=Date.now();
const install=(c:any)=>db.prepare('INSERT INTO command_installations (id,user_id,command_id,target_id,master_key_id,encrypted_private_key,public_key,fingerprint,remote_script_path,authorized_key_line,installed_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)')
  .run(randomUUID(),uid,c.id,c.targetId,key.id,'x','ssh-ed25519 AAAA','SHA256:cap','~/.ssh/farcmd/x-'+c.id+'.sh','restrict,command="x" ssh-ed25519 AAAA',now,now,now);
[disk,restart,deploy].forEach(install);
db.prepare('INSERT INTO verification_authorities (id,user_id,target_id,username,privilege,encrypted_private_key,public_key,fingerprint,encrypted_secret,authorized_key_line,authorized_key_sha256,status,installed_at,last_verified_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
  .run(randomUUID(),uid,web.id,'farcmd','sudo','x','ssh-ed25519 AAAA','SHA256:verifier','x','x','x','active',now,now,now,now);
store.upsertOAuthGrant(uid,'https://claude.ai/oauth/mcp-oauth-client-metadata','Claude',[1,2,3,4],true);
store.touchOAuthGrant(uid,'https://claude.ai/oauth/mcp-oauth-client-metadata');
const hist=new SqliteExecutionHistoryStore(db);
const run=(c:any,minsAgo:number,status:any,stdout:string,exitCode:number|null,client='https://claude.ai/oauth/mcp-oauth-client-metadata')=>{const t=now-minsAgo*60_000;hist.create({id:randomUUID(),userId:uid,clientId:client,commandId:c.id,commandName:c.name,targetId:c.targetId,level:c.level,startedAt:t,endedAt:t+840,durationMs:840,exitCode,stdout,stderr:'',status});};
run(disk,3,'success','Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        40G   22G   16G  58% /',0);
run(restart,12,'success','active',0);
run(deploy,55,'success','Deployed v2.4.1',0,'web');
run(restart,90,'blocked','',null);
run(disk,140,'success','/dev/sda1 40G 21G 17G 55% /',0);
const audit=new AuditLog(db);
audit.record({event:'command.execute',actor:'mcp',userId:uid,clientId:'https://claude.ai/oauth/mcp-oauth-client-metadata',targetType:'command',targetId:disk.id,details:{level:1,exitCode:0}});
audit.record({event:'verification.passed',actor:'mcp',userId:uid,targetType:'ssh_target',targetId:web.id,details:{level:3}});

// Commands page, the setup checklist and dialogs.
await nav('SSH'); await nav('Commands'); await page.locator('.row').first().waitFor();
await shot('commands');
await page.locator('.row',{hasText:'Disk usage'}).getByRole('button',{name:'Edit'}).click(); await page.locator('dialog.modal').waitFor();
await shot('edit-locked',false); await page.locator('dialog.modal').getByRole('button',{name:'Cancel'}).click();
await page.getByRole('button',{name:'New command'}).click(); await page.locator('dialog.modal').waitFor();
await shot('new-command',false); await page.locator('dialog.modal').getByRole('button',{name:'Cancel'}).click();
await nav('SSH'); await page.locator('details.checklist').waitFor();
await shot('ssh');
await page.locator('.row',{hasText:'db-01'}).getByRole('button',{name:'Verifier'}).click(); await page.waitForTimeout(400);
await shot('verifier-choice',false);
const auto=page.getByRole('button',{name:/automatic/i}); if(await auto.count()){await auto.first().click();await page.waitForTimeout(400);await shot('verifier-install');}
await nav('OAuth Sources'); await shot('oauth');
await nav('History'); await shot('history');
await nav('Audit'); await shot('audit');
await nav('Settings'); await shot('settings');
// Phone width.
await page.setViewportSize({width:390,height:844}); await nav('Commands'); await page.locator('.row').first().waitFor(); await shot('commands-mobile');
await browser.close(); await app.close(); rmSync(dir,{recursive:true,force:true});
console.log('Screenshots written to '+OUT);
