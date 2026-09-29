/**
 * Browser test of reviewing MCP command suggestions in the built web UI (run `npm run build` first): the
 * review link opens the prefilled create form after sign-in, creating needs the review checkbox, and a
 * suggestion can be dismissed. Uses Playwright's Chromium; set FARCMD_CHROMIUM to use a different binary.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
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
import { SqliteCommandSuggestionStore, type CommandSuggestionRecord } from '../src/storage/command-suggestions.js';
import { SqliteOAuthGrantStore } from '../src/oauth/grants.js';

process.env.FARCMD_ENCRYPTION_KEY??=randomBytes(32).toString('base64');
const WEB_ROOT=fileURLToPath(new URL('../dist/web/',import.meta.url));
const PASSWORD='correct horse battery staple';

test('web UI: review a suggested command from its link, create it, dismiss another, allow suggestions per OAuth source',{skip:!existsSync(join(WEB_ROOT,'index.html'))&&'dist/web missing: run npm run build'},async()=>{
  const dir=mkdtempSync(join(tmpdir(),'farcmd-ui-suggestions-'));
  const store=new SqliteAuthStore(join(dir,'app.sqlite')); const db=store.getDatabase();
  const port=await new Promise<number>(resolve=>{const s=createServer();s.listen(0,'127.0.0.1',()=>{const p=(s.address() as any).port;s.close(()=>resolve(p));});});
  const address='http://127.0.0.1:'+port;
  const app=Fastify(); await app.register(formbody); await app.register(cookie); await mountWebApi(app,new SqliteUserStore(db),store,address);
  await app.register(fastifyStatic,{root:WEB_ROOT,prefix:'/'});
  await app.listen({host:'127.0.0.1',port});
  const user=await new UserAdmin(db).create({email:'ui@example.test',name:'UI',password:PASSWORD});
  const now=Date.now(), keyId=randomUUID();
  db.prepare('INSERT INTO ssh_keys (id,user_id,name,encrypted_private_key,created_at,updated_at) VALUES (?,?,?,?,?,?)').run(keyId,user.id,'key','1.x.x',now,now);
  for(const name of ['dev','prod'])db.prepare('INSERT INTO ssh_targets (id,user_id,name,hostname,port,username,ssh_key_id,host_fingerprint,enabled,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)').run(randomUUID(),user.id,name,name+'.internal',22,'deploy',keyId,'sha256:abc',1,now,now);
  const prodId=(db.prepare("SELECT id FROM ssh_targets WHERE name='prod'").get() as any).id;
  const suggestions=new SqliteCommandSuggestionStore(db);
  const suggestion=(name:string,content:string):CommandSuggestionRecord=>({id:randomUUID(),userId:user.id,clientId:'https://claude.ai',clientName:'Claude',name,description:'Suggested in chat',type:'shell',content,level:3,targetHint:'the dev server',rationale:'Needed for redeploys',status:'pending',createdAt:now});
  const redeploy=suggestion('saarnavideo: redeploy','/opt/server-commands/saarnavideo-redeploy.sh'); const wipe=suggestion('wipe everything','rm -rf /srv');
  suggestions.create(redeploy); suggestions.create(wipe);
  const grants=new SqliteOAuthGrantStore(db); grants.upsert(user.id,'https://claude.ai','Claude',[1,2,3],false);
  const browser=await chromium.launch(process.env.FARCMD_CHROMIUM?{executablePath:process.env.FARCMD_CHROMIUM}:{});
  try{
    const context=await browser.newContext(); await context.grantPermissions(['clipboard-read','clipboard-write'],{origin:address});
    const page=await context.newPage(); const problems:string[]=[];
    page.on('pageerror',e=>problems.push('pageerror: '+e.message));
    page.on('console',m=>{if(m.type()==='error')problems.push('console: '+m.text());});
    page.on('dialog',d=>d.accept());
    // The reviewUrl that suggest_command returned; signing in continues to the review dialog.
    await page.goto(address+'/?page=suggestion&id='+redeploy.id);
    await page.fill('input[name=email]','ui@example.test'); await page.fill('input[name=password]',PASSWORD); await page.click('#login button');
    const dialog=page.locator('dialog.modal');
    await dialog.getByRole('heading',{name:'Review suggested command'}).waitFor();
    await dialog.getByText('Written by an MCP client (Claude).').waitFor();
    await dialog.getByText('Meant for: the dev server').waitFor();
    assert.equal(await dialog.locator('textarea[name=content]').inputValue(),redeploy.content,'prefilled with the exact content');
    assert.equal(await dialog.locator('select[name=level]').inputValue(),'3');
    await page.locator('.row',{hasText:'wipe everything'}).waitFor(); // both are listed behind the dialog
    if(process.env.FARCMD_UI_SCREENSHOTS)await page.screenshot({path:join(process.env.FARCMD_UI_SCREENSHOTS,'suggestion-review.png'),fullPage:true});
    // Copy for review: the suggestion with a security-review prompt, to paste into another agent.
    await dialog.getByRole('button',{name:'Copy for review'}).click();
    await dialog.getByRole('button',{name:'Copied'}).waitFor();
    const copied=await page.evaluate(()=>navigator.clipboard.readText());
    for(const part of ['Name: saarnavideo: redeploy',redeploy.content,'Suggested by MCP client: Claude','untrusted data','DO NOT INSTALL'])assert.ok(copied.includes(part),part);
    // The person chooses target and level; the review checkbox is required.
    await dialog.locator('select[name=targetId]').selectOption(prodId); await dialog.locator('select[name=level]').selectOption('4');
    await dialog.getByRole('button',{name:'Create command'}).click();
    assert.equal(await dialog.count(),1,'not created without confirming the review');
    await dialog.getByLabel('I have reviewed the content and chosen the target and level.').check();
    await dialog.getByRole('button',{name:'Create command'}).click();
    await dialog.waitFor({state:'detached'});
    const created=page.locator('.row',{hasText:'saarnavideo: redeploy'});
    await created.getByText('Level 4 · High-impact').waitFor(); await created.getByText('No capability').waitFor();
    assert.equal(await created.getByRole('button',{name:'Run'}).isDisabled(),true,'still needs Install');
    assert.equal(new URL(page.url()).search,'','the review link is not reopened on reload');
    const command=db.prepare('SELECT id,target_id,level,content FROM commands').get() as any;
    assert.equal(command.target_id,prodId); assert.equal(command.level,4); assert.equal(command.content,redeploy.content);
    assert.equal(suggestions.get(user.id,redeploy.id)?.status,'accepted'); assert.equal(suggestions.get(user.id,redeploy.id)?.commandId,command.id);
    // Without a usable clipboard (e.g. plain HTTP) the text is shown to copy by hand.
    await page.evaluate(()=>{navigator.clipboard.writeText=()=>Promise.reject(new Error('denied'));});
    await page.locator('.row',{hasText:'wipe everything'}).getByRole('button',{name:'Copy for review'}).click();
    assert.match(await dialog.locator('textarea.review-copy').inputValue(),/rm -rf \/srv[\s\S]*DO NOT INSTALL|DO NOT INSTALL[\s\S]*rm -rf \/srv/);
    await dialog.getByRole('button',{name:'Close'}).click(); await dialog.waitFor({state:'detached'});
    // Dismiss the other one from the list.
    await page.locator('.row',{hasText:'wipe everything'}).getByRole('button',{name:'Dismiss'}).click();
    await page.getByRole('heading',{name:/Suggested by MCP clients/}).waitFor({state:'detached'});
    assert.equal(suggestions.get(user.id,wipe.id)?.status,'dismissed');
    assert.equal((db.prepare('SELECT COUNT(*) AS n FROM commands').get() as any).n,1);
    // OAuth Sources: suggestions are allowed per client with a checkbox (off by default).
    await page.getByRole('link',{name:'OAuth Sources',exact:true}).click();
    const source=page.locator('.grant',{hasText:'Claude'});
    assert.equal(await source.getByLabel(/Allow suggestions/).isChecked(),false,'off by default');
    await source.getByLabel(/Allow suggestions/).check(); await source.getByRole('button',{name:'Save'}).click();
    await page.locator('.grant',{hasText:'Claude'}).getByText('Suggestions allowed').waitFor();
    assert.equal(grants.get(user.id,'https://claude.ai')?.allowSuggestions,true);
    assert.deepEqual(grants.get(user.id,'https://claude.ai')?.visibleLevels,[1,2,3],'levels unchanged');
    if(process.env.FARCMD_UI_SCREENSHOTS)await page.screenshot({path:join(process.env.FARCMD_UI_SCREENSHOTS,'oauth-suggestions.png'),fullPage:true});
    // An already reviewed link says so instead of opening a form.
    await page.goto(address+'/?page=suggestion&id='+wipe.id);
    await page.getByRole('heading',{name:'Command registry'}).waitFor();
    assert.equal(await dialog.count(),0);
    assert.deepEqual(problems.filter(p=>!/401|Authentication required/.test(p)),[],'no script errors'); // the session check before sign-in answers 401
  }finally{
    await browser.close(); await app.close();
    rmSync(dir,{recursive:true,force:true});
  }
});
