/**
 * Browser smoke test of the built web UI (run `npm run build` first): sign in, open every page without
 * script errors, use the MCP access switch, sign out. Uses Playwright's Chromium; set
 * FARCMD_CHROMIUM to use a different browser binary.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import formbody from '@fastify/formbody';
import fastifyStatic from '@fastify/static';
import { chromium } from 'playwright';
import { SqliteAuthStore, SqliteUserStore } from '../src/storage/sqlite.js';
import { UserAdmin } from '../src/user-admin.js';
import { mountWebApi } from '../src/web-api.js';
import { McpAccessPolicy } from '../src/mcp-access.js';

process.env.FARCMD_ENCRYPTION_KEY??=randomBytes(32).toString('base64');
const WEB_ROOT=fileURLToPath(new URL('../dist/web/',import.meta.url));
const PASSWORD='correct horse battery staple';

test('web UI: sign in, visit every page, toggle MCP access, sign out',{skip:!existsSync(join(WEB_ROOT,'index.html'))&&'dist/web missing: run npm run build'},async()=>{
  const dir=mkdtempSync(join(tmpdir(),'farcmd-ui-'));
  const store=new SqliteAuthStore(join(dir,'app.sqlite')); const db=store.getDatabase();
  const app=Fastify(); await app.register(formbody); await app.register(cookie); await mountWebApi(app,new SqliteUserStore(db),store);
  await app.register(fastifyStatic,{root:WEB_ROOT,prefix:'/'});
  const address=await app.listen({host:'127.0.0.1',port:0});
  const savedUrl=process.env.MCP_PUBLIC_URL; process.env.MCP_PUBLIC_URL=address; // the API's allowed Origin
  const user=await new UserAdmin(db).create({email:'ui@example.test',name:'UI',password:PASSWORD});
  const browser=await chromium.launch(process.env.FARCMD_CHROMIUM?{executablePath:process.env.FARCMD_CHROMIUM}:{});
  try{
    const page=await browser.newPage(); const problems:string[]=[];
    page.on('pageerror',e=>problems.push('pageerror: '+e.message));
    page.on('console',m=>{if(m.type()==='error')problems.push('console: '+m.text());});
    page.on('dialog',d=>d.accept());
    await page.goto(address+'/');
    await page.getByText('New accounts are created by the administrator.').waitFor();
    await page.fill('input[name=email]','ui@example.test'); await page.fill('input[name=password]','wrong password!!');
    await page.click('#login button'); await page.getByText('Invalid email or password').waitFor();
    await page.fill('input[name=password]',PASSWORD); await page.click('#login button');
    await page.getByRole('heading',{name:'Dashboard'}).waitFor();
    // MCP access switch: off, then on again, through the real UI and API (CSRF header included).
    if(process.env.FARCMD_UI_SCREENSHOTS)await page.screenshot({path:join(process.env.FARCMD_UI_SCREENSHOTS,'dashboard-mcp-on.png'),fullPage:true});
    await page.getByRole('button',{name:'Turn off MCP access'}).click();
    await page.getByRole('button',{name:'Turn on MCP access'}).waitFor();
    if(process.env.FARCMD_UI_SCREENSHOTS)await page.screenshot({path:join(process.env.FARCMD_UI_SCREENSHOTS,'dashboard-mcp-off.png'),fullPage:true});
    assert.equal(new McpAccessPolicy(db).status(user.id).userEnabled,false);
    await page.getByRole('button',{name:'Turn on MCP access'}).click();
    await page.getByRole('button',{name:'Turn off MCP access'}).waitFor();
    assert.equal(new McpAccessPolicy(db).status(user.id).effective,true);
    // SSH and Commands: lists with row actions; adding and editing happen in dialogs.
    await page.getByRole('link',{name:'SSH',exact:true}).click();
    await page.getByRole('button',{name:'Generate key'}).click();
    const dialog=page.locator('dialog.modal');
    await dialog.getByLabel('Name',{exact:true}).fill('ops-master'); await dialog.getByRole('button',{name:'Generate'}).click();
    await page.locator('.row',{hasText:'ops-master'}).waitFor(); await dialog.waitFor({state:'detached'}); // closes after saving
    await page.getByRole('button',{name:'Add target'}).click();
    await dialog.getByLabel('Name',{exact:true}).fill('web-01'); await dialog.getByLabel('Hostname',{exact:true}).fill('web-01.internal'); await dialog.getByLabel('Username',{exact:true}).fill('deploy');
    await dialog.getByRole('button',{name:'Add target'}).click();
    await page.locator('.row',{hasText:'deploy@web-01.internal:22'}).waitFor();
    await page.locator('.row',{hasText:'web-01'}).getByRole('button',{name:'Edit'}).click();
    await dialog.getByLabel('Port',{exact:true}).fill('2222'); await dialog.getByRole('button',{name:'Save'}).click();
    await page.locator('.row',{hasText:'deploy@web-01.internal:2222'}).waitFor();
    await page.getByRole('link',{name:'Commands',exact:true}).click();
    await page.getByRole('button',{name:'New command'}).click();
    await dialog.getByLabel('Name',{exact:true}).fill('Disk usage'); await dialog.getByLabel('Content',{exact:true}).fill('df -h');
    await dialog.getByRole('button',{name:'Create command'}).click();
    await page.locator('.row',{hasText:'Disk usage'}).waitFor();
    await page.getByRole('button',{name:'New command'}).click(); await dialog.getByRole('button',{name:'Create command'}).click();
    assert.equal(await dialog.count(),1,'an invalid form keeps the dialog open'); await dialog.getByRole('button',{name:'Cancel'}).click();
    await page.locator('.row',{hasText:'Disk usage'}).getByRole('button',{name:'Edit'}).click();
    await dialog.locator('select[name=level]').selectOption('2'); await dialog.getByRole('button',{name:'Save'}).click();
    await page.locator('.row',{hasText:'Disk usage'}).getByText('Level 2 · Low-impact').waitFor();
    assert.equal(await page.locator('.row',{hasText:'Disk usage'}).getByRole('button',{name:'Run'}).isDisabled(),true,'Run needs an installed capability');
    await page.locator('.row',{hasText:'Disk usage'}).getByRole('button',{name:'Edit'}).click();
    await dialog.getByLabel('Show output after approval (levels 4–5)').check(); await dialog.getByRole('button',{name:'Save'}).click();
    await dialog.waitFor({state:'detached'});
    if(process.env.FARCMD_UI_SCREENSHOTS)await page.screenshot({path:join(process.env.FARCMD_UI_SCREENSHOTS,'commands.png'),fullPage:true});
    for(const [link,heading] of [['SSH',/SSH/],['Commands',/Commands/],['OAuth Sources',/OAuth Sources/],['History',/History/],['Audit',/Audit log/],['Settings',/Settings|Account/],['Dashboard',/Dashboard/]] as const){
      await page.getByRole('link',{name:link,exact:true}).click();
      await page.getByRole('heading',{name:heading}).first().waitFor();
    }
    await page.getByRole('button',{name:'Log out'}).click();
    await page.getByRole('heading',{name:'Sign in'}).waitFor();
    assert.deepEqual(problems.filter(p=>!/401|Authentication required/.test(p)),[],'no script errors');
    const events=(db.prepare("SELECT event||':'||outcome AS e FROM security_events WHERE actor='web' ORDER BY seq").all() as any[]).map(r=>r.e);
    assert.deepEqual(events.filter(e=>/^(auth|mcp_access)\./.test(e)),['auth.login:failure','auth.login:success','mcp_access.update:success','mcp_access.update:success','auth.logout:success']);
  }finally{
    await browser.close(); await app.close();
    if(savedUrl===undefined)delete process.env.MCP_PUBLIC_URL; else process.env.MCP_PUBLIC_URL=savedUrl;
    rmSync(dir,{recursive:true,force:true});
  }
});
