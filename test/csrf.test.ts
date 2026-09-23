import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import formbody from '@fastify/formbody';
import { SqliteAuthStore, SqliteUserStore } from '../src/storage/sqlite.js';
import { UserAdmin } from '../src/user-admin.js';
import { mountWebApi } from '../src/web-api.js';

process.env.FARCMD_ENCRYPTION_KEY??=randomBytes(32).toString('base64');
const PASSWORD='correct horse battery staple';

test('state-changing API calls need the farcmd header, same-origin fetch metadata and the public origin',async()=>{
  const dir=mkdtempSync(join(tmpdir(),'farcmd-csrf-'));
  try{
    const store=new SqliteAuthStore(join(dir,'app.sqlite')); const users=new SqliteUserStore(store.getDatabase());
    const app=Fastify(); await app.register(formbody); await app.register(cookie); await mountWebApi(app,users,store);
    await new UserAdmin(store.getDatabase()).create({email:'c@example.test',name:'C',password:PASSWORD});
    const ok={'x-farcmd-request':'1'};
    const login=await app.inject({method:'POST',url:'/api/auth/login',headers:ok,payload:{email:'c@example.test',password:PASSWORD}});
    assert.equal(login.statusCode,200);
    const cookieHeader='farcmd_session='+login.cookies.find(c=>c.name==='farcmd_session')!.value;
    const put=(headers:Record<string,string>)=>app.inject({method:'PUT',url:'/api/mcp-access',headers:{cookie:cookieHeader,...headers},payload:{enabled:false}});
    // A classic cross-site form post or fetch without the header: refused before the handler runs.
    const noHeader=await put({}); assert.equal(noHeader.statusCode,403); assert.match(noHeader.json().error,/x-farcmd-request/);
    assert.equal((await put({'x-farcmd-request':'yes'})).statusCode,403);
    assert.equal((await put({...ok,'sec-fetch-site':'cross-site'})).statusCode,403);
    assert.equal((await put({...ok,'sec-fetch-site':'same-site'})).statusCode,403,'sibling subdomains are refused too');
    assert.equal((await put({...ok,origin:'https://evil.example'})).statusCode,403);
    assert.equal((await app.inject({method:'POST',url:'/api/auth/login',payload:{email:'c@example.test',password:PASSWORD}})).statusCode,403,'login CSRF is covered');
    assert.equal((await app.inject({method:'GET',url:'/api/mcp-access',headers:{cookie:cookieHeader}})).json().userEnabled,true,'nothing changed');
    // What the web UI sends.
    assert.equal((await put({...ok,'sec-fetch-site':'same-origin',origin:'http://localhost:5999'})).statusCode,200);
    assert.equal((await put(ok)).statusCode,200,'non-browser clients without fetch metadata or Origin');
    assert.equal((await app.inject({method:'GET',url:'/api/mcp-access',headers:{cookie:cookieHeader}})).statusCode,200,'reads need no header');
  }finally{rmSync(dir,{recursive:true,force:true});}
});
