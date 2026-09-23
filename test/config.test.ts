import test from 'node:test';
import assert from 'node:assert/strict';
import Fastify from 'fastify';
import { parseTrustProxy, productionConfigProblems } from '../src/config.js';

test('FARCMD_TRUST_PROXY parsing',()=>{
  for(const off of [undefined,'','false','0'])assert.equal(parseTrustProxy(off),false);
  assert.equal(parseTrustProxy('true'),true);
  assert.deepEqual(parseTrustProxy('127.0.0.1, 172.16.0.0/12,::1'),['127.0.0.1','172.16.0.0/12','::1']);
  const hops=parseTrustProxy('2') as (a:string,h:number)=>boolean;
  assert.equal(typeof hops,'function'); assert.equal(hops('x',0),true); assert.equal(hops('x',1),true); assert.equal(hops('x',2),false);
  assert.throws(()=>parseTrustProxy('proxy.example.org'),/invalid address/);
});

test('client IP honours X-Forwarded-For only from trusted proxies',async()=>{
  const ipFor=async(trust:string|undefined,remoteAddress:string,xff?:string)=>{
    const app=Fastify({trustProxy:parseTrustProxy(trust) as any}); app.get('/ip',async request=>({ip:request.ip}));
    const r=await app.inject({method:'GET',url:'/ip',remoteAddress,...(xff?{headers:{'x-forwarded-for':xff}}:{})});
    await app.close(); return r.json().ip;
  };
  assert.equal(await ipFor(undefined,'127.0.0.1','203.0.113.9'),'127.0.0.1','untrusted by default: header ignored');
  assert.equal(await ipFor('127.0.0.1','127.0.0.1','203.0.113.9'),'203.0.113.9','trusted proxy: client address used');
  assert.equal(await ipFor('127.0.0.1','198.51.100.7','203.0.113.9'),'198.51.100.7','request not from the proxy: header ignored');
  assert.equal(await ipFor('172.16.0.0/12','172.20.0.5','203.0.113.9'),'203.0.113.9','CIDR (Docker proxy network)');
  assert.equal(await ipFor('127.0.0.1','127.0.0.1','6.6.6.6, 203.0.113.9'),'203.0.113.9','a client-supplied value in front is not trusted');
});

test('production refuses unsafe configuration',()=>{
  assert.deepEqual(productionConfigProblems({NODE_ENV:'development'}),[]);
  assert.deepEqual(productionConfigProblems({NODE_ENV:'production',MCP_PUBLIC_URL:'https://farcmd.example.org'}),[]);
  assert.match(productionConfigProblems({NODE_ENV:'production'}).join(),/must be set/);
  assert.match(productionConfigProblems({NODE_ENV:'production',MCP_PUBLIC_URL:'http://farcmd.example.org'}).join(),/https/);
  assert.match(productionConfigProblems({NODE_ENV:'production',MCP_PUBLIC_URL:'https://example.org/farcmd'}).join(),/without a path/);
  assert.match(productionConfigProblems({NODE_ENV:'production',MCP_PUBLIC_URL:'https://farcmd.example.org',MCP_DEFAULT_USER_PASSWORD:'x'}).join(),/farcmd-admin/);
});
