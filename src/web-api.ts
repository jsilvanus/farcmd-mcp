import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { hash, verify } from '@node-rs/argon2';
import { randomToken } from './oauth/pkce.js';
import type { UserStore, WebSessionStore } from './storage/interface.js';
import { WebSessionService } from './web-session.js';

const attempts=new Map<string,{count:number;reset:number}>();
const MAX_ATTEMPTS=8;
const WINDOW=15*60_000;

function rateLimit(key:string): boolean {
  const now=Date.now(); const current=attempts.get(key);
  if (!current || current.reset<=now) { attempts.set(key,{count:1,reset:now+WINDOW}); return true; }
  current.count++;
  return current.count<=MAX_ATTEMPTS;
}
function cleanEmail(email:string): string { return email.trim().toLowerCase(); }
function publicUser(user:{id:string;name:string;email?:string;createdAt:number}) {
  return {id:user.id,name:user.name,email:user.email,createdAt:user.createdAt};
}
function cookieOptions() {
  return {httpOnly:true,secure:process.env.NODE_ENV==='production',sameSite:'lax' as const,path:'/',maxAge:7*24*60*60};
}
function sessionFrom(request:FastifyRequest, sessions:WebSessionService) {
  const token=request.cookies.farcmd_session;
  return token ? sessions.get(token) : undefined;
}
async function requireUser(request:FastifyRequest, reply:FastifyReply, users:UserStore, sessions:WebSessionService) {
  const session=sessionFrom(request,sessions);
  if (!session) { reply.code(401).send({error:'Authentication required'}); return undefined; }
  const user=users.getUser(session.userId);
  if (!user) { sessions.delete(session.token); reply.clearCookie('farcmd_session',{path:'/'}); reply.code(401).send({error:'Authentication required'}); return undefined; }
  return user;
}

export async function mountWebApi(app:FastifyInstance, users:UserStore, sessionStore:WebSessionStore): Promise<void> {
  const sessions=new WebSessionService(sessionStore);
  app.get('/api/auth/session',async (request,reply)=>{
    const user=await requireUser(request,reply,users,sessions); if(!user)return;
    return {user:publicUser(user)};
  });
  app.post('/api/auth/login',async (request,reply)=>{
    const ip=request.ip; if(!rateLimit(ip)) return reply.code(429).send({error:'Too many login attempts. Try again later.'});
    const b=request.body as Record<string,unknown>;
    const email=typeof b.email==='string'?cleanEmail(b.email):'';
    const password=typeof b.password==='string'?b.password:'';
    const user=users.getUserByEmail(email);
    if(!user?.passwordHash || !(await verify(user.passwordHash,password))) return reply.code(401).send({error:'Invalid email or password'});
    const token=sessions.create(user.id);
    reply.setCookie('farcmd_session',token,cookieOptions());
    return {user:publicUser(user)};
  });
  app.post('/api/auth/logout',async (request,reply)=>{
    const token=request.cookies.farcmd_session; if(token)sessions.delete(token);
    reply.clearCookie('farcmd_session',{path:'/'});
    return {ok:true};
  });
  app.post('/api/auth/register',async (request,reply)=>{
    const ip=request.ip; if(!rateLimit('register:'+ip)) return reply.code(429).send({error:'Too many attempts. Try again later.'});
    const b=request.body as Record<string,unknown>;
    const name=typeof b.name==='string'?b.name.trim():'';
    const email=typeof b.email==='string'?cleanEmail(b.email):'';
    const password=typeof b.password==='string'?b.password:'';
    if(name.length<1||name.length>120) return reply.code(400).send({error:'Invalid name'});
    if(!/^\\S+@\\S+\\.\\S+$/.test(email)||email.length>320) return reply.code(400).send({error:'Invalid email'});
    if(password.length<12||password.length>1024) return reply.code(400).send({error:'Password must be 12-1024 characters'});
    if(users.getUserByEmail(email)) return reply.code(409).send({error:'An account with that email already exists'});
    const user={id:crypto.randomUUID(),name,email,passwordHash:await hash(password,{algorithm:2}),createdAt:Date.now()};
    users.createUser(user);
    const token=sessions.create(user.id); reply.setCookie('farcmd_session',token,cookieOptions());
    return reply.code(201).send({user:publicUser(user)});
  });
  app.patch('/api/account',async (request,reply)=>{
    const user=await requireUser(request,reply,users,sessions); if(!user)return;
    const b=request.body as Record<string,unknown>;
    const name=typeof b.name==='string'?b.name.trim():user.name;
    const email=typeof b.email==='string'?cleanEmail(b.email):(user.email??'');
    if(name.length<1||name.length>120||!/^\\S+@\\S+\\.\\S+$/.test(email)) return reply.code(400).send({error:'Invalid account data'});
    const other=users.getUserByEmail(email);
    if(other&&other.id!==user.id) return reply.code(409).send({error:'That email is already in use'});
    users.updateUser(user.id,name,email);
    return {user:publicUser(users.getUser(user.id)!)};
  });
}
