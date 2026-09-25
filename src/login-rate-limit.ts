import { hash, verify } from '@node-rs/argon2';

/**
 * Password sign-in protection shared by the web login (/api/auth/login) and the OAuth sign-in form
 * (/oauth/authorize), so the two paths share one budget per client IP: at most 8 attempts in 15 minutes.
 */
const MAX_ATTEMPTS=8;
const WINDOW_MS=15*60_000;
const MAX_TRACKED=10_000;
const attempts=new Map<string,{count:number;reset:number}>();

/** Counts one attempt for this key; false once the key is over its limit. Expired entries are swept so the map stays bounded. */
export function rateLimit(key:string,max=MAX_ATTEMPTS,windowMs=WINDOW_MS,map=attempts):boolean{
  const now=Date.now(); const current=map.get(key);
  if(!current||current.reset<=now){
    if(map.size>=MAX_TRACKED)for(const [k,v] of map)if(v.reset<=now)map.delete(k);
    map.set(key,{count:1,reset:now+windowMs}); return true;
  }
  current.count++;
  return current.count<=max;
}
/** Budget key for password sign-ins from one IP, across the web and OAuth sign-in forms. */
export function loginRateLimit(ip:string):boolean{ return rateLimit('login:'+ip); }

let dummyHash:Promise<string>|undefined;
/**
 * Verifies a password against a stored Argon2id hash. For an unknown account it still runs one
 * verification against a dummy hash, so response time does not reveal whether the email exists.
 */
export async function verifyPassword(passwordHash:string|undefined,password:string):Promise<boolean>{
  if(passwordHash)return verify(passwordHash,password);
  dummyHash??=hash('farcmd-dummy-password',{algorithm:2});
  await verify(await dummyHash,password).catch(()=>false);
  return false;
}
