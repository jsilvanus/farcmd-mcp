/** Deployment configuration helpers (validated at startup). */

export const DAY_MS=86_400_000;

/** A non-negative integer from the environment, or fallback when unset or empty. */
export function envInt(name:string,fallback:number):number{
  const raw=process.env[name]; if(raw===undefined||raw==='')return fallback;
  const n=Number(raw); if(!Number.isInteger(n)||n<0)throw new Error(name+' must be a non-negative integer');
  return n;
}
/** A retention period in days from the environment (0 = keep forever), in milliseconds. */
export function envRetentionMs(name:string,defaultDays=365):number{
  const days=Number(process.env[name]??String(defaultDays));
  if(!Number.isFinite(days)||days<0)throw new Error(name+' must be a non-negative number');
  return days*DAY_MS;
}

/**
 * FARCMD_TRUST_PROXY controls which reverse proxies may set X-Forwarded-For/-Proto:
 *   unset / "false"   trust nobody (direct exposure; request.ip is the TCP peer)
 *   "true"            trust any proxy (only if the app port is unreachable except through the proxy)
 *   "<n>"             trust the last n hops
 *   "<ip|cidr>,..."   trust these proxy addresses (e.g. "127.0.0.1,172.16.0.0/12" for Docker/Traefik)
 * The result is passed to Fastify's trustProxy option, which determines request.ip used for rate
 * limiting and the audit log.
 */
export type TrustProxy=boolean|string[]|((address:string,hop:number)=>boolean);
export function parseTrustProxy(value:string|undefined):TrustProxy{
  const v=(value??'').trim();
  if(v===''||v==='false'||v==='0')return false;
  if(v==='true')return true;
  if(/^\d+$/.test(v)){const hops=Number(v);return (_address:string,hop:number)=>hop<hops;}
  const list=v.split(',').map(s=>s.trim()).filter(Boolean);
  for(const entry of list)if(!/^[0-9a-fA-F:.]+(\/\d{1,3})?$/.test(entry))throw new Error('FARCMD_TRUST_PROXY: invalid address or CIDR "'+entry+'"');
  return list;
}

/** Refuse obviously unsafe production settings instead of starting half-secure. Returns the problems found. */
export function productionConfigProblems(env:NodeJS.ProcessEnv):string[]{
  if(env.NODE_ENV!=='production')return [];
  const problems:string[]=[];
  let url:URL|undefined;
  try{url=new URL(env.MCP_PUBLIC_URL??'');}catch{problems.push('MCP_PUBLIC_URL must be set to the public https:// URL of this server.');}
  if(url&&url.protocol!=='https:')problems.push('MCP_PUBLIC_URL must use https:// in production (OAuth and secure cookies require TLS; terminate it at the reverse proxy).');
  if(url&&(url.pathname!=='/'||url.search||url.hash))problems.push('MCP_PUBLIC_URL must be an origin without a path (e.g. https://farcmd.example.org).');
  if(env.MCP_DEFAULT_USER_PASSWORD)problems.push('MCP_DEFAULT_USER_PASSWORD is a development bootstrap; create users with farcmd-admin in production.');
  return problems;
}
