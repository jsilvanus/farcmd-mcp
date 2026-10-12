/**
 * farcmd can be served under a sub-path of a shared host, e.g. MCP_PUBLIC_URL=https://example.org/farcmd-mcp.
 * The routes stay mounted at the root; `rewriteUrlFor` strips the prefix from incoming URLs instead, so the
 * container still answers unprefixed requests (its own /health check, a proxy that strips the prefix).
 */

/** Discovery documents that RFC 8414 / RFC 9728 locate at the host root, with the issuer or resource path appended. */
const WELL_KNOWN=['oauth-authorization-server','oauth-protected-resource','openid-configuration'];

/** The path of a public URL without the trailing slash: '' at the root, '/farcmd-mcp' under a sub-path. */
export function basePathOf(publicUrl:string):string{return new URL(publicUrl).pathname.replace(/\/+$/,'');}

/** The normalized public URL: origin plus base path, never a trailing slash. Everything else appends '/…' to it. */
export function normalizePublicUrl(publicUrl:string):string{const url=new URL(publicUrl);return url.origin+basePathOf(publicUrl);}

/** Base path of the configured MCP_PUBLIC_URL ('' when unset or at the root). */
export function basePath(env:NodeJS.ProcessEnv=process.env):string{try{return basePathOf(env.MCP_PUBLIC_URL??'');}catch{return '';}}

/** Path for cookies scoped to this app, so they are not sent to other apps on a shared host. */
export function cookiePath(suffix='',env:NodeJS.ProcessEnv=process.env):string{return (basePath(env)+suffix)||'/';}

/** RFC 8414 / RFC 9728 path-inserted discovery URL: <origin>/.well-known/<name><base path><suffix>. */
export function wellKnownUrl(publicUrl:string,name:string,suffix=''):string{return new URL(publicUrl).origin+'/.well-known/'+name+basePathOf(publicUrl)+suffix;}

/** Fastify `rewriteUrl`: maps public, prefixed URLs to the routes mounted at the root. */
export function rewriteUrlFor(base:string):(url:string)=>string{
  if(!base)return url=>url;
  const prefixes=WELL_KNOWN.map(name=>({from:'/.well-known/'+name+base,to:'/.well-known/'+name}));
  const rest=(url:string,prefix:string):string|undefined=>{
    if(url===prefix)return '';
    const next=url.charAt(prefix.length);
    return url.startsWith(prefix)&&(next==='/'||next==='?')?url.slice(prefix.length):undefined;
  };
  return url=>{
    const own=rest(url,base);
    if(own!==undefined)return own===''||own.startsWith('?')?'/'+own:own;
    for(const {from,to} of prefixes){const tail=rest(url,from);if(tail!==undefined)return to+tail;}
    return url;
  };
}
