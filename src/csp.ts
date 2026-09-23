/** Production Content-Security-Policy. `formAction` extends `form-action 'self'`: browsers apply it to the redirects a form submission follows too. */
export function contentSecurityPolicy(formAction:string[]=[]):string{return "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action "+["'self'",...formAction].join(' ');}
/** CSP source for a redirect URI: its origin, or its scheme for custom schemes (e.g. `cursor:`), whose origin is opaque. */
export function redirectSource(uri:string):string{const url=new URL(uri);return url.origin==='null'?url.protocol:url.origin;}
