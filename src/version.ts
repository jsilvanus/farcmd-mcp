import { readFileSync } from 'node:fs';

/** farcmd-mcp version, read from package.json (next to src/ in development and dist/ in the image). */
export const VERSION:string=JSON.parse(readFileSync(new URL('../package.json',import.meta.url),'utf8')).version;
