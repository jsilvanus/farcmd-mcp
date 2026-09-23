import type { FastifyInstance, InjectOptions } from 'fastify';
import { CSRF_HEADER } from '../src/web-api.js';

/**
 * Make app.inject() send what the web UI sends on every API call (the CSRF header), so tests exercise
 * the API as the browser client uses it. test/csrf.test.ts covers requests without it.
 */
export function asWebClient<T extends FastifyInstance>(app:T):T{
  const inject=app.inject.bind(app) as (opts:InjectOptions|string)=>any;
  (app as any).inject=(opts:InjectOptions|string)=>{
    const o:InjectOptions=typeof opts==='string'?{url:opts}:opts;
    return inject({...o,headers:{[CSRF_HEADER]:'1',...(o.headers??{})}});
  };
  return app;
}
