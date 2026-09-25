import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { RequestHandlerExtra } from '@modelcontextprotocol/sdk/shared/protocol.js';
import type { ServerNotification, ServerRequest, CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import type { FarcmdConnector, ConnectorContext, PendingConfirmation } from '../connector.js';
import { requestUrlElicitation, supportsUrlElicitation } from './elicitation.js';
import type { CommandLevel } from '../command-registry.js';
import { COMMAND_LEVELS } from '../command-levels.js';
import { VERSION } from '../version.js';

type Extra=RequestHandlerExtra<ServerRequest,ServerNotification>;
const oauthSecuritySchemes=[{type:'oauth2' as const,scopes:['mcp']}];

function contextFromExtra(extra:Extra):ConnectorContext{
  const auth=extra.authInfo; const userId=auth?.extra?.userId;
  if(typeof userId!=='string'||!auth?.token||!auth.clientId)throw new Error('Authentication required.');
  return {userId,accessToken:auth.token,clientId:auth.clientId};
}
/**
 * MCP tool annotations per command level. They are hints for the client (for example whether to ask before a
 * call), not guarantees: farcmd cannot inspect what a script does, so they rest on the level a person assigned.
 * Level 1 is by definition safe/read-only, so it is marked read-only; clients may run it without asking.
 */
export const LEVEL_ANNOTATIONS:Record<CommandLevel,{readOnlyHint:boolean;destructiveHint:boolean;idempotentHint:boolean;openWorldHint:boolean}>={
  1:{readOnlyHint:true,destructiveHint:false,idempotentHint:true,openWorldHint:true},
  2:{readOnlyHint:false,destructiveHint:false,idempotentHint:false,openWorldHint:true},
  3:{readOnlyHint:false,destructiveHint:false,idempotentHint:false,openWorldHint:true},
  4:{readOnlyHint:false,destructiveHint:true,idempotentHint:false,openWorldHint:true},
  5:{readOnlyHint:false,destructiveHint:true,idempotentHint:false,openWorldHint:true},
};
const LOCAL_READ_ONLY={readOnlyHint:true,destructiveHint:false,idempotentHint:true,openWorldHint:false};
function security<T extends object>(config:T):T&{securitySchemes:typeof oauthSecuritySchemes}{return {...config,securitySchemes:oauthSecuritySchemes};}
function result(value:unknown):CallToolResult{return {content:[{type:'text',text:JSON.stringify(value,null,2)}]};}
function errorResult(error:unknown):CallToolResult{return {content:[{type:'text',text:error instanceof Error?error.message:String(error)}],isError:true};}

export interface McpServerOptions{
  connector:FarcmdConnector; publicUrl:string; visibleLevels:CommandLevel[];
  /** Writes a message on the response stream of the given request (see elicitation.ts). */
  sendRelated?:(message:Record<string,unknown>,relatedRequestId:string|number)=>Promise<void>;
  /** Aborts when the HTTP connection of this request closes. */
  connectionSignal?:AbortSignal;
}
const PROGRESS_INTERVAL_MS=15_000;

/**
 * Level 4/5 with a client that supports URL elicitation: show the approval link through the client and
 * keep this call open until the person approves in the browser, then return the result directly.
 * Anything else (no answer, client error, the call ending) falls back to the pending result with its
 * confirmation token, exactly as for clients without elicitation.
 */
async function approveInBrowser(options:McpServerOptions,context:ConnectorContext,pending:PendingConfirmation,extra:Extra):Promise<CallToolResult>{
  const ac=new AbortController(); const abort=()=>ac.abort();
  extra.signal.addEventListener('abort',abort,{once:true}); options.connectionSignal?.addEventListener('abort',abort,{once:true});
  const progressToken=extra._meta?.progressToken; let ticker:ReturnType<typeof setInterval>|undefined;
  try{
    const sent=await requestUrlElicitation({context,approvalUrl:pending.approvalUrl,signal:ac.signal,
      message:'farcmd: a level '+pending.level+' command is waiting for your approval. Open the link to review it'+(pending.confirmation==='password'?' and enter its execution password':'')+'.',
      send:m=>options.sendRelated!(m,extra.requestId)});
    if(!sent)return result(pending);
    // Keeps the stream alive through proxies and tells clients that restart their timeout on progress.
    if(progressToken!==undefined){let n=0;ticker=setInterval(()=>{extra.sendNotification({method:'notifications/progress',params:{progressToken,progress:++n,message:'Waiting for approval in the browser'}}).catch(()=>undefined);},PROGRESS_INTERVAL_MS);}
    const approved=options.connector.awaitConfirmation(context,pending.commandId,pending.level,pending.confirmationToken,ac.signal);
    const first=await Promise.race([approved.then(r=>({r})),sent.answer.then(a=>({a}))]);
    if('a' in first){
      const a=first.a;
      if(a&&'action' in a&&a.action!=='accept'){
        options.connector.declinePending(context,pending.confirmationToken,a.action); ac.abort(); await approved;
        return errorResult(new Error('The approval link was '+(a.action==='decline'?'declined':'dismissed')+' in the MCP client. The command did not run and this request can no longer be approved.'));
      }
      if(!a||!('action' in a)){ac.abort();await approved;return result(pending);} // the client could not show the link
    }
    const r='r' in first?first.r:await approved;
    if(r){options.sendRelated!({jsonrpc:'2.0',method:'notifications/elicitation/complete',params:{elicitationId:sent.elicitationId}},extra.requestId).catch(()=>undefined);return result(r);}
    if(pending.expiresAt<=Date.now())return errorResult(new Error('The approval request expired before it was approved. The command did not run.'));
    return result(pending);
  }finally{
    if(ticker)clearInterval(ticker);
    extra.signal.removeEventListener('abort',abort); options.connectionSignal?.removeEventListener('abort',abort); ac.abort();
  }
}

export function createMcpServer(options:McpServerOptions):McpServer{
  const server=new McpServer({name:'farcmd-mcp',version:VERSION});
  server.registerTool('farcmd_health',security({title:'Check farcmd connection',annotations:{title:'Check farcmd connection',...LOCAL_READ_ONLY},description:'Verify that the authenticated farcmd MCP endpoint is reachable.',inputSchema:{}}),async(_args,extra)=>{
    try{return result(await options.connector.health(contextFromExtra(extra)));}catch(error){return errorResult(error);}
  });
  server.registerTool('list_commands',security({
    title:'List farcmd commands',annotations:{title:'List farcmd commands',...LOCAL_READ_ONLY},
    description:'List predefined SSH capabilities. Returns command metadata only; the stored shell command is never exposed.',
    inputSchema:{},
  }),async(_args,extra)=>{
    try{return result({commands:await options.connector.listCommands(contextFromExtra(extra))});}catch(error){return errorResult(error);}
  });
  const registerLevel=(level:CommandLevel)=>{
    const title='Run level '+level+' command ('+COMMAND_LEVELS[level].toLowerCase()+')';
    server.registerTool('command_level_'+level,security({
      title,annotations:{title,...LEVEL_ANNOTATIONS[level]},
      description:'Execute one predefined SSH command. OAuth controls whether the command level is exposed; levels 4 and 5 require separate human confirmation in the farcmd web UI. Clients that support URL elicitation show the approval link and receive the result in this same call; otherwise the result contains approvalUrl and confirmationToken: after the person has approved, call again with the same commandId and the confirmationToken. Input is only a command ID; the server keeps the exact shell command private.',
      inputSchema:{commandId:z.string().uuid().describe('ID of the predefined command capability'),confirmationToken:z.string().optional().describe('Return the result of a previously human-confirmed level 4 or 5 execution')},
    }),async(args,extra)=>{
      try{
        const context=contextFromExtra(extra);
        const r=await options.connector.executeCommand(context,args.commandId,level,args.confirmationToken);
        if('pending' in r&&!args.confirmationToken&&options.sendRelated&&supportsUrlElicitation(context.userId,context.clientId))return await approveInBrowser(options,context,r,extra);
        return result(r);
      }catch(error){return errorResult(error);}
    });
  };
  options.visibleLevels.forEach(registerLevel);
  return server;
}
