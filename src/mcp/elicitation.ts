/**
 * URL-mode elicitation for level 4/5 approvals on a stateless MCP endpoint.
 *
 * Every POST /mcp gets a fresh server and transport, so the SDK cannot route a client's answer to a
 * server-to-client request back to the call that sent it. farcmd therefore sends `elicitation/create`
 * itself on the waiting tool call's response stream, with a request id of its own, and mcp/http.ts
 * hands the client's answer (which arrives as a separate POST) to the waiter here. Client
 * capabilities are only sent in `initialize`, which is also a separate request, so they are
 * remembered per user and OAuth client.
 */
import { randomUUID } from 'node:crypto';
import type { ConnectorContext } from '../connector.js';

export const ELICITATION_REQUEST_PREFIX='farcmd-elicit-';

const capabilities=new Map<string,{urlElicitation:boolean;seenAt:number}>();
const CAPABILITY_TTL_MS=7*24*60*60_000;
const key=(userId:string,clientId:string)=>userId+'\n'+clientId;

export function rememberClientCapabilities(userId:string,clientId:string,caps:unknown):void{
  const elicitation=(caps as any)?.elicitation;
  capabilities.set(key(userId,clientId),{urlElicitation:!!elicitation&&typeof elicitation==='object'&&!!elicitation.url,seenAt:Date.now()});
  if(capabilities.size>10_000)for(const [k,v] of capabilities)if(Date.now()-v.seenAt>CAPABILITY_TTL_MS)capabilities.delete(k);
}
export function supportsUrlElicitation(userId:string,clientId:string):boolean{
  const c=capabilities.get(key(userId,clientId)); return !!c&&c.urlElicitation&&Date.now()-c.seenAt<CAPABILITY_TTL_MS;
}
/** Test helper. */
export function forgetClientCapabilities():void{capabilities.clear();}

export type ElicitationAnswer={action:'accept'|'decline'|'cancel'}|{error:string};
const waiters=new Map<string,{userId:string;clientId:string;resolve:(a:ElicitationAnswer)=>void}>();

/**
 * Delivers a client's JSON-RPC response to an elicitation farcmd sent. Returns false for anything else.
 * The answer must come from the same user and OAuth client the request was sent to.
 */
export function deliverElicitationResponse(message:any,userId:string|undefined,clientId:string|undefined):boolean{
  if(!message||typeof message!=='object'||typeof message.id!=='string'||!message.id.startsWith(ELICITATION_REQUEST_PREFIX)||'method' in message)return false;
  const w=waiters.get(message.id); if(!w||w.userId!==userId||w.clientId!==clientId)return false;
  waiters.delete(message.id);
  const action=message.result?.action;
  w.resolve(message.error?{error:String(message.error.message??'elicitation failed')}:action==='accept'||action==='decline'||action==='cancel'?{action}:{error:'invalid elicitation result'});
  return true;
}

export interface ElicitApprovalOptions{
  context:ConnectorContext; approvalUrl:string; message:string; signal:AbortSignal;
  send:(message:Record<string,unknown>)=>Promise<void>;
}
/**
 * Sends the approval link as a URL elicitation. Resolves with the client's answer, or undefined if the
 * request could not be sent or the call ended first.
 */
export async function requestUrlElicitation(o:ElicitApprovalOptions):Promise<{elicitationId:string;answer:Promise<ElicitationAnswer|undefined>}|undefined>{
  const id=ELICITATION_REQUEST_PREFIX+randomUUID(); const elicitationId=randomUUID();
  let resolve!:(a:ElicitationAnswer|undefined)=>void; const answer=new Promise<ElicitationAnswer|undefined>(r=>resolve=r);
  waiters.set(id,{userId:o.context.userId,clientId:o.context.clientId,resolve});
  const stop=()=>{waiters.delete(id);resolve(undefined);}; o.signal.addEventListener('abort',stop,{once:true});
  answer.finally(()=>{o.signal.removeEventListener('abort',stop);waiters.delete(id);}).catch(()=>undefined);
  try{await o.send({jsonrpc:'2.0',id,method:'elicitation/create',params:{mode:'url',message:o.message,url:o.approvalUrl,elicitationId}});}
  catch{stop();return undefined;}
  return {elicitationId,answer};
}
