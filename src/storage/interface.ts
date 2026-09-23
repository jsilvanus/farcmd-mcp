import type { SqliteOAuthTokenStore } from '../oauth/tokens.js';
export interface OAuthGrantLike { userId:string; clientId:string; clientName:string; visibleLevels:(1|2|3|4|5)[]; level5PermanentlyHidden:boolean; revokedAt?:number; lastUsedAt?:number; }
export interface AuthStore {
  /** Authorization codes and rotating refresh tokens (stored hashed). */
  oauthTokens():SqliteOAuthTokenStore;
  getOAuthGrant(userId:string,clientId:string):OAuthGrantLike|undefined;
  upsertOAuthGrant(userId:string,clientId:string,clientName:string,visibleLevels:number[],level5PermanentlyHidden:boolean):void;
  revokeOAuthGrant(userId:string,clientId:string):void;
  updateOAuthGrant(userId:string,clientId:string,visibleLevels:number[],level5PermanentlyHidden:boolean):void;
  listOAuthGrants(userId:string):OAuthGrantLike[];
  touchOAuthGrant(userId:string,clientId:string):void;
  recordSecurityEvent?(userId:string|undefined,clientId:string|undefined,event:string,details?:Record<string,unknown>,outcome?:'success'|'failure'):void;
}
export interface McpUser { id:string; name:string; email?:string; passwordHash?:string; createdAt:number; disabledAt?:number; }
/** A user may sign in, hold sessions/tokens and use MCP only while this is true. */
export function isActiveUser(user:McpUser|undefined):user is McpUser { return !!user&&user.disabledAt===undefined; }
export interface UserStore {
  createUser(user:McpUser):void; listUsers():McpUser[]; getUser(id:string):McpUser|undefined; getUserByEmail(email:string):McpUser|undefined;
  updateUser(id:string,name:string,email:string):void;
}
export interface WebSessionRecord { token:string; userId:string; expires:number; }
export interface WebSessionStore { saveWebSession(record:WebSessionRecord):void; getWebSession(token:string):WebSessionRecord|undefined; deleteWebSession(token:string):void; }
