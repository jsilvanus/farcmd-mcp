export interface AuthorizationCodeRecord { code:string; clientId:string; redirectUri:string; challenge:string; subject:string; scope:string; expires:number; }
export interface RefreshTokenRecord { token:string; clientId:string; subject:string; scope:string; expires:number; }
export interface OAuthGrantLike { userId:string; clientId:string; clientName:string; visibleLevels:(1|2|3|4|5)[]; level5PermanentlyHidden:boolean; revokedAt?:number; lastUsedAt?:number; }
export interface AuthStore {
  saveAuthorizationCode(record:AuthorizationCodeRecord):void; consumeAuthorizationCode(code:string):AuthorizationCodeRecord|undefined;
  saveRefreshToken(record:RefreshTokenRecord):void; getRefreshToken(token:string):RefreshTokenRecord|undefined;
  getOAuthGrant(userId:string,clientId:string):OAuthGrantLike|undefined;
  upsertOAuthGrant(userId:string,clientId:string,clientName:string,visibleLevels:number[],level5PermanentlyHidden:boolean):void;
  revokeOAuthGrant(userId:string,clientId:string):void;
  updateOAuthGrant(userId:string,clientId:string,visibleLevels:number[],level5PermanentlyHidden:boolean):void;
  listOAuthGrants(userId:string):OAuthGrantLike[];
  touchOAuthGrant(userId:string,clientId:string):void;
  recordSecurityEvent?(userId:string|undefined,clientId:string|undefined,event:string,details?:Record<string,unknown>,outcome?:'success'|'failure'):void;
}
export interface McpUser { id:string; name:string; email?:string; passwordHash?:string; createdAt:number; }
export interface UserStore {
  createUser(user:McpUser):void; listUsers():McpUser[]; getUser(id:string):McpUser|undefined; getUserByEmail(email:string):McpUser|undefined;
  updateUser(id:string,name:string,email:string):void;
}
export interface WebSessionRecord { token:string; userId:string; expires:number; }
export interface WebSessionStore { saveWebSession(record:WebSessionRecord):void; getWebSession(token:string):WebSessionRecord|undefined; deleteWebSession(token:string):void; }
