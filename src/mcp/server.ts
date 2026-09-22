import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { RequestHandlerExtra } from '@modelcontextprotocol/sdk/shared/protocol.js';
import type { ServerNotification, ServerRequest, CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import type { FarcmdConnector, ConnectorContext } from '../connector.js';

type Extra = RequestHandlerExtra<ServerRequest, ServerNotification>;
const oauthSecuritySchemes = [{ type: 'oauth2' as const, scopes: ['mcp'] }];

function contextFromExtra(extra: Extra): ConnectorContext {
  const auth = extra.authInfo;
  const userId = auth?.extra?.userId;
  if (typeof userId !== 'string' || !auth?.token || !auth.clientId) throw new Error('Authentication required.');
  return { userId, accessToken: auth.token, clientId: auth.clientId };
}
function security<T extends object>(config: T): T & { securitySchemes: typeof oauthSecuritySchemes } {
  return { ...config, securitySchemes: oauthSecuritySchemes };
}
function result(value: unknown): CallToolResult {
  return { content: [{ type:'text', text: JSON.stringify(value, null, 2) }] };
}
function errorResult(error: unknown): CallToolResult {
  return { content:[{type:'text',text:error instanceof Error ? error.message : String(error)}], isError:true };
}
export interface McpServerOptions { connector: FarcmdConnector; publicUrl: string; }

export function createMcpServer(options: McpServerOptions): McpServer {
  const server = new McpServer({ name:'farcmd-mcp', version:'0.1.0' });

  server.registerTool('farcmd_health', security({
    description:'Verify that the authenticated farcmd MCP endpoint is reachable.',
    inputSchema:{},
  }), async (_args, extra) => {
    try { return result(await options.connector.health(contextFromExtra(extra))); }
    catch (error) { return errorResult(error); }
  });

  return server;
}
