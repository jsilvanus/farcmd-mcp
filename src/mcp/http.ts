import type { IncomingMessage } from 'node:http';
import type { FastifyInstance } from 'fastify';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import { createMcpServer } from './server.js';
import type { FarcmdConnector } from '../connector.js';
import { verifyAccessToken } from '../oauth/jwt.js';
import { deliverElicitationResponse, rememberClientCapabilities } from './elicitation.js';

export interface McpHttpOptions {
  connector: FarcmdConnector;
  publicUrl: string;
  jwtSecret: Uint8Array;
  resource: string;
  /** Access tokens stay valid for up to an hour; this refuses them at once for disabled or deleted users. */
  isUserActive?: (userId: string) => boolean;
}

export async function mountMcpHttp(app: FastifyInstance, options: McpHttpOptions): Promise<void> {
  app.post('/mcp', async (request, reply) => {
    let authInfo: AuthInfo;
    const header = request.headers.authorization;

    // MCP authorization: requests without a valid access token get 401 and a challenge that points to
    // the protected resource metadata, which is how clients (e.g. ChatGPT) discover and confirm OAuth.
    const challenge = (error?: string) => reply.code(401).header('WWW-Authenticate',
      'Bearer resource_metadata="' + options.publicUrl + '/.well-known/oauth-protected-resource/mcp", scope="mcp"' +
      (error ? ', error="' + error + '", error_description="The access token is missing, expired or invalid."' : '')).send({error: error ?? 'unauthorized'});
    if (!header?.startsWith('Bearer ')) return challenge();
    try {
      const token = header.slice('Bearer '.length);
      const { payload } = await verifyAccessToken(options.jwtSecret, options.publicUrl, options.resource, token);
      if (typeof payload.sub === 'string' && options.isUserActive && !options.isUserActive(payload.sub)) throw new Error('inactive user');
      authInfo = {
        token,
        clientId: typeof payload.client_id === 'string' ? payload.client_id : 'oauth-client',
        scopes: typeof payload.scope === 'string' ? payload.scope.split(' ') : [],
        extra: { ...(typeof payload.sub === 'string' ? {userId:payload.sub} : {}) },
      };
    } catch {
      return challenge('invalid_token');
    }

    const userId=typeof authInfo.extra?.userId==='string'?authInfo.extra.userId:undefined;
    const messages:any[]=Array.isArray(request.body)?request.body:[request.body];
    // Capabilities arrive only with initialize; later (stateless) requests look them up.
    if(userId)for(const m of messages)if(m?.method==='initialize')rememberClientCapabilities(userId,authInfo.clientId,m.params?.capabilities);
    // A client's answer to an elicitation farcmd sent on another request's stream (see elicitation.ts).
    if(messages.length>0&&messages.every(m=>deliverElicitationResponse(m,userId,authInfo.clientId)))return reply.code(202).send();

    const visibleLevels=userId?options.connector.visibleLevels({userId,clientId:authInfo.clientId,accessToken:authInfo.token}):[];
    const transport = new StreamableHTTPServerTransport({});
    const closed = new AbortController();
    const server = createMcpServer({connector:options.connector,publicUrl:options.publicUrl,visibleLevels,connectionSignal:closed.signal,
      sendRelated:(message,relatedRequestId)=>transport.send(message as any,{relatedRequestId})});
    await server.connect(transport as unknown as Transport);

    reply.hijack();
    reply.raw.on('close', () => {
      closed.abort();
      transport.close().catch(() => undefined);
      server.close().catch(() => undefined);
    });

    const rawRequest = request.raw as IncomingMessage & { auth?: AuthInfo };
    rawRequest.auth = authInfo;
    await transport.handleRequest(rawRequest, reply.raw, request.body);
  });

  app.head('/mcp', async (_request, reply) => reply.code(200).send());
  app.get('/mcp', async (_request, reply) => reply.code(405).send({error:'Method not allowed'}));
  app.delete('/mcp', async (_request, reply) => reply.code(405).send({error:'Method not allowed'}));
}
