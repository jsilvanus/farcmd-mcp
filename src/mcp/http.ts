import type { IncomingMessage } from 'node:http';
import type { FastifyInstance } from 'fastify';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import { createMcpServer } from './server.js';
import type { FarcmdConnector } from '../connector.js';
import { verifyBearerToken } from '../auth.js';

export interface McpHttpOptions {
  connector: FarcmdConnector;
  publicUrl: string;
  jwtSecret: Uint8Array;
  resource: string;
}

export async function mountMcpHttp(app: FastifyInstance, options: McpHttpOptions): Promise<void> {
  app.post('/mcp', async (request, reply) => {
    let authInfo: AuthInfo | undefined;
    const header = request.headers.authorization;

    if (header?.startsWith('Bearer ')) {
      try {
        const token = header.slice('Bearer '.length);
        const payload = await verifyBearerToken(token, options.jwtSecret, options.publicUrl, options.resource);
        authInfo = {
          token,
          clientId: typeof payload.client_id === 'string' ? payload.client_id : 'oauth-client',
          scopes: typeof payload.scope === 'string' ? payload.scope.split(' ') : [],
          extra: { ...(typeof payload.sub === 'string' ? {userId:payload.sub} : {}) },
        };
      } catch {
        // Tool boundary returns the MCP authentication error.
      }
    }

    const visibleLevels=authInfo&&typeof authInfo.extra?.userId==='string'?options.connector.visibleLevels({userId:authInfo.extra.userId,clientId:authInfo.clientId,accessToken:authInfo.token}):[];
    const server = createMcpServer({connector:options.connector,publicUrl:options.publicUrl,visibleLevels});
    const transport = new StreamableHTTPServerTransport({});
    await server.connect(transport as unknown as Transport);

    reply.hijack();
    reply.raw.on('close', () => {
      transport.close().catch(() => undefined);
      server.close().catch(() => undefined);
    });

    const rawRequest = request.raw as IncomingMessage & { auth?: AuthInfo };
    if (authInfo) rawRequest.auth = authInfo;
    await transport.handleRequest(rawRequest, reply.raw, request.body);
  });

  app.head('/mcp', async (_request, reply) => reply.code(200).send());
  app.get('/mcp', async (_request, reply) => reply.code(405).send({error:'Method not allowed'}));
  app.delete('/mcp', async (_request, reply) => reply.code(405).send({error:'Method not allowed'}));
}
