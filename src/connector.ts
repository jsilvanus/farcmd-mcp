export interface ConnectorContext {
  userId: string;
  clientId: string;
  accessToken: string;
}

export interface FarcmdConnector {
  health(context: ConnectorContext): Promise<{ ok: true }>;
}

export class FarcmdConnectorImpl implements FarcmdConnector {
  async health(_context: ConnectorContext): Promise<{ ok: true }> {
    return { ok: true };
  }
}
