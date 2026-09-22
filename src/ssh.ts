import { Client, utils, type ConnectConfig } from 'ssh2';
import { createHash } from 'node:crypto';

export interface SshKeyMaterial {
  privateKey: string;
  passphrase?: string;
}

export interface SshTargetConfig {
  hostname: string;
  port: number;
  username: string;
  hostFingerprint?: string;
}

export interface SshTestResult {
  ok: boolean;
  fingerprint?: string;
  error?: string;
}

function privateKeyFingerprint(privateKey: string, passphrase?: string): string | undefined {
  const parsed = utils.parseKey(privateKey, passphrase);
  if (parsed instanceof Error) return undefined;
  const keys = Array.isArray(parsed) ? parsed : [parsed];
  const key = keys.find(k => typeof k.isPrivateKey === 'function' && k.isPrivateKey());
  if (!key) return undefined;
  const publicSsh = key.getPublicSSH();
  const body = publicSsh.trim().split(/\\s+/).slice(1, 2)[0];
  if (!body) return undefined;
  return 'sha256:' + createHash('sha256').update(Buffer.from(body, 'base64')).digest('base64url');
}

export function inspectPrivateKey(privateKey: string, passphrase?: string): { valid: boolean; encrypted: boolean; fingerprint?: string } {
  const withoutPassphrase = utils.parseKey(privateKey);
  if (!(withoutPassphrase instanceof Error)) {
    const fingerprint = privateKeyFingerprint(privateKey);
    return { valid: true, encrypted: false, ...(fingerprint ? { fingerprint } : {}) };
  }
  if (passphrase !== undefined) {
    const withPassphrase = utils.parseKey(privateKey, passphrase);
    if (!(withPassphrase instanceof Error)) {
      const fingerprint = privateKeyFingerprint(privateKey, passphrase);
      return { valid: true, encrypted: true, ...(fingerprint ? { fingerprint } : {}) };
    }
  }
  const encrypted = privateKey.includes('BEGIN OPENSSH PRIVATE KEY') || privateKey.includes('BEGIN ENCRYPTED PRIVATE KEY') || privateKey.includes('Proc-Type: 4,ENCRYPTED');
  return { valid: encrypted, encrypted };
}

export async function testSshConnection(target: SshTargetConfig, key: SshKeyMaterial): Promise<SshTestResult> {
  return new Promise(resolve => {
    const client = new Client();
    let presented: string | undefined;
    let settled = false;
    const finish = (result: SshTestResult) => {
      if (settled) return;
      settled = true;
      client.end();
      resolve(result);
    };
    const config: ConnectConfig = {
      host: target.hostname,
      port: target.port,
      username: target.username,
      privateKey: key.privateKey,
      ...(key.passphrase !== undefined ? { passphrase: key.passphrase } : {}),
      readyTimeout: 10_000,
      hostHash: 'sha256',
      hostVerifier: fingerprint => {
        presented = 'sha256:' + fingerprint;
        return !target.hostFingerprint || target.hostFingerprint === presented;
      },
    };
    client.once('ready', () => finish({ ok: true, ...(presented ? { fingerprint: presented } : {}) }));
    client.once('error', err => finish({
      ok: false,
      ...(presented ? { fingerprint: presented } : {}),
      error: target.hostFingerprint && presented && target.hostFingerprint !== presented
        ? 'Host key fingerprint does not match the configured fingerprint'
        : (err.message || 'SSH connection failed'),
    }));
    client.connect(config);
  });
}
