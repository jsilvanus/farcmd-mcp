import { parsePrivateKey } from './ssh.js';

const TTL_MS = 15 * 60_000;

type Entry = { passphrase: string; expires: number };
const cache = new Map<string, Entry>();

function key(userId: string, keyId: string): string {
  return userId + ':' + keyId;
}

export function unlockSshKey(userId: string, keyId: string, privateKey: string, passphrase: string): void {
  const parsed = parsePrivateKey(privateKey, passphrase);
  if (parsed instanceof Error) throw new Error('Invalid SSH key or passphrase');
  if (!parsed) throw new Error('Not an SSH private key');
  clearExpiredSshKeyUnlocks(); // passphrases of keys never read again do not linger in memory
  cache.set(key(userId, keyId), { passphrase, expires: Date.now() + TTL_MS });
}

export function getSshPassphrase(userId: string, keyId: string): string | undefined {
  const id = key(userId, keyId);
  const entry = cache.get(id);
  if (!entry || entry.expires < Date.now()) {
    cache.delete(id);
    return undefined;
  }
  entry.expires = Date.now() + TTL_MS;
  return entry.passphrase;
}

export function lockSshKey(userId: string, keyId: string): void {
  cache.delete(key(userId, keyId));
}

function clearExpiredSshKeyUnlocks(): void {
  const now = Date.now();
  for (const [id, entry] of cache) if (entry.expires < now) cache.delete(id);
}
