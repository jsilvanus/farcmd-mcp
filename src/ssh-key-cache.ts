import ssh2 from 'ssh2';
const { utils } = ssh2;

const TTL_MS = 15 * 60_000;

type Entry = { passphrase: string; expires: number };
const cache = new Map<string, Entry>();

function key(userId: string, keyId: string): string {
  return userId + ':' + keyId;
}

export function unlockSshKey(userId: string, keyId: string, privateKey: string, passphrase: string): void {
  const parsed = utils.parseKey(privateKey, passphrase);
  if (parsed instanceof Error) throw new Error('Invalid SSH key or passphrase');
  const keys = Array.isArray(parsed) ? parsed : [parsed];
  if (!keys.some(k => typeof k.isPrivateKey === 'function' && k.isPrivateKey())) throw new Error('Not an SSH private key');
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

export function clearExpiredSshKeyUnlocks(): void {
  const now = Date.now();
  for (const [id, entry] of cache) if (entry.expires < now) cache.delete(id);
}
