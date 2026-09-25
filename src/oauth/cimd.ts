import { lookup } from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';

export interface CimdMetadata {
  client_id: string;
  client_name: string;
  redirect_uris: string[];
}

const MAX_BYTES = 64 * 1024;

export function isCimdClientId(clientId: string): boolean {
  try {
    const u = new URL(clientId);
    return u.protocol === 'https:' && u.pathname !== '/' &&
      !u.username && !u.password && !u.search && !u.hash &&
      !u.pathname.split('/').includes('..');
  } catch { return false; }
}

export async function fetchCimdMetadata(clientId: string): Promise<CimdMetadata> {
  if (!isCimdClientId(clientId)) throw new Error('Invalid CIMD client_id');
  let current = new URL(clientId);

  for (let i = 0; i <= 3; i++) {
    await assertPublicHost(current.hostname);
    const response = await fetch(current, {
      headers: { accept: 'application/json' },
      redirect: 'manual',
      signal: AbortSignal.timeout(5000),
    });

    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      if (!location || i === 3) throw new Error('Invalid CIMD redirect');
      current = new URL(location, current);
      if (!isCimdClientId(current.toString())) throw new Error('Invalid CIMD redirect');
      continue;
    }

    if (!response.ok) throw new Error('Unable to fetch CIMD document');
    const length = response.headers.get('content-length');
    if (length && Number(length) > MAX_BYTES) throw new Error('CIMD document is too large');

    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > MAX_BYTES) throw new Error('CIMD document is too large');

    let value: unknown;
    try { value = JSON.parse(text); } catch { throw new Error('Invalid CIMD document'); }
    if (!value || typeof value !== 'object') throw new Error('Invalid CIMD document');

    const v = value as Record<string, unknown>;
    if (v.client_id !== clientId || typeof v.client_name !== 'string' ||
        !Array.isArray(v.redirect_uris) || v.redirect_uris.some(x => typeof x !== 'string')) {
      throw new Error('Invalid CIMD document');
    }

    return {
      client_id: clientId,
      client_name: v.client_name,
      redirect_uris: v.redirect_uris as string[],
    };
  }
  throw new Error('Unable to fetch CIMD document');
}

async function assertPublicHost(hostname: string) {
  const addresses = await lookup(hostname, { all: true });
  if (!addresses.length || addresses.some(x => privateIp(x.address))) {
    throw new Error('CIMD host resolves to a private address');
  }
}

/** Addresses a CIMD fetch must never reach: loopback, private, link-local, CGNAT, benchmarking, multicast, reserved. */
const blocked = new BlockList();
for (const [net, prefix] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
  ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 3]] as const) {
  blocked.addSubnet(net, prefix, 'ipv4');
}
for (const [net, prefix] of [['::', 128], ['::1', 128], ['fc00::', 7], ['fe80::', 10], ['fec0::', 10], ['ff00::', 8], ['2001:db8::', 32], ['100::', 64]] as const) {
  blocked.addSubnet(net, prefix, 'ipv6');
}

/** Exported for tests. IPv4-mapped (::ffff:a.b.c.d) and NAT64 (64:ff9b::/96) addresses are checked as the IPv4 address they carry. */
export function privateIp(address: string): boolean {
  const version = isIP(address);
  if (version === 4) return blocked.check(address, 'ipv4');
  if (version !== 6) return true;
  const embedded = embeddedIpv4(address);
  if (embedded) return blocked.check(embedded, 'ipv4');
  return blocked.check(address, 'ipv6');
}

function embeddedIpv4(address: string): string | undefined {
  const n = address.toLowerCase();
  const dotted = /^(?:::ffff:|64:ff9b::)(\d+\.\d+\.\d+\.\d+)$/.exec(n);
  if (dotted) return dotted[1];
  const hex = /^(?:::ffff:|64:ff9b::)([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(n);
  if (hex) { const hi = parseInt(hex[1]!, 16), lo = parseInt(hex[2]!, 16); return [hi >> 8, hi & 255, lo >> 8, lo & 255].join('.'); }
  return undefined;
}
