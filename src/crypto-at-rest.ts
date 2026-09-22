import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const VERSION = 1;
const NONCE_BYTES = 12;
const KEY_BYTES = 32;

function masterKey(): Buffer {
  const raw = process.env.FARCMD_ENCRYPTION_KEY;
  if (!raw) throw new Error('FARCMD_ENCRYPTION_KEY is required');
  const key = Buffer.from(raw, 'base64');
  if (key.length !== KEY_BYTES) throw new Error('FARCMD_ENCRYPTION_KEY must decode to exactly 32 bytes');
  return key;
}

export function encryptSecret(plaintext: string, aad: string): string {
  const key = masterKey();
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [VERSION, nonce.toString('base64url'), tag.toString('base64url'), ciphertext.toString('base64url')].join('.');
}

export function decryptSecret(blob: string, aad: string): string {
  const parts = blob.split('.');
  if (parts.length !== 4 || parts[0] !== String(VERSION)) throw new Error('Unsupported encrypted secret');
  const nonceText = parts[1]!; const tagText = parts[2]!; const ciphertextText = parts[3]!;
  const decipher = createDecipheriv('aes-256-gcm', masterKey(), Buffer.from(nonceText, 'base64url'));
  decipher.setAAD(Buffer.from(aad, 'utf8'));
  decipher.setAuthTag(Buffer.from(tagText, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(ciphertextText, 'base64url')), decipher.final()]).toString('utf8');
}
