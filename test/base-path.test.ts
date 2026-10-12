import test from 'node:test';
import assert from 'node:assert/strict';
import { basePath, basePathOf, cookiePath, normalizePublicUrl, rewriteUrlFor, wellKnownUrl } from '../src/base-path.js';

test('base path and normalized public URL', () => {
  assert.equal(basePathOf('https://farcmd.example.org'), '');
  assert.equal(basePathOf('https://farcmd.example.org/'), '');
  assert.equal(basePathOf('https://example.org/farcmd-mcp/'), '/farcmd-mcp');
  assert.equal(normalizePublicUrl('https://farcmd.example.org/'), 'https://farcmd.example.org');
  assert.equal(normalizePublicUrl('https://example.org/farcmd-mcp/'), 'https://example.org/farcmd-mcp');
  assert.equal(basePath({}), '');
  assert.equal(cookiePath('', {MCP_PUBLIC_URL:'https://farcmd.example.org'}), '/');
  assert.equal(cookiePath('/oidc', {MCP_PUBLIC_URL:'https://farcmd.example.org'}), '/oidc');
  assert.equal(cookiePath('', {MCP_PUBLIC_URL:'https://example.org/farcmd-mcp'}), '/farcmd-mcp');
  assert.equal(cookiePath('/oidc', {MCP_PUBLIC_URL:'https://example.org/farcmd-mcp'}), '/farcmd-mcp/oidc');
});

test('discovery URLs are path-inserted at the host root (RFC 8414 / RFC 9728)', () => {
  assert.equal(wellKnownUrl('https://farcmd.example.org', 'oauth-protected-resource', '/mcp'), 'https://farcmd.example.org/.well-known/oauth-protected-resource/mcp');
  assert.equal(wellKnownUrl('https://example.org/farcmd-mcp', 'oauth-protected-resource', '/mcp'), 'https://example.org/.well-known/oauth-protected-resource/farcmd-mcp/mcp');
  assert.equal(wellKnownUrl('https://example.org/farcmd-mcp', 'oauth-authorization-server'), 'https://example.org/.well-known/oauth-authorization-server/farcmd-mcp');
});

test('rewriteUrl maps public URLs onto the root-mounted routes', () => {
  const root = rewriteUrlFor('');
  assert.equal(root('/mcp'), '/mcp');
  const rewrite = rewriteUrlFor('/farcmd-mcp');
  assert.equal(rewrite('/farcmd-mcp'), '/');
  assert.equal(rewrite('/farcmd-mcp/'), '/');
  assert.equal(rewrite('/farcmd-mcp?page=confirm&token=x'), '/?page=confirm&token=x');
  assert.equal(rewrite('/farcmd-mcp/?page=confirm'), '/?page=confirm');
  assert.equal(rewrite('/farcmd-mcp/mcp'), '/mcp');
  assert.equal(rewrite('/farcmd-mcp/api/auth/me'), '/api/auth/me');
  assert.equal(rewrite('/farcmd-mcp/oauth/authorize?client_id=a'), '/oauth/authorize?client_id=a');
  assert.equal(rewrite('/farcmd-mcp/.well-known/openid-configuration'), '/.well-known/openid-configuration');
  assert.equal(rewrite('/.well-known/oauth-authorization-server/farcmd-mcp'), '/.well-known/oauth-authorization-server');
  assert.equal(rewrite('/.well-known/openid-configuration/farcmd-mcp'), '/.well-known/openid-configuration');
  assert.equal(rewrite('/.well-known/oauth-protected-resource/farcmd-mcp/mcp'), '/.well-known/oauth-protected-resource/mcp');
  assert.equal(rewrite('/.well-known/oauth-protected-resource/farcmd-mcp'), '/.well-known/oauth-protected-resource');
  // Unprefixed requests (the container's own health check) still reach the app; look-alike prefixes are not stripped.
  assert.equal(rewrite('/health'), '/health');
  assert.equal(rewrite('/farcmd-mcpx/mcp'), '/farcmd-mcpx/mcp');
  assert.equal(rewrite('/.well-known/oauth-authorization-server/farcmd-mcpx'), '/.well-known/oauth-authorization-server/farcmd-mcpx');
});
