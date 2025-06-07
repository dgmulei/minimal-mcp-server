// Cloudflare KV-based storage for auth codes and access tokens
// Replaces in-memory storage from storage.ts
import type { AuthCode, AccessToken } from './storage';
import type { Env } from './worker';

// KV keys
function authCodeKey(code: string) {
  return `authcode:${code}`;
}
function accessTokenKey(token: string) {
  return `accesstoken:${token}`;
}

// Auth code helpers
export async function storeAuthCode(env: Env, authCode: AuthCode): Promise<void> {
  await env.MCP_KV.put(authCodeKey(authCode.code), JSON.stringify(authCode), { expirationTtl: 600 });
}
export async function getAuthCode(env: Env, code: string): Promise<AuthCode | undefined> {
  const val = await env.MCP_KV.get(authCodeKey(code));
  return val ? JSON.parse(val) : undefined;
}
export async function deleteAuthCode(env: Env, code: string): Promise<void> {
  await env.MCP_KV.delete(authCodeKey(code));
}

// Access token helpers
export async function storeAccessToken(env: Env, accessToken: AccessToken): Promise<void> {
  await env.MCP_KV.put(accessTokenKey(accessToken.token), JSON.stringify(accessToken), { expirationTtl: 3600 });
}
export async function getAccessToken(env: Env, token: string): Promise<AccessToken | undefined> {
  const val = await env.MCP_KV.get(accessTokenKey(token));
  return val ? JSON.parse(val) : undefined;
}
export async function deleteAccessToken(env: Env, token: string): Promise<void> {
  await env.MCP_KV.delete(accessTokenKey(token));
}
