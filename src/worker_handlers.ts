// Handler stubs for Cloudflare Worker endpoints
// Each function will be implemented to match the Express logic, using Worker APIs and KV
import type { Env } from './worker';

export async function handleHealth(request: Request, env: Env): Promise<Response> {
  return new Response(JSON.stringify({ status: 'healthy', server: 'minimal-mcp-server', timestamp: new Date().toISOString(), activeSessions: 0 }), {
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
  });
}

export async function handleOAuthMetadata(request: Request, env: Env, type: 'protected' | 'authorization'): Promise<Response> {
  const url = new URL(request.url);
  const baseUrl = `${url.protocol}//${url.host}`;
  let body;
  if (type === 'protected') {
    body = {
      resource: `${baseUrl}/mcp`,
      authorization_servers: [baseUrl],
      scopes_supported: ['mcp:tools'],
      bearer_methods_supported: ['header']
    };
  } else {
    body = {
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}/authorize`,
      token_endpoint: `${baseUrl}/token`,
      response_types_supported: ['code'],
      response_modes_supported: ['query'],
      grant_types_supported: ['authorization_code'],
      code_challenge_methods_supported: ['S256'],
      scopes_supported: ['mcp:tools'],
      token_endpoint_auth_methods_supported: ['none']
    };
  }
  return new Response(JSON.stringify(body), { headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } });
}

import { AuthorizeSchema, createAuthCode } from './oauth';

// Node.js Buffer-compatible base64url encoder
function base64urlEncode(bytes: Uint8Array): string {
  const enc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let base64 = '', i;
  for (i = 0; i + 2 < bytes.length; i += 3) {
    base64 += enc[bytes[i] >> 2];
    base64 += enc[((bytes[i] & 0x03) << 4) | (bytes[i + 1] >> 4)];
    base64 += enc[((bytes[i + 1] & 0x0f) << 2) | (bytes[i + 2] >> 6)];
    base64 += enc[bytes[i + 2] & 0x3f];
  }
  if (i < bytes.length) {
    base64 += enc[bytes[i] >> 2];
    if (i === bytes.length - 1) {
      base64 += enc[(bytes[i] & 0x03) << 4];
      base64 += '==';
    } else {
      base64 += enc[((bytes[i] & 0x03) << 4) | (bytes[i + 1] >> 4)];
      base64 += enc[(bytes[i + 1] & 0x0f) << 2];
      base64 += '=';
    }
  }
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

import { storeAuthCode } from './kv_storage';
import type { Env } from './worker';
// Cloudflare Workers provide ExecutionContext globally, but for TS:
type ExecutionContext = any;

export async function handleAuthorize(request: Request, env: Env): Promise<Response> {
  try {
    const url = new URL(request.url);
    const params = Object.fromEntries(url.searchParams.entries());
    // Validate query parameters
    const parsed = AuthorizeSchema.parse(params);
    // Validate redirect URI (must be localhost or HTTPS)
    const urlObj = new URL(parsed.redirect_uri);
    if (urlObj.protocol !== 'https:' && !['localhost', '127.0.0.1'].includes(urlObj.hostname)) {
      return new Response(JSON.stringify({
        error: 'invalid_request',
        error_description: 'Redirect URI must be localhost or HTTPS'
      }), { status: 400, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } });
    }
    // Auto-approve (no consent screen)
    // If code_challenge_method is S256, recompute the code_challenge using the same function as /token
    let codeChallenge = parsed.code_challenge;

    const authCode = await createAuthCode(
      parsed.client_id,
      parsed.redirect_uri,
      codeChallenge,
      parsed.code_challenge_method,
      parsed.scope ? parsed.scope.split(' ') : ['mcp:tools'],
      parsed.state
    );
    await storeAuthCode(env, authCode);
    // Redirect back to client with code
    urlObj.searchParams.set('code', authCode.code);
    if (parsed.state) urlObj.searchParams.set('state', parsed.state);
    return Response.redirect(urlObj.toString(), 302);
  } catch (error) {
    return new Response(JSON.stringify({
      error: 'invalid_request',
      error_description: 'Invalid authorization request'
    }), { status: 400, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } });
  }
}

import { TokenSchema, createAccessToken } from './oauth';
import { getAuthCode, deleteAuthCode, storeAccessToken } from './kv_storage';

export async function handleToken(request: Request, env: Env): Promise<Response> {
  try {
    const body = await request.json();
    const params = TokenSchema.parse(body);
    // Retrieve authorization code
    const authCode = await getAuthCode(env, params.code);
    if (!authCode) {
      return new Response(JSON.stringify({
        error: 'invalid_grant',
        error_description: 'Invalid or expired authorization code'
      }), { status: 400, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } });
    }
    // Validate client ID and redirect URI
    if (authCode.clientId !== params.client_id || authCode.redirectUri !== params.redirect_uri) {
      return new Response(JSON.stringify({
        error: 'invalid_grant',
        error_description: 'Authorization code does not match client'
      }), { status: 400, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } });
    }
    // Verify PKCE challenge
    const codeVerifierHash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(params.code_verifier));
    const codeVerifierHashB64 = base64urlEncode(new Uint8Array(codeVerifierHash));
    if (codeVerifierHashB64 !== authCode.codeChallenge) {
      // Show raw bytes for debugging
      const codeVerifierBytes = Array.from(new TextEncoder().encode(params.code_verifier));
      const hashBytes = Array.from(new Uint8Array(codeVerifierHash));
      return new Response(JSON.stringify({
        error: 'invalid_grant',
        error_description: 'Invalid code verifier',
        debug: {
          received_code_verifier: params.code_verifier,
          code_verifier_utf8_bytes: codeVerifierBytes,
          sha256_hash_bytes: hashBytes,
          computed_code_verifier_hash: codeVerifierHashB64,
          stored_code_challenge: authCode.codeChallenge,
        }
      }), { status: 400, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } });
    }
    // Delete used authorization code
    await deleteAuthCode(env, params.code);
    // Create and store access token
    const accessToken = await createAccessToken(authCode.clientId, authCode.scopes);
    await storeAccessToken(env, accessToken);
    // Return token response
    return new Response(JSON.stringify({
      access_token: accessToken.token,
      token_type: 'Bearer',
      expires_in: 3600,
      scope: authCode.scopes.join(' ')
    }), { headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } });
  } catch (error) {
    return new Response(JSON.stringify({
      error: 'invalid_request',
      error_description: 'Invalid token request'
    }), { status: 400, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } });
  }
}


import { getAccessToken } from './kv_storage';

export async function handleValidateAccessToken(request: Request, env: Env, ctx: ExecutionContext, next: (req: Request, env: Env, ctx: ExecutionContext) => Promise<Response>): Promise<Response> {
  const authHeader = request.headers.get('authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return new Response(JSON.stringify({
      jsonrpc: '2.0',
      error: { code: -32000, message: 'Missing or invalid authorization header' },
      id: null
    }), { status: 401, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } });
  }
  const token = authHeader.substring(7);
  const accessToken = await getAccessToken(env, token);
  if (!accessToken) {
    return new Response(JSON.stringify({
      jsonrpc: '2.0',
      error: { code: -32001, message: 'Invalid or expired access token' },
      id: null
    }), { status: 401, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } });
  }
  // Optionally attach auth info to request (not possible with immutable Request, so pass via env or context if needed)
  return next(request, env, ctx);
}


export async function handleMcpRequest(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  // TODO: Integrate Model Context Protocol SDK logic here if/when SDK supports Workers
  if (request.method === 'DELETE') {
    // For session termination, just return 204 (no content)
    return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*' } });
  }
  if (request.method === 'POST') {
    // For now, respond with a stub JSON-RPC success
    return new Response(JSON.stringify({
      jsonrpc: '2.0',
      result: { message: 'MCP endpoint stub: success', serverTime: new Date().toISOString() },
      id: null
    }), { status: 200, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } });
  }
  return new Response(JSON.stringify({
    jsonrpc: '2.0',
    error: { code: -32601, message: 'Method not allowed' },
    id: null
  }), { status: 405, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } });
}
