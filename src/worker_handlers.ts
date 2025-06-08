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
import type { Env as WorkerEnv } from './worker';
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
    const params = await request.json();
    // Validate params
    const parsed = TokenSchema.parse(params);
    // Retrieve and validate authorization code
    const authCode = await getAuthCode(env, parsed.code);
    if (!authCode) {
      return new Response(JSON.stringify({
        error: 'invalid_grant',
        error_description: 'Invalid or expired authorization code'
      }), { status: 400, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } });
    }
    // Verify PKCE challenge
    const codeVerifierHash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(params.code_verifier));
    const codeVerifierHashB64 = base64urlEncode(new Uint8Array(codeVerifierHash));
    if (codeVerifierHashB64 !== authCode.codeChallenge) {
      return new Response(JSON.stringify({
        error: 'invalid_grant',
        error_description: 'Invalid code verifier'
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

// Minimal in-memory session store for demonstration (Cloudflare Durable Objects recommended for production)
const mcpSessions: Record<string, { created: number }> = {};

export async function handleMcpRequest(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  // CORS preflight support
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, MCP-Session-Id',
        'Access-Control-Max-Age': '86400',
      }
    });
  }

  // Parse session ID from headers
  const sessionId = request.headers.get('Mcp-Session-Id') || undefined;

  // DELETE = session termination
  if (request.method === 'DELETE') {
    if (sessionId && mcpSessions[sessionId]) {
      delete mcpSessions[sessionId];
      return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*' } });
    } else {
      return new Response(JSON.stringify({
        jsonrpc: '2.0',
        error: { code: -32001, message: 'Session not found' },
        id: null
      }), { status: 404, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } });
    }
  }

  // POST = MCP protocol
  if (request.method === 'POST') {
    let body: any;
    try {
      body = await request.json();
    } catch {
      return new Response(JSON.stringify({
        jsonrpc: '2.0',
        error: { code: -32700, message: 'Parse error: invalid JSON' },
        id: null
      }), { status: 400, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } });
    }

    // MCP initialize
    if (body && body.method === 'initialize') {
      // Generate new session
      const newSessionId = crypto.randomUUID();
      mcpSessions[newSessionId] = { created: Date.now() };
      return new Response(JSON.stringify({
        jsonrpc: '2.0',
        result: {
          server: 'minimal-mcp-server',
          version: '1.0.0',
          session_id: newSessionId,
          tools: [
            {
              name: 'ping',
              description: 'Simple ping tool to test MCP connectivity',
              parameters: {
                type: 'object',
                properties: {
                  message: { type: 'string', description: 'Message to echo back', default: 'pong' }
                },
                required: []
              }
            }
          ]
        },
        id: body.id || null
      }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Mcp-Session-Id': newSessionId
        }
      });
    }

    // Session required for all other methods
    if (!sessionId || !mcpSessions[sessionId]) {
      return new Response(JSON.stringify({
        jsonrpc: '2.0',
        error: { code: -32001, message: 'Missing or invalid MCP session' },
        id: body?.id || null
      }), { status: 401, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } });
    }

    // list_tools
    if (body && body.method === 'list_tools') {
      return new Response(JSON.stringify({
        jsonrpc: '2.0',
        result: [
          {
            name: 'ping',
            description: 'Simple ping tool to test MCP connectivity',
            parameters: {
              type: 'object',
              properties: {
                message: { type: 'string', description: 'Message to echo back', default: 'pong' }
              },
              required: []
            }
          }
        ],
        id: body.id || null
      }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Mcp-Session-Id': sessionId
        }
      });
    }

    // call_tool
    if (body && body.method === 'call_tool' && body.params?.name === 'ping') {
      const message = body.params?.message || 'pong';
      return new Response(JSON.stringify({
        jsonrpc: '2.0',
        result: {
          content: [
            {
              type: 'text',
              text: `Ping successful! Message: ${message}. Server time: ${new Date().toISOString()}`
            }
          ]
        },
        id: body.id || null
      }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Mcp-Session-Id': sessionId
        }
      });
    }

    // Unknown or unsupported method
    return new Response(JSON.stringify({
      jsonrpc: '2.0',
      error: { code: -32601, message: 'Method not found or not implemented' },
      id: body?.id || null
    }), {
      status: 404,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        ...(sessionId ? { 'Mcp-Session-Id': sessionId } : {})
      }
    });
  }

  // All other methods not allowed
  return new Response(JSON.stringify({
    jsonrpc: '2.0',
    error: { code: -32601, message: 'Method not allowed' },
    id: null
  }), { status: 405, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } });
}
