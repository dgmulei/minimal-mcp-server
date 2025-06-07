// Cloudflare Worker entrypoint for minimal MCP server
// This file adapts the Express app to the Cloudflare Workers platform
// - All endpoints and OAuth logic are preserved
// - Storage is via Cloudflare KV

import { handleHealth, handleOAuthMetadata, handleAuthorize, handleToken, handleValidateAccessToken, handleMcpRequest } from './worker_handlers';

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const { pathname } = url;
    const method = request.method;

    // Health check
    if (pathname === '/health' && method === 'GET') {
      return handleHealth(request, env);
    }
    // OAuth discovery endpoints
    if (pathname === '/.well-known/oauth-protected-resource' && method === 'GET') {
      return handleOAuthMetadata(request, env, 'protected');
    }
    if (pathname === '/.well-known/oauth-authorization-server' && method === 'GET') {
      return handleOAuthMetadata(request, env, 'authorization');
    }
    // OAuth flow
    if (pathname === '/authorize' && method === 'GET') {
      return handleAuthorize(request, env);
    }
    if (pathname === '/token' && method === 'POST') {
      return handleToken(request, env);
    }
    // MCP endpoint
    if (pathname === '/mcp') {
      // CORS preflight
      if (method === 'OPTIONS') {
        return new Response(null, {
          status: 200,
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization, Mcp-Session-Id',
            'Access-Control-Expose-Headers': 'Mcp-Session-Id, WWW-Authenticate',
          },
        });
      }
      // OAuth validation and MCP logic
      return handleValidateAccessToken(request, env, ctx, handleMcpRequest);
    }
    // 404 fallback
    return new Response(
      JSON.stringify({
        error: 'not_found',
        error_description: `Endpoint ${method} ${pathname} not found`
      }),
      { status: 404, headers: { 'Content-Type': 'application/json' } }
    );
  },
};

// Types for KV and environment
// Cloudflare Workers type shims
// (You may want to use @cloudflare/workers-types for full type safety)
type KVNamespace = any;
type ExecutionContext = any;

export interface Env {
  MCP_KV: KVNamespace;
}
