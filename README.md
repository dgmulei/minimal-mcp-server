# Minimal MCP Server

A minimal Model Context Protocol (MCP) server with OAuth 2.1 authentication, designed for Claude Web integration.

## Features

- OAuth 2.1 with PKCE support
- Streamable HTTP transport
- Simple ping tool for connectivity testing
- Anthropic MCP specification compliant

## Quick Start

```bash
# Clone and install
git clone https://github.com/dgmulei/minimal-mcp-server.git
cd minimal-mcp-server
npm install

# Run locally
npm run dev

# Build for production
npm run build
npm start
```

## Endpoints

### OAuth Discovery
- `/.well-known/oauth-protected-resource` - Resource metadata
- `/.well-known/oauth-authorization-server` - Auth server metadata

### OAuth Flow
- `/authorize` - Authorization endpoint
- `/token` - Token exchange endpoint

### MCP
- `/mcp` - Main MCP endpoint (requires Bearer token)

### Health
- `/health` - Server health check

## Testing with MCP Inspector

```bash
# Install MCP Inspector
npm install -g @modelcontextprotocol/inspector

# Test the server (after OAuth setup)
npx @modelcontextprotocol/inspector http://localhost:3000/mcp
```

## Claude Web Integration

1. Start the server locally: `npm run dev`
2. In Claude Web, go to Settings > Integrations
3. Add custom integration: `http://localhost:3000/mcp`
4. Complete OAuth flow
5. Test with: "Use the ping tool to test connectivity"

## Architecture

- `src/index.ts` - Express server setup
- `src/oauth.ts` - OAuth 2.1 endpoints
- `src/mcp.ts` - MCP transport layer
- `src/storage.ts` - In-memory token storage

## Deployment

Ready for Cloudflare Workers deployment with KV storage.
