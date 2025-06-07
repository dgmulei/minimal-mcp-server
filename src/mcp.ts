import { Request, Response } from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';
import { randomUUID } from 'crypto';

// Store active transports by session ID
const transports: Record<string, StreamableHTTPServerTransport> = {};

// Create MCP server with a simple ping tool
function createMcpServer(): McpServer {
  const server = new McpServer({
    name: 'minimal-mcp-server',
    version: '1.0.0',
  }, { 
    capabilities: { 
      tools: {},
      logging: {} 
    } 
  });

  // Register a simple ping tool for testing connectivity
  server.tool(
    'ping',
    'Simple ping tool to test MCP connectivity',
    {
      message: z.string().describe('Message to echo back').optional().default('pong')
    },
    async ({ message }) => {
      console.log('Ping tool called');
      
      return {
        content: [
          {
            type: 'text',
            text: `Ping successful! Message: ${message}. Server time: ${new Date().toISOString()}`
          }
        ]
      };
    }
  );

  return server;
}

// Check if request is an initialize request
function isInitializeRequest(body: any): boolean {
  return body && body.method === 'initialize';
}

// MCP endpoint handler - supports Streamable HTTP transport
export async function handleMcpRequest(req: Request, res: Response): Promise<void> {
  try {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    const body = req.body;
    let transport: StreamableHTTPServerTransport;

    if (req.method === 'DELETE') {
      // Handle session termination
      if (sessionId && transports[sessionId]) {
        console.log(`Terminating session: ${sessionId}`);
        await transports[sessionId].close();
        delete transports[sessionId];
        res.status(204).end();
      } else {
        res.status(404).json({
          jsonrpc: '2.0',
          error: {
            code: -32001,
            message: 'Session not found'
          },
          id: null
        });
      }
      return;
    }

    if (sessionId && transports[sessionId]) {
      // Use existing transport
      transport = transports[sessionId];
      console.log(`Using existing session: ${sessionId}`);
    } else if (isInitializeRequest(body)) {
      // Create new transport for initialize request
      const newSessionId = randomUUID();
      console.log(`Creating new session: ${newSessionId}`);
      
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => newSessionId,
        onsessioninitialized: (actualSessionId) => {
          console.log(`Session initialized: ${actualSessionId}`);
          transports[actualSessionId] = transport;
        }
      });

      // Set up cleanup on close
      transport.onclose = () => {
        const sid = transport.sessionId;
        if (sid && transports[sid]) {
          console.log(`Cleaning up session: ${sid}`);
          delete transports[sid];
        }
      };

      // Connect MCP server to transport
      const mcpServer = createMcpServer();
      await mcpServer.connect(transport);

      // Set session ID in response header
      res.setHeader('Mcp-Session-Id', newSessionId);
    } else {
      // Invalid request
      res.status(400).json({
        jsonrpc: '2.0',
        error: {
          code: -32000,
          message: 'Invalid request: missing session ID or not an initialize request'
        },
        id: body?.id || null
      });
      return;
    }

    // Ensure session ID is in response headers
    if (transport.sessionId) {
      res.setHeader('Mcp-Session-Id', transport.sessionId);
    }

    // Handle the request through the transport
    await transport.handleRequest(req, res, body);

  } catch (error) {
    console.error('MCP request error:', error);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: '2.0',
        error: {
          code: -32603,
          message: 'Internal server error'
        },
        id: null
      });
    }
  }
}

// Health check endpoint
export function healthCheck(req: Request, res: Response): void {
  res.json({
    status: 'healthy',
    server: 'minimal-mcp-server',
    timestamp: new Date().toISOString(),
    activeSessions: Object.keys(transports).length
  });
}
