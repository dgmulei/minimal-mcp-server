import express from 'express';
import cors from 'cors';
import { protectedResourceMetadata, authorizationServerMetadata, authorize, token, validateAccessToken } from './oauth.js';
import { handleMcpRequest, healthCheck } from './mcp.js';
const app = express();
const port = process.env.PORT || 3000;
// Middleware
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Mcp-Session-Id'],
    exposedHeaders: ['Mcp-Session-Id', 'WWW-Authenticate']
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// Add request logging
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} ${req.method} ${req.url}`);
    next();
});
// OAuth Discovery Endpoints (no auth required)
app.get('/.well-known/oauth-protected-resource', protectedResourceMetadata);
app.get('/.well-known/oauth-authorization-server', authorizationServerMetadata);
// OAuth Flow Endpoints (no auth required)
app.get('/authorize', authorize);
app.post('/token', token);
// Health check (no auth required)
app.get('/health', healthCheck);
// MCP Endpoint (requires OAuth for non-OPTIONS requests)
app.options('/mcp', (req, res) => {
    res.status(200).end();
});
app.all('/mcp', validateAccessToken, handleMcpRequest);
// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Server error:', error);
    if (!res.headersSent) {
        res.status(500).json({
            error: 'internal_server_error',
            error_description: 'An internal server error occurred'
        });
    }
});
// 404 handler
app.use((req, res) => {
    res.status(404).json({
        error: 'not_found',
        error_description: `Endpoint ${req.method} ${req.path} not found`
    });
});
// Start server
app.listen(port, () => {
    console.log(`🚀 Minimal MCP Server running on port ${port}`);
    console.log(`📋 Health check: http://localhost:${port}/health`);
    console.log(`🔐 OAuth metadata: http://localhost:${port}/.well-known/oauth-authorization-server`);
    console.log(`🤖 MCP endpoint: http://localhost:${port}/mcp`);
    console.log('');
    console.log('Ready for Claude Web integration!');
});
// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n🛑 Shutting down server...');
    process.exit(0);
});
process.on('SIGTERM', () => {
    console.log('\n🛑 Shutting down server...');
    process.exit(0);
});
