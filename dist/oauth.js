import { createHash } from 'crypto';
import { z } from 'zod';
import { storage, createAuthCode, createAccessToken } from './storage.js';
// Validation schemas
const AuthorizeSchema = z.object({
    response_type: z.literal('code'),
    client_id: z.string(),
    redirect_uri: z.string().url(),
    scope: z.string().optional(),
    state: z.string().optional(),
    code_challenge: z.string(),
    code_challenge_method: z.literal('S256')
});
const TokenSchema = z.object({
    grant_type: z.literal('authorization_code'),
    code: z.string(),
    redirect_uri: z.string().url(),
    client_id: z.string(),
    code_verifier: z.string()
});
// Helper function to get base URL from request
function getBaseUrl(req) {
    const protocol = req.headers['x-forwarded-proto'] || req.protocol;
    const host = req.headers['x-forwarded-host'] || req.headers.host;
    return `${protocol}://${host}`;
}
// OAuth 2.0 Protected Resource Metadata (RFC 8707)
export function protectedResourceMetadata(req, res) {
    const baseUrl = getBaseUrl(req);
    res.json({
        resource: `${baseUrl}/mcp`,
        authorization_servers: [baseUrl],
        scopes_supported: ['mcp:tools'],
        bearer_methods_supported: ['header']
    });
}
// OAuth 2.0 Authorization Server Metadata (RFC 8414)
export function authorizationServerMetadata(req, res) {
    const baseUrl = getBaseUrl(req);
    res.json({
        issuer: baseUrl,
        authorization_endpoint: `${baseUrl}/authorize`,
        token_endpoint: `${baseUrl}/token`,
        response_types_supported: ['code'],
        response_modes_supported: ['query'],
        grant_types_supported: ['authorization_code'],
        code_challenge_methods_supported: ['S256'],
        scopes_supported: ['mcp:tools'],
        token_endpoint_auth_methods_supported: ['none']
    });
}
// Authorization endpoint - handles the OAuth authorization flow
export function authorize(req, res) {
    try {
        // Validate query parameters
        const params = AuthorizeSchema.parse(req.query);
        // Validate redirect URI (must be localhost or HTTPS)
        // Validate redirect URI (must be localhost or HTTPS)
        const urlObj = new URL(params.redirect_uri);
        if (urlObj.protocol !== 'https:' &&
            !['localhost', '127.0.0.1'].includes(urlObj.hostname)) {
            res.status(400).json({
                error: 'invalid_request',
                error_description: 'Redirect URI must be localhost or HTTPS'
            });
            return;
        }
        // For this minimal implementation, we'll auto-approve the request
        // In a real implementation, you'd show a consent screen here
        const authCode = createAuthCode(params.client_id, params.redirect_uri, params.code_challenge, params.code_challenge_method, params.scope ? params.scope.split(' ') : ['mcp:tools'], params.state);
        storage.storeAuthCode(authCode);
        // Redirect back to client with authorization code
        urlObj.searchParams.set('code', authCode.code);
        if (params.state) {
            urlObj.searchParams.set('state', params.state);
        }
        res.redirect(urlObj.toString());
    }
    catch (error) {
        console.error('Authorization error:', error);
        res.status(400).json({
            error: 'invalid_request',
            error_description: 'Invalid authorization request'
        });
    }
}
// Token endpoint - exchanges authorization code for access token
export function token(req, res) {
    try {
        // Validate request body
        const params = TokenSchema.parse(req.body);
        // Retrieve authorization code
        const authCode = storage.getAuthCode(params.code);
        if (!authCode) {
            res.status(400).json({
                error: 'invalid_grant',
                error_description: 'Invalid or expired authorization code'
            });
            return;
        }
        // Validate client ID and redirect URI
        if (authCode.clientId !== params.client_id ||
            authCode.redirectUri !== params.redirect_uri) {
            res.status(400).json({
                error: 'invalid_grant',
                error_description: 'Authorization code does not match client'
            });
            return;
        }
        // Verify PKCE challenge
        const codeVerifierHash = createHash('sha256')
            .update(params.code_verifier)
            .digest('base64url');
        if (codeVerifierHash !== authCode.codeChallenge) {
            res.status(400).json({
                error: 'invalid_grant',
                error_description: 'Invalid code verifier'
            });
            return;
        }
        // Delete used authorization code
        storage.deleteAuthCode(params.code);
        // Create access token
        const accessToken = createAccessToken(authCode.clientId, authCode.scopes);
        storage.storeAccessToken(accessToken);
        // Return token response
        res.json({
            access_token: accessToken.token,
            token_type: 'Bearer',
            expires_in: 3600,
            scope: authCode.scopes.join(' ')
        });
    }
    catch (error) {
        console.error('Token error:', error);
        res.status(400).json({
            error: 'invalid_request',
            error_description: 'Invalid token request'
        });
    }
}
// Middleware to validate access tokens
export function validateAccessToken(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({
            jsonrpc: '2.0',
            error: {
                code: -32000,
                message: 'Missing or invalid authorization header'
            },
            id: null
        });
        return;
    }
    const token = authHeader.substring(7); // Remove 'Bearer ' prefix
    const accessToken = storage.getAccessToken(token);
    if (!accessToken) {
        res.status(401).json({
            jsonrpc: '2.0',
            error: {
                code: -32001,
                message: 'Invalid or expired access token'
            },
            id: null
        });
        return;
    }
    // Add auth info to request for use in MCP handlers
    req.auth = {
        token: accessToken.token,
        clientId: accessToken.clientId,
        scopes: accessToken.scopes,
        expiresAt: Math.floor(accessToken.expiresAt / 1000)
    };
    next();
}
