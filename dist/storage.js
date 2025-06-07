import { randomUUID } from 'crypto';
// In-memory storage for local development
// In production, this would be replaced with Cloudflare KV
class InMemoryStorage {
    authCodes = new Map();
    accessTokens = new Map();
    // Auth code operations (10 minute TTL)
    storeAuthCode(authCode) {
        this.authCodes.set(authCode.code, authCode);
        // Clean up expired codes
        setTimeout(() => {
            this.authCodes.delete(authCode.code);
        }, 10 * 60 * 1000); // 10 minutes
    }
    getAuthCode(code) {
        const authCode = this.authCodes.get(code);
        if (authCode && authCode.expiresAt > Date.now()) {
            return authCode;
        }
        // Clean up expired code
        this.authCodes.delete(code);
        return undefined;
    }
    deleteAuthCode(code) {
        this.authCodes.delete(code);
    }
    // Access token operations (1 hour TTL)
    storeAccessToken(accessToken) {
        this.accessTokens.set(accessToken.token, accessToken);
        // Clean up expired tokens
        setTimeout(() => {
            this.accessTokens.delete(accessToken.token);
        }, 60 * 60 * 1000); // 1 hour
    }
    getAccessToken(token) {
        const accessToken = this.accessTokens.get(token);
        if (accessToken && accessToken.expiresAt > Date.now()) {
            return accessToken;
        }
        // Clean up expired token
        this.accessTokens.delete(token);
        return undefined;
    }
    deleteAccessToken(token) {
        this.accessTokens.delete(token);
    }
}
export const storage = new InMemoryStorage();
// Helper functions
export function generateAuthCode() {
    return randomUUID();
}
export function generateAccessToken() {
    return randomUUID();
}
export function createAuthCode(clientId, redirectUri, codeChallenge, codeChallengeMethod, scopes, state) {
    return {
        code: generateAuthCode(),
        clientId,
        redirectUri,
        codeChallenge,
        codeChallengeMethod,
        scopes,
        expiresAt: Date.now() + 10 * 60 * 1000, // 10 minutes
        state
    };
}
export function createAccessToken(clientId, scopes) {
    return {
        token: generateAccessToken(),
        clientId,
        scopes,
        expiresAt: Date.now() + 60 * 60 * 1000 // 1 hour
    };
}
