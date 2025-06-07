
export interface AuthCode {
  code: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  scopes: string[];
  expiresAt: number;
  state?: string;
}

export interface AccessToken {
  token: string;
  clientId: string;
  scopes: string[];
  expiresAt: number;
}

// In-memory storage for local development
// In production, this would be replaced with Cloudflare KV
class InMemoryStorage {
  private authCodes = new Map<string, AuthCode>();
  private accessTokens = new Map<string, AccessToken>();

  // Auth code operations (10 minute TTL)
  storeAuthCode(authCode: AuthCode): void {
    this.authCodes.set(authCode.code, authCode);
    // Clean up expired codes
    setTimeout(() => {
      this.authCodes.delete(authCode.code);
    }, 10 * 60 * 1000); // 10 minutes
  }

  getAuthCode(code: string): AuthCode | undefined {
    const authCode = this.authCodes.get(code);
    if (authCode && authCode.expiresAt > Date.now()) {
      return authCode;
    }
    // Clean up expired code
    this.authCodes.delete(code);
    return undefined;
  }

  deleteAuthCode(code: string): void {
    this.authCodes.delete(code);
  }

  // Access token operations (1 hour TTL)
  storeAccessToken(accessToken: AccessToken): void {
    this.accessTokens.set(accessToken.token, accessToken);
    // Clean up expired tokens
    setTimeout(() => {
      this.accessTokens.delete(accessToken.token);
    }, 60 * 60 * 1000); // 1 hour
  }

  getAccessToken(token: string): AccessToken | undefined {
    const accessToken = this.accessTokens.get(token);
    if (accessToken && accessToken.expiresAt > Date.now()) {
      return accessToken;
    }
    // Clean up expired token
    this.accessTokens.delete(token);
    return undefined;
  }

  deleteAccessToken(token: string): void {
    this.accessTokens.delete(token);
  }
}

export const storage = new InMemoryStorage();

// Helper functions
export async function generateAuthCode(): Promise<string> {
  return crypto.randomUUID();
}

export async function generateAccessToken(): Promise<string> {
  return crypto.randomUUID();
}

export async function createAuthCode(
  clientId: string,
  redirectUri: string,
  codeChallenge: string,
  codeChallengeMethod: string,
  scopes: string[],
  state?: string
): Promise<AuthCode> {
  return {
    code: await generateAuthCode(),
    clientId,
    redirectUri,
    codeChallenge,
    codeChallengeMethod,
    scopes,
    expiresAt: Date.now() + 10 * 60 * 1000, // 10 minutes
    state
  };
}

export async function createAccessToken(
  clientId: string,
  scopes: string[]
): Promise<AccessToken> {
  return {
    token: await generateAccessToken(),
    clientId,
    scopes,
    expiresAt: Date.now() + 60 * 60 * 1000 // 1 hour
  };
}
