/**
 * @struktos/auth - JWT Token Adapter
 * 
 * Implementation of ITokenPort using jsonwebtoken library.
 * Follows Hexagonal Architecture (Ports & Adapters) pattern.
 */

import jwt, { VerifyOptions, JwtPayload } from 'jsonwebtoken';
import { User, TokenPayload } from '../models/auth.models';
import {
  ITokenPort,
  TokenGenerationOptions,
  TokenVerificationOptions,
  GeneratedToken,
  TokenPair,
  TokenVerificationError,
  TokenErrorType,
} from '../interfaces/ITokenPort';

/**
 * JWT Adapter Options
 */
export interface JwtAdapterOptions {
  /** JWT secret key */
  secret: string;
  /** Default access token expiration (default: '1h') */
  accessTokenExpiry?: string | number;
  /** Default refresh token expiration (default: '7d') */
  refreshTokenExpiry?: string | number;
  /** Default issuer */
  issuer?: string;
  /** Default audience */
  audience?: string;
  /** Token ID generator */
  jtiGenerator?: () => string;
}

/**
 * JwtTokenAdapter - JWT implementation of ITokenPort
 * 
 * @example
 * ```typescript
 * const tokenAdapter = new JwtTokenAdapter({
 *   secret: process.env.JWT_SECRET!,
 *   issuer: 'my-app',
 *   audience: 'my-api'
 * });
 * 
 * const tokens = await tokenAdapter.generateTokenPair(user);
 * ```
 */
export class JwtTokenAdapter implements ITokenPort {
  private readonly options: Required<JwtAdapterOptions>;
  private revokedTokens: Set<string> = new Set();

  constructor(options: JwtAdapterOptions) {
    this.options = {
      accessTokenExpiry: '1h',
      refreshTokenExpiry: '7d',
      issuer: 'struktos-auth',
      audience: 'struktos-api',
      jtiGenerator: () => this.generateJti(),
      ...options,
    };
  }

  // ==================== Token Generation ====================

  async generateAccessToken(
    user: User,
    options?: TokenGenerationOptions
  ): Promise<GeneratedToken> {
    const payload = this.buildPayload(user, 'access', options?.additionalClaims);
    const signOptions = this.buildSignOptions(
      options?.expiresIn ?? this.options.accessTokenExpiry,
      options?.issuer,
      options?.audience
    );

    const token = jwt.sign(payload, this.options.secret, signOptions);
    const decoded = jwt.decode(token) as JwtPayload;

    return {
      token,
      expiresAt: decoded.exp!,
      expiresIn: decoded.exp! - Math.floor(Date.now() / 1000),
    };
  }

  async generateRefreshToken(
    user: User,
    options?: TokenGenerationOptions
  ): Promise<GeneratedToken> {
    const payload = this.buildPayload(user, 'refresh', options?.additionalClaims);
    const signOptions = this.buildSignOptions(
      options?.expiresIn ?? this.options.refreshTokenExpiry,
      options?.issuer,
      options?.audience
    );

    const token = jwt.sign(payload, this.options.secret, signOptions);
    const decoded = jwt.decode(token) as JwtPayload;

    return {
      token,
      expiresAt: decoded.exp!,
      expiresIn: decoded.exp! - Math.floor(Date.now() / 1000),
    };
  }

  async generateTokenPair(
    user: User,
    accessOptions?: TokenGenerationOptions,
    refreshOptions?: TokenGenerationOptions
  ): Promise<TokenPair> {
    const [accessToken, refreshToken] = await Promise.all([
      this.generateAccessToken(user, accessOptions),
      this.generateRefreshToken(user, refreshOptions),
    ]);

    return { accessToken, refreshToken };
  }

  // ==================== Token Verification ====================

  async verifyToken(
    token: string,
    options?: TokenVerificationOptions
  ): Promise<TokenPayload> {
    return this.verifyTokenSync(token, options);
  }

  verifyTokenSync(
    token: string,
    options?: TokenVerificationOptions
  ): TokenPayload {
    // Check if token is revoked
    if (this.revokedTokens.has(token)) {
      throw new TokenVerificationError(
        TokenErrorType.REVOKED_TOKEN,
        'Token has been revoked'
      );
    }

    try {
      const verifyOptions: VerifyOptions = {};

      if (options?.issuer ?? this.options.issuer) {
        verifyOptions.issuer = options?.issuer ?? this.options.issuer;
      }

      if (options?.audience ?? this.options.audience) {
        verifyOptions.audience = options?.audience ?? this.options.audience;
      }

      if (options?.ignoreExpiration) {
        verifyOptions.ignoreExpiration = true;
      }

      const payload = jwt.verify(token, this.options.secret, verifyOptions) as TokenPayload;
      return payload;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new TokenVerificationError(
          TokenErrorType.EXPIRED_TOKEN,
          'Token has expired',
          error
        );
      }

      if (error instanceof jwt.JsonWebTokenError) {
        if (error.message === 'invalid signature') {
          throw new TokenVerificationError(
            TokenErrorType.INVALID_SIGNATURE,
            'Invalid token signature',
            error
          );
        }

        if (error.message === 'jwt not active') {
          throw new TokenVerificationError(
            TokenErrorType.NOT_BEFORE,
            'Token is not yet active',
            error
          );
        }

        throw new TokenVerificationError(
          TokenErrorType.INVALID_TOKEN,
          error.message,
          error
        );
      }

      throw new TokenVerificationError(
        TokenErrorType.INVALID_TOKEN,
        'Token verification failed',
        error as Error
      );
    }
  }

  async isTokenValid(
    token: string,
    options?: TokenVerificationOptions
  ): Promise<boolean> {
    try {
      await this.verifyToken(token, options);
      return true;
    } catch {
      return false;
    }
  }

  // ==================== Token Decoding ====================

  decodeToken(token: string): TokenPayload | null {
    try {
      const payload = jwt.decode(token) as TokenPayload | null;
      return payload;
    } catch {
      return null;
    }
  }

  // ==================== Token Revocation ====================

  async revokeToken(token: string): Promise<void> {
    this.revokedTokens.add(token);
  }

  async isTokenRevoked(token: string): Promise<boolean> {
    return this.revokedTokens.has(token);
  }

  // ==================== Private Methods ====================

  private buildPayload(
    user: User,
    type: 'access' | 'refresh',
    additionalClaims?: Record<string, unknown>
  ): Partial<TokenPayload> {
    return {
      sub: user.id,
      username: user.username,
      email: user.email,
      roles: user.roles,
      claims: user.claims,
      type,
      jti: this.options.jtiGenerator(),
      ...additionalClaims,
    };
  }

  private buildSignOptions(
    expiresIn: string | number,
    issuer?: string,
    audience?: string
  ): jwt.SignOptions {
    return {
      expiresIn: expiresIn as jwt.SignOptions['expiresIn'],
      issuer: issuer ?? this.options.issuer,
      audience: audience ?? this.options.audience,
    };
  }

  private generateJti(): string {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  // ==================== Utilities ====================

  /**
   * Clear revoked tokens (for testing/cleanup)
   */
  clearRevokedTokens(): void {
    this.revokedTokens.clear();
  }

  /**
   * Get count of revoked tokens
   */
  getRevokedCount(): number {
    return this.revokedTokens.size;
  }
}

/**
 * Factory function
 */
export function createJwtTokenAdapter(options: JwtAdapterOptions): JwtTokenAdapter {
  return new JwtTokenAdapter(options);
}