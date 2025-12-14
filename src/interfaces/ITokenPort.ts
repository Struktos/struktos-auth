/**
 * @struktos/auth - ITokenPort Interface
 * 
 * Port interface for token operations (JWT generation/validation).
 * This abstraction allows switching JWT libraries without changing business logic.
 * 
 * Follows Hexagonal Architecture (Ports & Adapters) pattern.
 */

import { TokenPayload, User } from '../models/auth.models';

/**
 * Token generation options
 */
export interface TokenGenerationOptions {
  /** Token expiration time (e.g., '1h', '7d', 3600) */
  expiresIn?: string | number;
  /** JWT issuer */
  issuer?: string;
  /** JWT audience */
  audience?: string;
  /** Additional claims to include */
  additionalClaims?: Record<string, unknown>;
}

/**
 * Token verification options
 */
export interface TokenVerificationOptions {
  /** Expected issuer */
  issuer?: string;
  /** Expected audience */
  audience?: string;
  /** Ignore expiration check */
  ignoreExpiration?: boolean;
}

/**
 * Generated token result
 */
export interface GeneratedToken {
  /** The JWT token string */
  token: string;
  /** Token expiration timestamp (Unix epoch in seconds) */
  expiresAt: number;
  /** Token expiration time in seconds from now */
  expiresIn: number;
}

/**
 * Token pair (access + refresh)
 */
export interface TokenPair {
  /** Access token */
  accessToken: GeneratedToken;
  /** Refresh token */
  refreshToken: GeneratedToken;
}

/**
 * ITokenPort - Token operations port interface
 * 
 * Abstracts JWT library operations for:
 * - Token generation (sign)
 * - Token verification (verify)
 * - Token decoding (without verification)
 * 
 * @example
 * ```typescript
 * // In application layer
 * class AuthService {
 *   constructor(private tokenPort: ITokenPort) {}
 *   
 *   async login(credentials: LoginCredentials): Promise<AuthenticationResult> {
 *     const user = await this.validateCredentials(credentials);
 *     const tokens = await this.tokenPort.generateTokenPair(user);
 *     return { success: true, ...tokens };
 *   }
 * }
 * ```
 */
export interface ITokenPort {
  // ==================== Token Generation ====================

  /**
   * Generate an access token for a user
   * 
   * @param user - User to generate token for
   * @param options - Token generation options
   * @returns Generated token with expiration info
   */
  generateAccessToken(
    user: User,
    options?: TokenGenerationOptions
  ): Promise<GeneratedToken>;

  /**
   * Generate a refresh token for a user
   * 
   * @param user - User to generate token for
   * @param options - Token generation options
   * @returns Generated refresh token
   */
  generateRefreshToken(
    user: User,
    options?: TokenGenerationOptions
  ): Promise<GeneratedToken>;

  /**
   * Generate both access and refresh tokens
   * 
   * @param user - User to generate tokens for
   * @param accessOptions - Access token options
   * @param refreshOptions - Refresh token options
   * @returns Token pair
   */
  generateTokenPair(
    user: User,
    accessOptions?: TokenGenerationOptions,
    refreshOptions?: TokenGenerationOptions
  ): Promise<TokenPair>;

  // ==================== Token Verification ====================

  /**
   * Verify a token and extract payload
   * 
   * @param token - Token to verify
   * @param options - Verification options
   * @returns Token payload if valid
   * @throws TokenVerificationError if invalid
   */
  verifyToken(
    token: string,
    options?: TokenVerificationOptions
  ): Promise<TokenPayload>;

  /**
   * Verify token synchronously (blocking)
   * Use with caution - prefer async version
   * 
   * @param token - Token to verify
   * @param options - Verification options
   * @returns Token payload if valid
   * @throws TokenVerificationError if invalid
   */
  verifyTokenSync(
    token: string,
    options?: TokenVerificationOptions
  ): TokenPayload;

  /**
   * Check if a token is valid (boolean result)
   * Does not throw on invalid token
   * 
   * @param token - Token to check
   * @param options - Verification options
   * @returns true if valid, false otherwise
   */
  isTokenValid(
    token: string,
    options?: TokenVerificationOptions
  ): Promise<boolean>;

  // ==================== Token Decoding ====================

  /**
   * Decode a token without verification
   * Useful for extracting payload from expired tokens
   * 
   * @param token - Token to decode
   * @returns Token payload (unverified)
   */
  decodeToken(token: string): TokenPayload | null;

  // ==================== Token Revocation ====================

  /**
   * Revoke a token (add to blacklist)
   * 
   * @param token - Token to revoke
   */
  revokeToken(token: string): Promise<void>;

  /**
   * Check if a token is revoked
   * 
   * @param token - Token to check
   * @returns true if revoked, false otherwise
   */
  isTokenRevoked(token: string): Promise<boolean>;
}

/**
 * Token verification error types
 */
export enum TokenErrorType {
  INVALID_TOKEN = 'INVALID_TOKEN',
  EXPIRED_TOKEN = 'EXPIRED_TOKEN',
  INVALID_SIGNATURE = 'INVALID_SIGNATURE',
  MISSING_CLAIMS = 'MISSING_CLAIMS',
  REVOKED_TOKEN = 'REVOKED_TOKEN',
  NOT_BEFORE = 'NOT_BEFORE',
}

/**
 * Token verification error
 */
export class TokenVerificationError extends Error {
  constructor(
    public readonly type: TokenErrorType,
    message: string,
    public readonly originalError?: Error
  ) {
    super(message);
    this.name = 'TokenVerificationError';
  }
}