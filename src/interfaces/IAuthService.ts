/**
 * @struktos/auth - IAuthService Interface
 * 
 * Core authentication service interface.
 * Inspired by C# Identity's UserManager and SignInManager.
 * 
 * This interface defines the contract for authentication operations,
 * allowing different implementations (JWT, OAuth, etc.)
 */

import { User, AuthenticationResult, TokenPayload, RegistrationData, LoginCredentials } from '../models/auth.models';

/**
 * IAuthService - Authentication Service Interface
 * 
 * Provides a clean abstraction for authentication operations.
 * Implementations should handle:
 * - User registration
 * - User authentication (login)
 * - Token generation and validation
 * - Password management
 * 
 * @example
 * ```typescript
 * class JwtAuthService implements IAuthService {
 *   async register(data: RegistrationData): Promise<AuthenticationResult> {
 *     // Implementation
 *   }
 * }
 * ```
 */
export interface IAuthService<TUser extends User = User> {
  // ==================== Registration ====================

  /**
   * Register a new user
   * 
   * @param data - Registration data including username, email, password
   * @returns Authentication result with tokens if successful
   */
  register(data: RegistrationData): Promise<AuthenticationResult>;

  // ==================== Authentication ====================

  /**
   * Authenticate a user with credentials
   * 
   * @param credentials - Login credentials (username/email + password)
   * @returns Authentication result with tokens if successful
   */
  login(credentials: LoginCredentials): Promise<AuthenticationResult>;

  /**
   * Logout user (invalidate tokens if applicable)
   * 
   * @param userId - User ID to logout
   */
  logout(userId: string): Promise<void>;

  // ==================== Token Management ====================

  /**
   * Validate a JWT token and extract user
   * 
   * @param token - JWT access token
   * @returns User if valid, null if invalid
   */
  validateToken(token: string): Promise<TUser | null>;

  /**
   * Verify token and return payload without loading user
   * 
   * @param token - JWT access token
   * @returns Token payload if valid
   * @throws Error if token is invalid
   */
  verifyToken(token: string): TokenPayload;

  /**
   * Refresh access token using refresh token
   * 
   * @param refreshToken - Refresh token
   * @returns New authentication result with fresh tokens
   */
  refreshToken(refreshToken: string): Promise<AuthenticationResult>;

  /**
   * Revoke a refresh token
   * 
   * @param refreshToken - Refresh token to revoke
   */
  revokeToken(refreshToken: string): Promise<void>;

  // ==================== Password Management ====================

  /**
   * Change user password
   * 
   * @param userId - User ID
   * @param currentPassword - Current password
   * @param newPassword - New password
   * @returns Success status
   */
  changePassword(userId: string, currentPassword: string, newPassword: string): Promise<boolean>;

  /**
   * Reset password with token
   * 
   * @param token - Password reset token
   * @param newPassword - New password
   * @returns Success status
   */
  resetPassword(token: string, newPassword: string): Promise<boolean>;

  /**
   * Generate password reset token
   * 
   * @param email - User email
   * @returns Reset token (or void if sent via email)
   */
  generatePasswordResetToken(email: string): Promise<string | void>;

  // ==================== User Queries ====================

  /**
   * Get user by ID
   * 
   * @param userId - User ID
   * @returns User if found, null otherwise
   */
  getUserById(userId: string): Promise<TUser | null>;

  /**
   * Get user by username
   * 
   * @param username - Username
   * @returns User if found, null otherwise
   */
  getUserByUsername(username: string): Promise<TUser | null>;

  /**
   * Get user by email
   * 
   * @param email - Email address
   * @returns User if found, null otherwise
   */
  getUserByEmail(email: string): Promise<TUser | null>;
}

/**
 * Partial IAuthService for simpler implementations
 * Only requires core authentication methods
 */
export interface IAuthServiceCore<TUser extends User = User> {
  login(credentials: LoginCredentials): Promise<AuthenticationResult>;
  validateToken(token: string): Promise<TUser | null>;
  verifyToken(token: string): TokenPayload;
}