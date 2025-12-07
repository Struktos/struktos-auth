import jwt, { SignOptions } from 'jsonwebtoken';
import { hash, compare } from 'bcryptjs';
import { CacheManager, RequestContext } from '@struktos/core';
import { IAuthStore } from '../interfaces/IAuthStore';
import {
  User,
  AuthenticationResult,
  LoginCredentials,
  RegistrationData,
  TokenPayload,
  Claim
} from '../models/auth.models';

/**
 * Auth Service Options
 */
export interface AuthServiceOptions {
  /**
   * JWT secret key
   */
  jwtSecret: string;
  
  /**
   * JWT expiration time (default: 1h)
   */
  jwtExpiresIn?: string | number;
  
  /**
   * Refresh token expiration time (default: 7d)
   */
  refreshTokenExpiresIn?: string | number;
  
  /**
   * Number of bcrypt rounds (default: 10)
   */
  bcryptRounds?: number;
  
  /**
   * Enable token caching (default: true)
   */
  enableTokenCache?: boolean;
  
  /**
   * Token cache TTL in milliseconds (default: 30 minutes)
   */
  tokenCacheTTL?: number;
  
  /**
   * Enable user claims caching (default: true)
   */
  enableClaimsCache?: boolean;
  
  /**
   * Claims cache TTL in milliseconds (default: 15 minutes)
   */
  claimsCacheTTL?: number;
  
  /**
   * Maximum failed access attempts before lockout (default: 5)
   */
  maxAccessAttempts?: number;
  
  /**
   * Lockout duration in minutes (default: 15)
   */
  lockoutDuration?: number;
  
  /**
   * JWT issuer
   */
  issuer?: string;
  
  /**
   * JWT audience
   */
  audience?: string;
}

/**
 * AuthService - Core authentication service
 * Inspired by C# Identity's UserManager and SignInManager
 * 
 * Features:
 * - JWT token generation and validation
 * - Password hashing with bcrypt
 * - Integration with @struktos/core Context
 * - High-performance caching with CacheManager
 * - Account lockout support
 */
export class AuthService<TUser extends User = User> {
  private tokenCache: CacheManager<string, TokenPayload>;
  private claimsCache: CacheManager<string, Claim[]>;
  private options: Required<AuthServiceOptions>;
  
  constructor(
    private authStore: IAuthStore<TUser>,
    options: AuthServiceOptions
  ) {
    this.options = {
      jwtExpiresIn: '1h',
      refreshTokenExpiresIn: '7d',
      bcryptRounds: 10,
      enableTokenCache: true,
      tokenCacheTTL: 30 * 60 * 1000, // 30 minutes
      enableClaimsCache: true,
      claimsCacheTTL: 15 * 60 * 1000, // 15 minutes
      maxAccessAttempts: 5,
      lockoutDuration: 15,
      issuer: 'struktos-auth',
      audience: 'struktos-api',
      ...options
    };
    
    this.tokenCache = new CacheManager<string, TokenPayload>(1000);
    this.claimsCache = new CacheManager<string, Claim[]>(500);
  }
  
  // ==================== User Registration ====================
  
  /**
   * Register a new user
   */
  async register(data: RegistrationData): Promise<AuthenticationResult> {
    try {
      // Check if username already exists
      const existingUser = await this.authStore.findUserByUsername(data.username);
      if (existingUser) {
        return {
          success: false,
          error: 'Username already exists'
        };
      }
      
      // Check if email already exists
      const existingEmail = await this.authStore.findUserByEmail(data.email);
      if (existingEmail) {
        return {
          success: false,
          error: 'Email already exists'
        };
      }
      
      // Hash password
      const passwordHash = await hash(data.password, this.options.bcryptRounds);
      
      // Create user
      const user = await this.authStore.createUser({
        username: data.username,
        email: data.email,
        passwordHash,
        phoneNumber: data.phoneNumber,
        emailConfirmed: false,
        lockoutEnabled: true,
        accessFailedCount: 0
      } as Omit<TUser, 'id' | 'createdAt' | 'updatedAt'>);
      
      // Generate tokens
      const { accessToken, refreshToken, expiresIn } = await this.generateTokens(user);
      
      return {
        success: true,
        user,
        accessToken,
        refreshToken,
        expiresIn
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Registration failed'
      };
    }
  }
  
  // ==================== Authentication ====================
  
  /**
   * Authenticate user with username and password
   */
  async login(credentials: LoginCredentials): Promise<AuthenticationResult> {
    try {
      // Find user
      const user = await this.authStore.findUserByUsername(credentials.username);
      if (!user) {
        return {
          success: false,
          error: 'Invalid username or password'
        };
      }
      
      // Check lockout
      if (await this.isLockedOut(user)) {
        return {
          success: false,
          error: 'Account is locked out',
          isLockedOut: true
        };
      }
      
      // Verify password
      const passwordValid = await compare(credentials.password, user.passwordHash);
      if (!passwordValid) {
        // Increment failed attempts
        await this.handleFailedLogin(user);
        return {
          success: false,
          error: 'Invalid username or password'
        };
      }
      
      // Reset failed attempts
      await this.authStore.resetAccessFailedCount(user.id);
      
      // Check if 2FA is required
      if (user.twoFactorEnabled) {
        return {
          success: false,
          requiresTwoFactor: true,
          error: 'Two-factor authentication required'
        };
      }
      
      // Load roles and claims
      const roles = await this.authStore.getUserRoles(user.id);
      const claims = await this.authStore.getUserClaims(user.id);
      
      user.roles = roles;
      user.claims = claims;
      
      // Generate tokens
      const { accessToken, refreshToken, expiresIn } = await this.generateTokens(user);
      
      // Store user in Context
      this.storeUserInContext(user);
      
      return {
        success: true,
        user,
        accessToken,
        refreshToken,
        expiresIn
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Login failed'
      };
    }
  }
  
  /**
   * Validate JWT token and extract user
   */
  async validateToken(token: string): Promise<TUser | null> {
    try {
      // Check cache first
      if (this.options.enableTokenCache) {
        const cachedPayload = this.tokenCache.get(token);
        if (cachedPayload) {
          const user = await this.authStore.findUserById(cachedPayload.sub);
          if (user) {
            return this.enrichUserWithRolesAndClaims(user);
          }
        }
      }
      
      // Verify token
      const payload = jwt.verify(token, this.options.jwtSecret, {
        issuer: this.options.issuer,
        audience: this.options.audience
      }) as TokenPayload;
      
      // Cache token payload
      if (this.options.enableTokenCache) {
        this.tokenCache.set(token, payload);
      }
      
      // Get user from store
      const user = await this.authStore.findUserById(payload.sub);
      if (!user) return null;
      
      return this.enrichUserWithRolesAndClaims(user);
    } catch (error) {
      return null;
    }
  }
  
  // ==================== Token Generation ====================
  
  /**
   * Generate JWT access and refresh tokens
   */
  private async generateTokens(user: TUser): Promise<{
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
  }> {
    const payload: TokenPayload = {
      sub: user.id,
      username: user.username,
      email: user.email,
      roles: user.roles,
      claims: user.claims,
      iss: this.options.issuer,
      aud: this.options.audience
    };
    
    const accessToken = jwt.sign(payload, this.options.jwtSecret, {
      expiresIn: this.options.jwtExpiresIn
    } as SignOptions);
    
    const refreshToken = jwt.sign(
      { sub: user.id, type: 'refresh' },
      this.options.jwtSecret,
      { expiresIn: this.options.refreshTokenExpiresIn } as SignOptions
    );
    
    const decoded = jwt.decode(accessToken) as TokenPayload;
    const expiresIn = decoded.exp ? decoded.exp - Math.floor(Date.now() / 1000) : 3600;
    
    return { accessToken, refreshToken, expiresIn };
  }
  
  // ==================== Context Integration ====================
  
  /**
   * Store authenticated user in Context
   */
  private storeUserInContext(user: TUser): void {
    const context = RequestContext.current();
    if (context) {
      context.set('userId', user.id);
      context.set('username', user.username);
      context.set('user', user);
    }
  }
  
  /**
   * Get current authenticated user from Context
   */
  getCurrentUser(): TUser | undefined {
    const context = RequestContext.current();
    return context?.get('user') as TUser | undefined;
  }
  
  /**
   * Get current user ID from Context
   */
  getCurrentUserId(): string | undefined {
    const context = RequestContext.current();
    return context?.get('userId') as string | undefined;
  }
  
  // ==================== Roles and Claims ====================
  
  /**
   * Enrich user with roles and claims (with caching)
   */
  private async enrichUserWithRolesAndClaims(user: TUser): Promise<TUser> {
    // Get roles
    const roles = await this.authStore.getUserRoles(user.id);
    
    // Get claims (check cache first)
    let claims: Claim[];
    if (this.options.enableClaimsCache) {
      claims = this.claimsCache.get(user.id) || await this.fetchAndCacheClaims(user.id);
    } else {
      claims = await this.authStore.getUserClaims(user.id);
    }
    
    return {
      ...user,
      roles,
      claims
    };
  }
  
  /**
   * Fetch claims and cache them
   */
  private async fetchAndCacheClaims(userId: string): Promise<Claim[]> {
    const claims = await this.authStore.getUserClaims(userId);
    this.claimsCache.set(userId, claims);
    
    // Set TTL
    setTimeout(() => {
      this.claimsCache.delete(userId);
    }, this.options.claimsCacheTTL);
    
    return claims;
  }
  
  // ==================== Account Lockout ====================
  
  /**
   * Check if user is locked out
   */
  private async isLockedOut(user: TUser): Promise<boolean> {
    if (!user.lockoutEnabled) return false;
    if (!user.lockoutEnd) return false;
    
    return user.lockoutEnd > new Date();
  }
  
  /**
   * Handle failed login attempt
   */
  private async handleFailedLogin(user: TUser): Promise<void> {
    const failedCount = await this.authStore.incrementAccessFailedCount(user.id);
    
    if (failedCount >= this.options.maxAccessAttempts) {
      const lockoutEnd = new Date();
      lockoutEnd.setMinutes(lockoutEnd.getMinutes() + this.options.lockoutDuration);
      await this.authStore.setLockoutEnd(user.id, lockoutEnd);
    }
  }
  
  // ==================== Password Management ====================
  
  /**
   * Change user password
   */
  async changePassword(userId: string, currentPassword: string, newPassword: string): Promise<boolean> {
    const user = await this.authStore.findUserById(userId);
    if (!user) return false;
    
    // Verify current password
    const valid = await compare(currentPassword, user.passwordHash);
    if (!valid) return false;
    
    // Hash new password
    const passwordHash = await hash(newPassword, this.options.bcryptRounds);
    
    // Update user
    await this.authStore.updateUser(userId, { passwordHash } as Partial<TUser>);
    
    return true;
  }
}