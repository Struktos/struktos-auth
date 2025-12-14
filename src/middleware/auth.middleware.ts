/**
 * @struktos/auth - Authentication Middleware
 * 
 * IStruktosMiddleware-based authentication middleware.
 * Extracts JWT from Authorization header and injects user into RequestContext.
 * 
 * Works with @struktos/core's middleware pipeline.
 */

import {
  IStruktosMiddleware,
  MiddlewareContext,
  NextFunction,
  StruktosContextData,
  HttpException,
} from '@struktos/core';
import { IAuthService } from '../interfaces/IAuthService';
import { User } from '../models/auth.models';

/**
 * Auth middleware options
 */
export interface AuthMiddlewareOptions {
  /** Paths to exclude from authentication */
  excludePaths?: string[];
  /** Allow requests without token (optional auth) */
  optional?: boolean;
  /** Custom token extractor */
  tokenExtractor?: (ctx: MiddlewareContext<any>) => string | null;
  /** Custom error handler */
  onError?: (error: Error, ctx: MiddlewareContext<any>) => void;
}

/**
 * Extended context data with auth information
 */
export interface AuthenticatedContextData extends StruktosContextData {}

/**
 * AuthMiddleware - JWT Authentication Middleware
 * 
 * Implements IStruktosMiddleware for use with Struktos platform.
 * Extracts JWT token, validates it, and injects user into context.
 * 
 * @example
 * ```typescript
 * const authMiddleware = new AuthMiddleware(authService);
 * app.use(authMiddleware);
 * 
 * // In handlers, access user from context
 * const user = ctx.context.get('user');
 * ```
 */
export class AuthMiddleware<TUser extends User = User>
  implements IStruktosMiddleware<AuthenticatedContextData>
{
  private readonly options: Required<AuthMiddlewareOptions>;

  constructor(
    private readonly authService: IAuthService<TUser>,
    options: AuthMiddlewareOptions = {}
  ) {
    this.options = {
      excludePaths: options.excludePaths ?? [],
      optional: options.optional ?? false,
      tokenExtractor: options.tokenExtractor ?? this.defaultTokenExtractor.bind(this),
      onError: options.onError ?? this.defaultErrorHandler.bind(this),
    };
  }

  /**
   * Middleware invocation
   */
  async invoke(
    ctx: MiddlewareContext<AuthenticatedContextData>,
    next: NextFunction
  ): Promise<void> {
    const path = ctx.request.path;

    // Check if path is excluded
    if (this.isExcludedPath(path)) {
      await next();
      return;
    }

    // Extract token
    const token = this.options.tokenExtractor(ctx);

    // No token
    if (!token) {
      if (this.options.optional) {
        // Optional auth - continue without user
        ctx.context.set('isAuthenticated', false);
        await next();
        return;
      }

      // Required auth - throw error
      throw new HttpException(401, 'Authorization token required');
    }

    try {
      // Validate token and get user
      const user = await this.authService.validateToken(token);

      if (!user) {
        if (this.options.optional) {
          ctx.context.set('isAuthenticated', false);
          await next();
          return;
        }
        throw new HttpException(401, 'Invalid or expired token');
      }

      // Inject user into context
      this.injectUserIntoContext(ctx, user);

      // Continue to next middleware
      await next();
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }

      // Token validation error
      if (this.options.optional) {
        ctx.context.set('isAuthenticated', false);
        await next();
        return;
      }

      this.options.onError(error as Error, ctx);
      throw new HttpException(401, 'Authentication failed');
    }
  }

  /**
   * Default token extractor
   * Extracts Bearer token from Authorization header
   */
  private defaultTokenExtractor(ctx: MiddlewareContext<any>): string | null {
    const authHeader = ctx.request.headers?.authorization as string | undefined;

    if (!authHeader) {
      return null;
    }

    // Expected format: "Bearer <token>"
    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      return null;
    }

    return parts[1];
  }

  /**
   * Default error handler
   */
  private defaultErrorHandler(error: Error, _ctx: MiddlewareContext<any>): void {
    console.error('[AuthMiddleware] Authentication error:', error.message);
  }

  /**
   * Check if path is excluded from authentication
   */
  private isExcludedPath(path: string): boolean {
    return this.options.excludePaths.some((pattern) => {
      if (pattern.endsWith('*')) {
        // Wildcard match
        return path.startsWith(pattern.slice(0, -1));
      }
      return path === pattern;
    });
  }

  /**
   * Inject user information into context
   */
  private injectUserIntoContext(
    ctx: MiddlewareContext<AuthenticatedContextData>,
    user: TUser
  ): void {
    ctx.context.set('user', user);
    ctx.context.set('userId', user.id);
    ctx.context.set('username', user.username);
    ctx.context.set('roles', user.roles || []);
    ctx.context.set('claims', user.claims || []);
    ctx.context.set('isAuthenticated', true);
  }
}

/**
 * Factory function for creating auth middleware
 */
export function createAuthMiddleware<TUser extends User = User>(
  authService: IAuthService<TUser>,
  options?: AuthMiddlewareOptions
): AuthMiddleware<TUser> {
  return new AuthMiddleware(authService, options);
}

/**
 * Factory function for creating optional auth middleware
 */
export function createOptionalAuthMiddleware<TUser extends User = User>(
  authService: IAuthService<TUser>,
  options?: Omit<AuthMiddlewareOptions, 'optional'>
): AuthMiddleware<TUser> {
  return new AuthMiddleware(authService, { ...options, optional: true });
}