/**
 * @struktos/auth - Authorization Middleware
 * 
 * IStruktosMiddleware-based authorization middleware.
 * Checks roles and claims after authentication.
 */

import {
  IStruktosMiddleware,
  MiddlewareContext,
  NextFunction,
  StruktosContextData,
  HttpException,
} from '@struktos/core';
import { User, Claim } from '../models/auth.models';
import { IAuthGuard, AuthorizationContext } from '../interfaces/IAuthGuard';

/**
 * Context data with authenticated user
 */
interface AuthorizedContextData extends StruktosContextData {
  user?: User;
  userId?: string;
  roles?: string[];
  claims?: Claim[];
  isAuthenticated?: boolean;
}

/**
 * RolesMiddleware - Role-based Authorization
 * 
 * Checks if authenticated user has required roles.
 * 
 * @example
 * ```typescript
 * const adminOnly = new RolesMiddleware(['Admin']);
 * app.use('/admin/*', adminOnly);
 * ```
 */
export class RolesMiddleware implements IStruktosMiddleware<AuthorizedContextData> {
  constructor(
    private readonly requiredRoles: string[],
    private readonly logic: 'AND' | 'OR' = 'OR'
  ) {}

  async invoke(
    ctx: MiddlewareContext<AuthorizedContextData>,
    next: NextFunction
  ): Promise<void> {
    const user = ctx.context.get('user') as User | undefined;

    if (!user) {
      throw new HttpException(401, 'Authentication required');
    }

    const userRoles = user.roles || [];

    let hasAccess: boolean;

    if (this.logic === 'OR') {
      // User must have at least one of the required roles
      hasAccess = this.requiredRoles.some((role) => userRoles.includes(role));
    } else {
      // User must have all required roles
      hasAccess = this.requiredRoles.every((role) => userRoles.includes(role));
    }

    if (!hasAccess) {
      throw new HttpException(
        403,
        `Access denied. Required roles: ${this.requiredRoles.join(', ')}`
      );
    }

    await next();
  }
}

/**
 * ClaimsMiddleware - Claims-based Authorization
 * 
 * Checks if authenticated user has required claims.
 * 
 * @example
 * ```typescript
 * const canWriteDocs = new ClaimsMiddleware([
 *   { type: 'permission', value: 'write:documents' }
 * ]);
 * app.use('/api/documents', canWriteDocs);
 * ```
 */
export class ClaimsMiddleware implements IStruktosMiddleware<AuthorizedContextData> {
  constructor(
    private readonly requiredClaims: Array<{ type: string; value?: string }>,
    private readonly logic: 'AND' | 'OR' = 'AND'
  ) {}

  async invoke(
    ctx: MiddlewareContext<AuthorizedContextData>,
    next: NextFunction
  ): Promise<void> {
    const user = ctx.context.get('user') as User | undefined;

    if (!user) {
      throw new HttpException(401, 'Authentication required');
    }

    const userClaims = user.claims || [];

    const checkClaim = (required: { type: string; value?: string }): boolean => {
      return userClaims.some((claim) => {
        if (claim.type !== required.type) return false;
        if (required.value !== undefined) {
          return claim.value === required.value;
        }
        return true;
      });
    };

    let hasAccess: boolean;

    if (this.logic === 'AND') {
      // User must have all required claims
      hasAccess = this.requiredClaims.every(checkClaim);
    } else {
      // User must have at least one required claim
      hasAccess = this.requiredClaims.some(checkClaim);
    }

    if (!hasAccess) {
      const claimsStr = this.requiredClaims
        .map((c) => `${c.type}${c.value ? `:${c.value}` : ''}`)
        .join(', ');
      throw new HttpException(403, `Access denied. Required claims: ${claimsStr}`);
    }

    await next();
  }
}

/**
 * GuardMiddleware - Custom Authorization Guard
 * 
 * Uses IAuthGuard interface for custom authorization logic.
 * 
 * @example
 * ```typescript
 * const resourceGuard = new ResourceBasedGuard();
 * const guardMiddleware = new GuardMiddleware(resourceGuard);
 * app.use('/api/resources/*', guardMiddleware);
 * ```
 */
export class GuardMiddleware implements IStruktosMiddleware<AuthorizedContextData> {
  constructor(
    private readonly guard: IAuthGuard,
    private readonly contextExtractor?: (
      ctx: MiddlewareContext<AuthorizedContextData>
    ) => AuthorizationContext
  ) {}

  async invoke(
    ctx: MiddlewareContext<AuthorizedContextData>,
    next: NextFunction
  ): Promise<void> {
    const user = ctx.context.get('user') as User | undefined;

    if (!user) {
      throw new HttpException(401, 'Authentication required');
    }

    // Extract authorization context
    const authContext = this.contextExtractor
      ? this.contextExtractor(ctx)
      : this.defaultContextExtractor(ctx);

    // Check authorization
    const result = await this.guard.authorize(user, authContext);

    if (!result.granted) {
      throw new HttpException(403, result.reason || 'Access denied');
    }

    await next();
  }

  private defaultContextExtractor(
    ctx: MiddlewareContext<AuthorizedContextData>
  ): AuthorizationContext {
    return {
      resource: ctx.request.path,
      action: ctx.request.method.toLowerCase(),
      resourceId: ctx.request.params?.id,
      metadata: {
        query: ctx.request.query,
        body: ctx.request.body,
      },
    };
  }
}

// ==================== Factory Functions ====================

/**
 * Create role-based authorization middleware
 */
export function requireRoles(
  ...roles: string[]
): RolesMiddleware {
  return new RolesMiddleware(roles, 'OR');
}

/**
 * Create role-based authorization middleware with AND logic
 */
export function requireAllRoles(
  ...roles: string[]
): RolesMiddleware {
  return new RolesMiddleware(roles, 'AND');
}

/**
 * Create claim-based authorization middleware
 */
export function requireClaim(
  type: string,
  value?: string
): ClaimsMiddleware {
  return new ClaimsMiddleware([{ type, value }], 'AND');
}

/**
 * Create claim-based authorization middleware with multiple claims
 */
export function requireClaims(
  claims: Array<{ type: string; value?: string }>,
  logic: 'AND' | 'OR' = 'AND'
): ClaimsMiddleware {
  return new ClaimsMiddleware(claims, logic);
}

/**
 * Create guard-based authorization middleware
 */
export function createAuthorizeMiddleware(
  guard: IAuthGuard,
  contextExtractor?: (ctx: MiddlewareContext<AuthorizedContextData>) => AuthorizationContext
): GuardMiddleware {
  return new GuardMiddleware(guard, contextExtractor);
}