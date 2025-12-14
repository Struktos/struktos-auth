/**
 * @struktos/auth - Authorization Guards
 * 
 * IAuthGuard interface and built-in guard implementations.
 * Inspired by C# Identity's authorization handlers.
 */

import { User } from '../models/auth.models';

/**
 * Authorization Context
 * Information about the resource being accessed
 */
export interface AuthorizationContext {
  /**
   * Resource type (e.g., "document", "user", "order")
   */
  resource: string;

  /**
   * Action being performed (e.g., "read", "write", "delete")
   */
  action: string;

  /**
   * Resource ID (if applicable)
   */
  resourceId?: string;

  /**
   * Additional metadata
   */
  metadata?: Record<string, unknown>;
}

/**
 * Authorization Result
 */
export interface AuthorizationResult {
  /**
   * Whether authorization is granted
   */
  granted: boolean;

  /**
   * Reason for denial (if not granted)
   */
  reason?: string;
}

/**
 * IAuthGuard - Authorization guard interface
 * 
 * Implementations can check roles, claims, or implement custom logic
 * 
 * @example
 * ```typescript
 * class CustomGuard implements IAuthGuard {
 *   async authorize(user: User, context: AuthorizationContext): Promise<AuthorizationResult> {
 *     // Custom logic
 *     return { granted: true };
 *   }
 * }
 * ```
 */
export interface IAuthGuard {
  /**
   * Check if user is authorized to perform an action on a resource
   */
  authorize(user: User, context: AuthorizationContext): Promise<AuthorizationResult>;
}

// ==================== Built-in Guards ====================

/**
 * Role-based Authorization Guard
 * Checks if user has required roles
 */
export class RoleBasedGuard implements IAuthGuard {
  constructor(
    private readonly requiredRoles: string[],
    private readonly logic: 'AND' | 'OR' = 'OR'
  ) {}

  async authorize(user: User, _context: AuthorizationContext): Promise<AuthorizationResult> {
    if (!user.roles || user.roles.length === 0) {
      return {
        granted: false,
        reason: 'User has no roles assigned',
      };
    }

    let hasAccess: boolean;

    if (this.logic === 'OR') {
      hasAccess = this.requiredRoles.some((role) => user.roles?.includes(role));
    } else {
      hasAccess = this.requiredRoles.every((role) => user.roles?.includes(role));
    }

    if (!hasAccess) {
      return {
        granted: false,
        reason: `User must have ${this.logic === 'OR' ? 'one of' : 'all of'} these roles: ${this.requiredRoles.join(', ')}`,
      };
    }

    return { granted: true };
  }
}

/**
 * Claim-based Authorization Guard
 * Checks if user has required claims
 */
export class ClaimBasedGuard implements IAuthGuard {
  constructor(
    private readonly requiredClaimType: string,
    private readonly requiredClaimValue?: string
  ) {}

  async authorize(user: User, _context: AuthorizationContext): Promise<AuthorizationResult> {
    if (!user.claims || user.claims.length === 0) {
      return {
        granted: false,
        reason: 'User has no claims',
      };
    }

    const hasClaim = this.requiredClaimValue
      ? user.claims.some(
          (c) => c.type === this.requiredClaimType && c.value === this.requiredClaimValue
        )
      : user.claims.some((c) => c.type === this.requiredClaimType);

    if (!hasClaim) {
      return {
        granted: false,
        reason: `User must have claim: ${this.requiredClaimType}${this.requiredClaimValue ? `=${this.requiredClaimValue}` : ''}`,
      };
    }

    return { granted: true };
  }
}

/**
 * Resource-based Authorization Guard
 * Checks if user has permission for specific resource and action
 */
export class ResourceBasedGuard implements IAuthGuard {
  async authorize(user: User, context: AuthorizationContext): Promise<AuthorizationResult> {
    if (!user.claims) {
      return {
        granted: false,
        reason: 'User has no permissions',
      };
    }

    // Check for permission claim in format "permission:action:resource"
    const permissionClaim = `${context.action}:${context.resource}`;
    const hasClaim = user.claims.some(
      (c) => c.type === 'permission' && c.value === permissionClaim
    );

    if (!hasClaim) {
      return {
        granted: false,
        reason: `User does not have permission: ${permissionClaim}`,
      };
    }

    return { granted: true };
  }
}

/**
 * Owner-based Authorization Guard
 * Checks if user owns the resource
 */
export class OwnerBasedGuard implements IAuthGuard {
  constructor(
    private readonly ownerIdExtractor?: (context: AuthorizationContext) => string | undefined
  ) {}

  async authorize(user: User, context: AuthorizationContext): Promise<AuthorizationResult> {
    // Extract owner ID from context
    const ownerId = this.ownerIdExtractor
      ? this.ownerIdExtractor(context)
      : (context.metadata?.ownerId as string | undefined);

    if (!ownerId) {
      return {
        granted: false,
        reason: 'Cannot determine resource owner',
      };
    }

    if (user.id !== ownerId) {
      return {
        granted: false,
        reason: 'User is not the owner of this resource',
      };
    }

    return { granted: true };
  }
}

/**
 * Composite Authorization Guard
 * Combines multiple guards with AND/OR logic
 */
export class CompositeGuard implements IAuthGuard {
  constructor(
    private readonly guards: IAuthGuard[],
    private readonly logic: 'AND' | 'OR' = 'AND'
  ) {}

  async authorize(user: User, context: AuthorizationContext): Promise<AuthorizationResult> {
    const results = await Promise.all(
      this.guards.map((guard) => guard.authorize(user, context))
    );

    if (this.logic === 'AND') {
      // All guards must grant access
      const allGranted = results.every((r) => r.granted);
      if (!allGranted) {
        const reasons = results
          .filter((r) => !r.granted)
          .map((r) => r.reason)
          .join('; ');
        return {
          granted: false,
          reason: reasons,
        };
      }
      return { granted: true };
    } else {
      // At least one guard must grant access
      const anyGranted = results.some((r) => r.granted);
      if (!anyGranted) {
        const reasons = results.map((r) => r.reason).join('; ');
        return {
          granted: false,
          reason: reasons,
        };
      }
      return { granted: true };
    }
  }
}

/**
 * Conditional Authorization Guard
 * Grants access based on custom condition
 */
export class ConditionalGuard implements IAuthGuard {
  constructor(
    private readonly condition: (
      user: User,
      context: AuthorizationContext
    ) => boolean | Promise<boolean>,
    private readonly denialReason: string = 'Access denied'
  ) {}

  async authorize(user: User, context: AuthorizationContext): Promise<AuthorizationResult> {
    const result = await this.condition(user, context);
    return {
      granted: result,
      reason: result ? undefined : this.denialReason,
    };
  }
}