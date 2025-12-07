import { Request, Response, NextFunction } from 'express';
import { RequestContext } from '@struktos/core';
import { AuthService } from '../services/AuthService';
import { IAuthGuard, AuthorizationContext } from '../interfaces/IAuthGuard';
import { User } from '../models/auth.models';

/**
 * Extended Express Request with authenticated user
 */
export interface AuthenticatedRequest extends Request {
  user?: User;
}

/**
 * Create authentication middleware
 * Extracts JWT from Authorization header and validates it
 */
export function createAuthenticateMiddleware<TUser extends User = User>(
  authService: AuthService<TUser>
) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      // Extract token from Authorization header
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        res.status(401).json({
          error: 'Unauthorized',
          message: 'No authorization header provided'
        });
        return;
      }
      
      // Expected format: "Bearer <token>"
      const parts = authHeader.split(' ');
      if (parts.length !== 2 || parts[0] !== 'Bearer') {
        res.status(401).json({
          error: 'Unauthorized',
          message: 'Invalid authorization header format. Expected: Bearer <token>'
        });
        return;
      }
      
      const token = parts[1];
      
      // Validate token
      const user = await authService.validateToken(token);
      if (!user) {
        res.status(401).json({
          error: 'Unauthorized',
          message: 'Invalid or expired token'
        });
        return;
      }
      
      // Store user in request and Context
      (req as AuthenticatedRequest).user = user;
      
      const context = RequestContext.current();
      if (context) {
        context.set('user', user);
        context.set('userId', user.id);
        context.set('username', user.username);
      }
      
      next();
    } catch (error) {
      res.status(401).json({
        error: 'Unauthorized',
        message: error instanceof Error ? error.message : 'Authentication failed'
      });
    }
  };
}

/**
 * Create optional authentication middleware
 * Tries to authenticate but doesn't fail if no token provided
 */
export function createOptionalAuthMiddleware<TUser extends User = User>(
  authService: AuthService<TUser>
) {
  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        return next();
      }
      
      const parts = authHeader.split(' ');
      if (parts.length !== 2 || parts[0] !== 'Bearer') {
        return next();
      }
      
      const token = parts[1];
      const user = await authService.validateToken(token);
      
      if (user) {
        (req as AuthenticatedRequest).user = user;
        
        const context = RequestContext.current();
        if (context) {
          context.set('user', user);
          context.set('userId', user.id);
          context.set('username', user.username);
        }
      }
      
      next();
    } catch (_error) {
      // Silently fail for optional auth
      next();
    }
  };
}

/**
 * Create authorization middleware using guards
 */
export function createAuthorizeMiddleware(
  guard: IAuthGuard,
  contextExtractor?: (req: Request) => AuthorizationContext
) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      // Get user from request or Context
      let user = (req as AuthenticatedRequest).user;
      if (!user) {
        const context = RequestContext.current();
        user = context?.get('user') as User | undefined;
      }
      
      if (!user) {
        res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required'
        });
        return;
      }
      
      // Extract authorization context
      const authContext = contextExtractor
        ? contextExtractor(req)
        : {
            resource: req.baseUrl || req.path,
            action: req.method.toLowerCase()
          };
      
      // Check authorization
      const result = await guard.authorize(user, authContext);
      
      if (!result.granted) {
        res.status(403).json({
          error: 'Forbidden',
          message: result.reason || 'Access denied'
        });
        return;
      }
      
      next();
    } catch (error) {
      res.status(500).json({
        error: 'Internal Server Error',
        message: error instanceof Error ? error.message : 'Authorization failed'
      });
    }
  };
}

/**
 * Require specific roles
 * Shorthand for role-based authorization
 */
export function requireRoles(...roles: string[]) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      let user = (req as AuthenticatedRequest).user;
      if (!user) {
        const context = RequestContext.current();
        user = context?.get('user') as User | undefined;
      }
      
      if (!user) {
        res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required'
        });
        return;
      }
      
      if (!user.roles || user.roles.length === 0) {
        res.status(403).json({
          error: 'Forbidden',
          message: 'User has no roles assigned'
        });
        return;
      }
      
      const hasRole = roles.some(role => user!.roles?.includes(role));
      if (!hasRole) {
        res.status(403).json({
          error: 'Forbidden',
          message: `Required roles: ${roles.join(', ')}`
        });
        return;
      }
      
      next();
    } catch (error) {
      res.status(500).json({
        error: 'Internal Server Error',
        message: error instanceof Error ? error.message : 'Authorization failed'
      });
    }
  };
}

/**
 * Require specific claim
 * Shorthand for claim-based authorization
 */
export function requireClaim(claimType: string, claimValue?: string) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      let user = (req as AuthenticatedRequest).user;
      if (!user) {
        const context = RequestContext.current();
        user = context?.get('user') as User | undefined;
      }
      
      if (!user) {
        res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required'
        });
        return;
      }
      
      if (!user.claims || user.claims.length === 0) {
        res.status(403).json({
          error: 'Forbidden',
          message: 'User has no claims'
        });
        return;
      }
      
      const hasClaim = claimValue
        ? user.claims.some(c => c.type === claimType && c.value === claimValue)
        : user.claims.some(c => c.type === claimType);
      
      if (!hasClaim) {
        res.status(403).json({
          error: 'Forbidden',
          message: `Required claim: ${claimType}${claimValue ? `=${claimValue}` : ''}`
        });
        return;
      }
      
      next();
    } catch (error) {
      res.status(500).json({
        error: 'Internal Server Error',
        message: error instanceof Error ? error.message : 'Authorization failed'
      });
    }
  };
}