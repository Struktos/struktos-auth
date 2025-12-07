/**
 * @struktos/auth
 * 
 * C# Identity-inspired authentication and authorization for Node.js
 * 
 * Features:
 * - JWT-based authentication
 * - Role-based authorization (RBAC)
 * - Claim-based authorization
 * - Database-agnostic design
 * - Context integration with @struktos/core
 * - High-performance caching
 * - Account lockout support
 */

// Core Service
export { AuthService, AuthServiceOptions } from './services/AuthService';

// Interfaces
export { IAuthStore, InMemoryAuthStore } from './interfaces/IAuthStore';
export {
  IAuthGuard,
  AuthorizationContext,
  AuthorizationResult,
  RoleBasedGuard,
  ClaimBasedGuard,
  ResourceBasedGuard,
  CompositeGuard
} from './interfaces/IAuthGuard';

// Models
export {
  User,
  Role,
  Claim,
  AuthenticationResult,
  TokenPayload,
  LoginCredentials,
  RegistrationData
} from './models/auth.models';

// Middleware
export {
  createAuthenticateMiddleware,
  createOptionalAuthMiddleware,
  createAuthorizeMiddleware,
  requireRoles,
  requireClaim,
  AuthenticatedRequest
} from './middleware/auth.middleware';

// Version
export const VERSION = '0.1.0';