/**
 * @struktos/auth v1.0.0
 * 
 * C# Identity-inspired authentication and authorization for Node.js.
 * Seamlessly integrated with @struktos/core.
 * 
 * Features:
 * - JWT-based authentication
 * - Role-based authorization (RBAC)
 * - Claims-based authorization
 * - Database-agnostic design (IAuthStore)
 * - Context integration with @struktos/core
 * - High-performance caching
 * - Account lockout support
 * - Hexagonal Architecture (Ports & Adapters)
 * 
 * @example
 * ```typescript
 * import { 
 *   AuthMiddleware, 
 *   JwtTokenAdapter, 
 *   InMemoryAuthStore 
 * } from '@struktos/auth';
 * 
 * const tokenAdapter = new JwtTokenAdapter({ secret: 'your-secret' });
 * const authStore = new InMemoryAuthStore();
 * const authMiddleware = new AuthMiddleware(authService);
 * 
 * app.use(authMiddleware);
 * ```
 */

// ==================== Interfaces ====================

// Auth Service Interface
export {
  IAuthService,
  IAuthServiceCore,
} from './interfaces/IAuthService';

// Auth Store Interface
export {
  IAuthStore,
  InMemoryAuthStore,
} from './interfaces/IAuthStore';

// Auth Guard Interface
export {
  IAuthGuard,
  AuthorizationContext,
  AuthorizationResult,
  RoleBasedGuard,
  ClaimBasedGuard,
  ResourceBasedGuard,
  OwnerBasedGuard,
  CompositeGuard,
  ConditionalGuard,
} from './interfaces/IAuthGuard';

// Token Port Interface
export {
  ITokenPort,
  TokenGenerationOptions,
  TokenVerificationOptions,
  GeneratedToken,
  TokenPair,
  TokenVerificationError,
  TokenErrorType,
} from './interfaces/ITokenPort';

// Password Port Interface
export {
  IPasswordPort,
  PasswordHashOptions,
  PasswordValidationResult,
  PasswordStrengthResult,
  PasswordStrength,
  PasswordPolicy,
  DEFAULT_PASSWORD_POLICY,
} from './interfaces/IPasswordPort';

// ==================== Models ====================

export {
  User,
  Role,
  Claim,
  AuthenticationResult,
  TokenPayload,
  LoginCredentials,
  RegistrationData,
  AuthContextData,
} from './models/auth.models';

// ==================== Middleware ====================

// Authentication Middleware
export {
  AuthMiddleware,
  AuthMiddlewareOptions,
  AuthenticatedContextData,
  createAuthMiddleware,
  createOptionalAuthMiddleware,
} from './middleware/auth.middleware';

// Authorization Middleware
export {
  RolesMiddleware,
  ClaimsMiddleware,
  GuardMiddleware,
  requireRoles,
  requireAllRoles,
  requireClaim,
  requireClaims,
  createAuthorizeMiddleware,
} from './middleware/authorize.middleware';

// ==================== Adapters ====================

// JWT Token Adapter
export {
  JwtTokenAdapter,
  JwtAdapterOptions,
  createJwtTokenAdapter,
} from './adapters/jwt-token.adapter';

// Bcrypt Password Adapter
export {
  BcryptPasswordAdapter,
  BcryptAdapterOptions,
  createBcryptPasswordAdapter,
} from './adapters/bcrypt-password.adapter';

// ==================== Version ====================

export const VERSION = '1.0.0';