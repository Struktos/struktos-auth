# Changelog

All notable changes to `@struktos/auth` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-12-14

### 🎉 Initial Release

First stable release of `@struktos/auth` - C# Identity-inspired authentication and authorization for Node.js.

### Added

#### Core Interfaces
- **IAuthService** - Authentication service interface with full lifecycle support
  - User registration, login, logout
  - Token generation and validation
  - Password management (change, reset)
  - User queries by ID, username, email

- **IAuthStore** - Database-agnostic storage interface
  - User CRUD operations
  - Role management (add, remove, check)
  - Claims management (add, remove)
  - Security operations (lockout, failed attempts)

- **IAuthGuard** - Authorization guard interface
  - `RoleBasedGuard` - Check user roles (AND/OR logic)
  - `ClaimBasedGuard` - Check user claims by type and/or value
  - `ResourceBasedGuard` - Permission-based access control
  - `OwnerBasedGuard` - Resource ownership verification
  - `CompositeGuard` - Combine multiple guards
  - `ConditionalGuard` - Custom condition-based authorization

- **ITokenPort** - JWT token operations port
  - Token generation (access + refresh)
  - Token verification (sync and async)
  - Token decoding without verification
  - Token revocation support

- **IPasswordPort** - Password operations port
  - Password hashing
  - Password verification
  - Password validation against policy
  - Password strength checking
  - Password generation

#### Adapters (Hexagonal Architecture)
- **JwtTokenAdapter** - jsonwebtoken implementation of ITokenPort
  - Configurable expiration, issuer, audience
  - JTI (JWT ID) generation
  - Token revocation list management

- **BcryptPasswordAdapter** - bcryptjs implementation of IPasswordPort
  - Configurable salt rounds
  - Customizable password policy
  - Strength meter with scoring

- **InMemoryAuthStore** - In-memory implementation of IAuthStore
  - For development and testing
  - Full feature parity with interface

#### Middleware (IStruktosMiddleware compatible)
- **AuthMiddleware** - JWT authentication middleware
  - Bearer token extraction
  - Automatic context injection (user, roles, claims)
  - Path exclusion support
  - Optional authentication mode

- **Authorization Middlewares**
  - `RolesMiddleware` - Role-based authorization
  - `ClaimsMiddleware` - Claims-based authorization
  - `GuardMiddleware` - Custom guard integration

#### Factory Functions
- `createAuthMiddleware()` - Create authentication middleware
- `createOptionalAuthMiddleware()` - Create optional auth middleware
- `requireRoles()` - Shorthand for role requirement
- `requireAllRoles()` - Require all specified roles
- `requireClaim()` - Shorthand for claim requirement
- `requireClaims()` - Require multiple claims
- `createAuthorizeMiddleware()` - Create guard-based middleware
- `createJwtTokenAdapter()` - Create JWT adapter instance
- `createBcryptPasswordAdapter()` - Create Bcrypt adapter instance

#### Models
- `User` - Base user interface (C# IdentityUser inspired)
- `Role` - Role definition with claims
- `Claim` - Type/value pair for fine-grained permissions
- `TokenPayload` - JWT token payload structure
- `AuthenticationResult` - Login/register result
- `LoginCredentials` - Login input
- `RegistrationData` - Registration input
- `AuthContextData` - Context data interface

#### Security Features
- Account lockout after failed attempts
- Failed login attempt tracking
- Configurable lockout duration
- Token revocation list
- Password policy enforcement

### Technical Details

- **TypeScript**: Full type safety with generics support
- **Node.js**: Requires Node.js 18.0.0 or higher
- **Dependencies**: jsonwebtoken, bcryptjs
- **Peer Dependencies**: @struktos/core ^1.0.0
- **Architecture**: Hexagonal Architecture (Ports & Adapters)

### Documentation

- Comprehensive README with examples
- Full API documentation in code comments
- Integration examples for common scenarios
- Testing guide with InMemoryAuthStore

---

## [Unreleased]

### Planned
- OAuth2/OIDC support
- Two-factor authentication (2FA)
- Session management
- Rate limiting integration
- Audit logging
- Multi-tenant support enhancements