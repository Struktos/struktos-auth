# @struktos/auth

C# ASP.NET Identity-inspired authentication and authorization for Node.js with Hexagonal Architecture.

[![npm version](https://badge.fury.io/js/%40struktos%2Fauth.svg)](https://www.npmjs.com/package/@struktos/auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-green.svg)](https://nodejs.org/)

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔐 **JWT Authentication** | Secure token-based auth with access/refresh token pairs |
| 👥 **Role-Based Access Control** | C# Identity-style RBAC with hierarchical roles |
| 🎫 **Claims-Based Authorization** | Fine-grained permissions using type/value claims |
| 🗄️ **Database-Agnostic** | `IAuthStore` interface works with any database |
| 🔌 **Context Integration** | Automatic user injection into @struktos/core RequestContext |
| ⚡ **High-Performance Caching** | Token and claims caching with CacheManager |
| 🛡️ **Account Lockout** | Automatic brute-force protection |
| 🔒 **Password Security** | Bcrypt hashing with strength validation |
| 🏛️ **Hexagonal Architecture** | Clean Ports & Adapters pattern |

## 📦 Installation

```bash
npm install @struktos/core @struktos/auth
# or
yarn add @struktos/core @struktos/auth
# or
pnpm add @struktos/core @struktos/auth
```

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     Application Layer                           │
│  ┌─────────────────┐  ┌─────────────────┐  ┌────────────────┐  │
│  │   AuthService   │  │   AuthGuards    │  │   Middleware   │  │
│  │  (IAuthService) │  │  (IAuthGuard)   │  │  (IStruktosM.) │  │
│  └────────┬────────┘  └────────┬────────┘  └───────┬────────┘  │
├───────────┼────────────────────┼───────────────────┼────────────┤
│           │         Ports      │                   │            │
│  ┌────────▼────────┐  ┌────────▼────────┐  ┌──────▼────────┐   │
│  │   ITokenPort    │  │  IPasswordPort  │  │  IAuthStore   │   │
│  └────────┬────────┘  └────────┬────────┘  └───────┬───────┘   │
├───────────┼────────────────────┼───────────────────┼────────────┤
│           │       Adapters     │                   │            │
│  ┌────────▼────────┐  ┌────────▼────────┐  ┌──────▼────────┐   │
│  │ JwtTokenAdapter │  │BcryptPasswordAd.│  │InMemoryAuth..│   │
│  │  (jsonwebtoken) │  │   (bcryptjs)    │  │ (Prisma/etc) │   │
│  └─────────────────┘  └─────────────────┘  └───────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### 1. Initialize Auth Service

```typescript
import { AuthService, InMemoryAuthStore, JwtTokenAdapter, BcryptPasswordAdapter } from '@struktos/auth';

// Create adapters (Hexagonal Architecture)
const tokenAdapter = new JwtTokenAdapter({
  secret: process.env.JWT_SECRET!,
  accessTokenExpiry: '1h',
  refreshTokenExpiry: '7d',
  issuer: 'my-app',
  audience: 'my-api'
});

const passwordAdapter = new BcryptPasswordAdapter({
  defaultRounds: 12,
  policy: {
    minLength: 8,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChar: true
  }
});

// Use InMemoryAuthStore for development, implement IAuthStore for production
const authStore = new InMemoryAuthStore();

// Create auth service
const authService = new AuthService(authStore, {
  jwtSecret: process.env.JWT_SECRET!,
  jwtExpiresIn: '1h',
  refreshTokenExpiresIn: '7d',
  enableTokenCache: true,
  enableClaimsCache: true,
  maxAccessAttempts: 5,
  lockoutDuration: 15 // minutes
});
```

### 2. User Registration & Login

```typescript
// Registration
const registerResult = await authService.register({
  username: 'john.doe',
  email: 'john@example.com',
  password: 'SecurePass123!'
});

if (registerResult.success) {
  console.log('User created:', registerResult.user);
  console.log('Access Token:', registerResult.accessToken);
  console.log('Refresh Token:', registerResult.refreshToken);
}

// Login
const loginResult = await authService.login({
  username: 'john.doe', // or email
  password: 'SecurePass123!'
});

if (loginResult.success) {
  // User authenticated
  const { accessToken, refreshToken, expiresIn } = loginResult;
}

// Handle locked accounts
if (loginResult.isLockedOut) {
  console.log('Account is locked. Try again later.');
}
```

### 3. Add Authentication Middleware

```typescript
import express from 'express';
import { createStruktosMiddleware } from '@struktos/adapter-express';
import { AuthMiddleware, createAuthMiddleware } from '@struktos/auth';

const app = express();

// Context middleware (required first)
app.use(createStruktosMiddleware());

// Authentication middleware
const authMiddleware = new AuthMiddleware(authService, {
  excludePaths: ['/auth/login', '/auth/register', '/health'],
  optional: false // Set true for optional authentication
});

// Apply to all routes
app.use(createAuthMiddleware(authService));

// Or use class-based middleware with Struktos pipeline
app.use(authMiddleware.handle.bind(authMiddleware));
```

### 4. Access User from Context

```typescript
import { RequestContext } from '@struktos/core';

app.get('/api/profile', (req, res) => {
  // User automatically injected by AuthMiddleware
  const ctx = RequestContext.current();
  const user = ctx?.get('user');
  const userId = ctx?.get('userId');
  const roles = ctx?.get('roles');

  // Or from request object
  const userFromReq = req.user;

  res.json({
    id: user.id,
    username: user.username,
    email: user.email,
    roles: user.roles
  });
});
```

## 🔒 Authorization

### Role-Based Access Control (RBAC)

```typescript
import { requireRoles, requireAllRoles, RolesMiddleware } from '@struktos/auth';

// Require ANY of the specified roles (OR logic)
app.get('/api/admin', requireRoles('Admin', 'SuperAdmin'), (req, res) => {
  res.json({ message: 'Welcome, Admin!' });
});

// Require ALL specified roles (AND logic)
app.get('/api/super', requireAllRoles('Admin', 'Verified'), (req, res) => {
  res.json({ message: 'You have all required roles!' });
});

// Using class-based middleware
const rolesMiddleware = new RolesMiddleware(['Admin', 'Moderator']);
app.use('/admin/*', rolesMiddleware.handle.bind(rolesMiddleware));

// Managing roles
await authStore.addUserToRole(userId, 'Admin');
await authStore.addUserToRole(userId, 'Moderator');
await authStore.removeUserFromRole(userId, 'Moderator');

const userRoles = await authStore.getUserRoles(userId);
const isAdmin = await authStore.isUserInRole(userId, 'Admin');
```

### Claims-Based Authorization

Claims provide fine-grained permissions beyond roles.

```typescript
import { requireClaim, requireClaims, ClaimsMiddleware } from '@struktos/auth';

// Require a specific claim type
app.get('/api/documents', requireClaim('permission', 'read:documents'), (req, res) => {
  res.json({ documents: [] });
});

// Require multiple claims (AND logic)
app.post('/api/documents', 
  requireClaims(
    { type: 'permission', value: 'write:documents' },
    { type: 'department', value: 'engineering' }
  ),
  (req, res) => {
    res.json({ message: 'Document created!' });
  }
);

// Managing claims
await authStore.addUserClaim(userId, { type: 'permission', value: 'read:users' });
await authStore.addUserClaim(userId, { type: 'permission', value: 'write:users' });
await authStore.addUserClaim(userId, { type: 'department', value: 'engineering' });
await authStore.addUserClaim(userId, { type: 'tenant', value: 'acme-corp' });

await authStore.removeUserClaim(userId, { type: 'permission', value: 'write:users' });

const claims = await authStore.getUserClaims(userId);
```

### Authorization Guards

Guards provide flexible, composable authorization logic.

```typescript
import {
  RoleBasedGuard,
  ClaimBasedGuard,
  ResourceBasedGuard,
  OwnerBasedGuard,
  CompositeGuard,
  ConditionalGuard,
  createAuthorizeMiddleware
} from '@struktos/auth';

// Role-based guard
const adminGuard = new RoleBasedGuard(['Admin', 'SuperAdmin']);

// Claim-based guard
const readPermissionGuard = new ClaimBasedGuard('permission', 'read:sensitive');

// Resource-based guard (custom logic)
const resourceGuard = new ResourceBasedGuard();

// Owner-based guard (check if user owns the resource)
const ownerGuard = new OwnerBasedGuard();

// Composite guard (combine multiple guards)
const compositeGuard = new CompositeGuard(
  [adminGuard, readPermissionGuard],
  'OR' // 'AND' or 'OR' logic
);

// Conditional guard (custom predicate)
const businessHoursGuard = new ConditionalGuard((ctx) => {
  const hour = new Date().getHours();
  return hour >= 9 && hour <= 17;
}, 'Access only during business hours (9 AM - 5 PM)');

// Use guards with middleware
app.get('/api/sensitive', createAuthorizeMiddleware(compositeGuard), (req, res) => {
  res.json({ data: 'sensitive information' });
});
```

## 🔑 Token Management

### JWT Token Adapter

```typescript
import { JwtTokenAdapter, TokenVerificationError, TokenErrorType } from '@struktos/auth';

const tokenAdapter = new JwtTokenAdapter({
  secret: process.env.JWT_SECRET!,
  accessTokenExpiry: '15m',     // Short-lived access tokens
  refreshTokenExpiry: '7d',     // Long-lived refresh tokens
  issuer: 'my-application',
  audience: 'my-api'
});

// Generate tokens
const accessToken = await tokenAdapter.generateAccessToken(user);
const refreshToken = await tokenAdapter.generateRefreshToken(user);
const tokenPair = await tokenAdapter.generateTokenPair(user);

// Verify tokens
try {
  const payload = await tokenAdapter.verifyToken(token);
  console.log('User ID:', payload.sub);
  console.log('Username:', payload.username);
  console.log('Roles:', payload.roles);
} catch (error) {
  if (error instanceof TokenVerificationError) {
    switch (error.type) {
      case TokenErrorType.EXPIRED_TOKEN:
        console.log('Token has expired');
        break;
      case TokenErrorType.INVALID_SIGNATURE:
        console.log('Invalid token signature');
        break;
      case TokenErrorType.REVOKED_TOKEN:
        console.log('Token has been revoked');
        break;
    }
  }
}

// Decode without verification (useful for expired tokens)
const payload = tokenAdapter.decodeToken(expiredToken);

// Token revocation
await tokenAdapter.revokeToken(refreshToken);
const isRevoked = await tokenAdapter.isTokenRevoked(refreshToken);

// Refresh tokens
const newTokens = await authService.refreshToken(refreshToken);
```

### Token Payload Structure

```typescript
interface TokenPayload {
  sub: string;           // User ID
  username: string;      // Username
  email: string;         // Email
  roles: string[];       // User roles
  type: 'access' | 'refresh';
  iat: number;           // Issued at
  exp: number;           // Expiration
  iss: string;           // Issuer
  aud: string;           // Audience
  jti: string;           // JWT ID (unique identifier)
}
```

## 🔐 Password Security

### Bcrypt Password Adapter

```typescript
import { BcryptPasswordAdapter, PasswordStrength } from '@struktos/auth';

const passwordAdapter = new BcryptPasswordAdapter({
  defaultRounds: 12, // Higher = more secure but slower
  policy: {
    minLength: 8,
    maxLength: 128,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChar: true,
    disallowCommonPasswords: true
  }
});

// Hash password
const hash = await passwordAdapter.hash('SecurePass123!');

// Verify password
const isValid = await passwordAdapter.verify('SecurePass123!', hash);

// Validate against policy
const validation = passwordAdapter.validate('weak');
if (!validation.isValid) {
  console.log('Password errors:', validation.errors);
  // ['Password must be at least 8 characters', 'Must contain uppercase letter', ...]
}

// Check password strength
const strength = passwordAdapter.checkStrength('MyP@ssw0rd!');
console.log('Strength:', PasswordStrength[strength.strength]); // 'STRONG'
console.log('Score:', strength.score); // 0-100
console.log('Feedback:', strength.feedback);

// Generate secure password
const randomPassword = passwordAdapter.generatePassword(16, {
  includeUppercase: true,
  includeLowercase: true,
  includeNumbers: true,
  includeSymbols: true
});
```

## 🗄️ Database Integration

### Implementing IAuthStore

Create a custom implementation for your database:

```typescript
import { IAuthStore, User, Role, Claim } from '@struktos/auth';
import { PrismaClient } from '@prisma/client';

export class PrismaAuthStore implements IAuthStore<User> {
  constructor(private readonly prisma: PrismaClient) {}

  // User CRUD
  async findUserById(userId: string): Promise<User | null> {
    return this.prisma.user.findUnique({
      where: { id: userId },
      include: { roles: true, claims: true }
    });
  }

  async findUserByUsername(username: string): Promise<User | null> {
    return this.prisma.user.findUnique({
      where: { username },
      include: { roles: true, claims: true }
    });
  }

  async findUserByEmail(email: string): Promise<User | null> {
    return this.prisma.user.findUnique({
      where: { email },
      include: { roles: true, claims: true }
    });
  }

  async createUser(userData: Omit<User, 'id' | 'createdAt' | 'updatedAt'>): Promise<User> {
    return this.prisma.user.create({
      data: userData
    });
  }

  async updateUser(userId: string, updates: Partial<User>): Promise<User | null> {
    return this.prisma.user.update({
      where: { id: userId },
      data: updates
    });
  }

  async deleteUser(userId: string): Promise<boolean> {
    await this.prisma.user.delete({ where: { id: userId } });
    return true;
  }

  // Role management
  async getUserRoles(userId: string): Promise<string[]> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: { roles: { select: { name: true } } }
    });
    return user?.roles.map(r => r.name) ?? [];
  }

  async addUserToRole(userId: string, roleName: string): Promise<void> {
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        roles: {
          connectOrCreate: {
            where: { name: roleName },
            create: { name: roleName }
          }
        }
      }
    });
  }

  async removeUserFromRole(userId: string, roleName: string): Promise<void> {
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        roles: { disconnect: { name: roleName } }
      }
    });
  }

  async isUserInRole(userId: string, roleName: string): Promise<boolean> {
    const roles = await this.getUserRoles(userId);
    return roles.includes(roleName);
  }

  // Claims management
  async getUserClaims(userId: string): Promise<Claim[]> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: { claims: true }
    });
    return user?.claims ?? [];
  }

  async addUserClaim(userId: string, claim: Claim): Promise<void> {
    await this.prisma.claim.create({
      data: {
        type: claim.type,
        value: claim.value,
        userId
      }
    });
  }

  async removeUserClaim(userId: string, claim: Claim): Promise<void> {
    await this.prisma.claim.deleteMany({
      where: {
        userId,
        type: claim.type,
        value: claim.value
      }
    });
  }

  // Security
  async incrementAccessFailedCount(userId: string): Promise<number> {
    const user = await this.prisma.user.update({
      where: { id: userId },
      data: { accessFailedCount: { increment: 1 } }
    });
    return user.accessFailedCount;
  }

  async resetAccessFailedCount(userId: string): Promise<void> {
    await this.prisma.user.update({
      where: { id: userId },
      data: { accessFailedCount: 0 }
    });
  }

  async setLockoutEnd(userId: string, lockoutEnd: Date | null): Promise<void> {
    await this.prisma.user.update({
      where: { id: userId },
      data: { lockoutEnd }
    });
  }
}
```

## 🧪 Testing

Use `InMemoryAuthStore` for unit and integration tests:

```typescript
import {
  InMemoryAuthStore,
  JwtTokenAdapter,
  BcryptPasswordAdapter,
  RoleBasedGuard
} from '@struktos/auth';

describe('Authentication Flow', () => {
  let authStore: InMemoryAuthStore;
  let tokenAdapter: JwtTokenAdapter;
  let passwordAdapter: BcryptPasswordAdapter;

  beforeEach(() => {
    authStore = new InMemoryAuthStore();
    tokenAdapter = new JwtTokenAdapter({
      secret: 'test-secret-key-32-characters-min',
      accessTokenExpiry: '1h'
    });
    passwordAdapter = new BcryptPasswordAdapter({
      defaultRounds: 4 // Lower rounds for faster tests
    });
  });

  afterEach(() => {
    authStore.clear(); // Reset store between tests
    tokenAdapter.clearRevokedTokens();
  });

  it('should register and authenticate user', async () => {
    // Register
    const passwordHash = await passwordAdapter.hash('TestPass123!');
    const user = await authStore.createUser({
      username: 'testuser',
      email: 'test@example.com',
      passwordHash
    });

    expect(user.id).toBeDefined();

    // Authenticate
    const storedUser = await authStore.findUserByUsername('testuser');
    const isValid = await passwordAdapter.verify('TestPass123!', storedUser!.passwordHash);
    expect(isValid).toBe(true);

    // Generate token
    const tokens = await tokenAdapter.generateTokenPair(storedUser!);
    expect(tokens.accessToken.token).toBeDefined();

    // Verify token
    const payload = await tokenAdapter.verifyToken(tokens.accessToken.token);
    expect(payload.sub).toBe(user.id);
  });

  it('should enforce role-based access', async () => {
    const user = await authStore.createUser({
      username: 'admin',
      email: 'admin@example.com',
      passwordHash: 'hash'
    });

    await authStore.addUserToRole(user.id, 'Admin');
    const updatedUser = await authStore.findUserById(user.id);

    const adminGuard = new RoleBasedGuard(['Admin']);
    const result = await adminGuard.canActivate({
      user: updatedUser!,
      resource: null,
      action: 'access'
    });

    expect(result.allowed).toBe(true);
  });
});
```

## 📚 API Reference

### Interfaces

| Interface | Description |
|-----------|-------------|
| `IAuthService` | Core authentication service contract |
| `IAuthStore` | Database-agnostic storage interface |
| `IAuthGuard` | Authorization guard interface |
| `ITokenPort` | JWT token operations port |
| `IPasswordPort` | Password hashing operations port |

### Models

| Model | Description |
|-------|-------------|
| `User` | Base user entity (C# IdentityUser inspired) |
| `Role` | Role definition with optional claims |
| `Claim` | Type/value pair for permissions |
| `TokenPayload` | JWT token payload structure |
| `AuthenticationResult` | Login/register response |

### Middleware

| Middleware | Description |
|------------|-------------|
| `AuthMiddleware` | JWT authentication with context injection |
| `RolesMiddleware` | Role-based authorization |
| `ClaimsMiddleware` | Claims-based authorization |
| `GuardMiddleware` | Custom guard-based authorization |

### Factory Functions

```typescript
// Middleware factories
createAuthMiddleware(authService, options?)
createOptionalAuthMiddleware(authService, options?)
requireRoles(...roles: string[])
requireAllRoles(...roles: string[])
requireClaim(type: string, value?: string)
requireClaims(...claims: ClaimRequirement[])
createAuthorizeMiddleware(guard: IAuthGuard)

// Adapter factories
createJwtTokenAdapter(options: JwtAdapterOptions)
createBcryptPasswordAdapter(options?: BcryptAdapterOptions)
```

## 🔗 Related Packages

| Package | Description |
|---------|-------------|
| [@struktos/core](https://www.npmjs.com/package/@struktos/core) | Context propagation, caching, enterprise patterns |
| [@struktos/adapter-express](https://www.npmjs.com/package/@struktos/adapter-express) | Express.js integration |
| [@struktos/adapter-fastify](https://www.npmjs.com/package/@struktos/adapter-fastify) | Fastify integration |
| [@struktos/adapter-nestjs](https://www.npmjs.com/package/@struktos/adapter-nestjs) | NestJS integration |
| [@struktos/prisma](https://www.npmjs.com/package/@struktos/prisma) | Prisma database adapter |

## 🗺️ Roadmap

- [ ] OAuth2/OIDC Support
- [ ] Two-Factor Authentication (2FA)
- [ ] Session Management
- [ ] Rate Limiting Integration
- [ ] Audit Logging
- [ ] Multi-Tenant Enhancements

## 📄 License

MIT © Struktos Contributors

## 🔗 Links

- [Documentation](https://struktos.dev/auth)
- [GitHub Repository](https://github.com/struktos/auth)
- [NPM Package](https://www.npmjs.com/package/@struktos/auth)
- [Changelog](./CHANGELOG.md)
- [Issue Tracker](https://github.com/struktos/auth/issues)