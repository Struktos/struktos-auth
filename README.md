# @struktos/auth

> C# Identity-inspired authentication and authorization for Node.js

[![npm version](https://img.shields.io/npm/v/@struktos/auth.svg)](https://www.npmjs.com/package/@struktos/auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🎯 What is this?

`@struktos/auth` brings C# ASP.NET Identity's powerful authentication and authorization patterns to Node.js, seamlessly integrated with [@struktos/core](https://www.npmjs.com/package/@struktos/core).

**Key Features:**

- ✅ **JWT Authentication** - Secure token-based authentication with automatic validation
- ✅ **Role-Based Access Control (RBAC)** - Simple and powerful role management
- ✅ **Claims-Based Authorization** - Fine-grained permissions like C# Identity
- ✅ **Database-Agnostic** - Works with any database through `IAuthStore` interface
- ✅ **Context Integration** - Automatic user injection into @struktos/core Context
- ✅ **High-Performance Caching** - Token and claims caching with CacheManager
- ✅ **Account Lockout** - Automatic protection against brute-force attacks
- ✅ **Full TypeScript Support** - Complete type safety with generics

## 📦 Installation

```bash
npm install @struktos/core @struktos/auth jsonwebtoken bcryptjs
```

## 🚀 Quick Start

### 1. Initialize Auth Service

```typescript
import { AuthService, InMemoryAuthStore } from '@struktos/auth';

const authStore = new InMemoryAuthStore();
const authService = new AuthService(authStore, {
  jwtSecret: 'your-super-secret-key',
  jwtExpiresIn: '1h',
  enableTokenCache: true,
  enableClaimsCache: true
});
```

### 2. Add Authentication Middleware

```typescript
import express from 'express';
import { createStruktosMiddleware } from '@struktos/adapter-express';
import { createAuthenticateMiddleware } from '@struktos/auth';

const app = express();

// Context middleware (required)
app.use(createStruktosMiddleware());

// Authentication middleware
const authenticate = createAuthenticateMiddleware(authService);

// Protected route
app.get('/api/profile', authenticate, (req, res) => {
  res.json({ user: req.user });
});
```

### 3. Register and Login

```typescript
// Register
app.post('/auth/register', async (req, res) => {
  const result = await authService.register({
    username: req.body.username,
    email: req.body.email,
    password: req.body.password
  });
  
  if (result.success) {
    res.json({
      accessToken: result.accessToken,
      refreshToken: result.refreshToken
    });
  } else {
    res.status(400).json({ error: result.error });
  }
});

// Login
app.post('/auth/login', async (req, res) => {
  const result = await authService.login({
    username: req.body.username,
    password: req.body.password
  });
  
  if (result.success) {
    res.json({
      accessToken: result.accessToken,
      user: result.user
    });
  } else {
    res.status(401).json({ error: result.error });
  }
});
```

## 🔐 Authorization

### Role-Based Authorization

```typescript
import { requireRoles } from '@struktos/auth';

// Require Admin role
app.get('/api/admin/users', 
  authenticate, 
  requireRoles('Admin'), 
  (req, res) => {
    res.json({ users: [...] });
  }
);

// Require any of multiple roles
app.get('/api/moderation/reports', 
  authenticate,
  requireRoles('Moderator', 'Admin'),
  (req, res) => {
    res.json({ reports: [...] });
  }
);
```

### Claims-Based Authorization

```typescript
import { requireClaim } from '@struktos/auth';

// Require specific permission claim
app.post('/api/documents', 
  authenticate,
  requireClaim('permission', 'write:documents'),
  (req, res) => {
    res.status(201).json({ document: {...} });
  }
);

// Check for claim type only
app.get('/api/beta-features',
  authenticate,
  requireClaim('feature', 'beta-access'),
  (req, res) => {
    res.json({ features: [...] });
  }
);
```

### Custom Authorization Guards

```typescript
import { 
  createAuthorizeMiddleware, 
  RoleBasedGuard, 
  ClaimBasedGuard,
  CompositeGuard 
} from '@struktos/auth';

// Create composite guard (AND logic)
const guard = new CompositeGuard([
  new RoleBasedGuard(['Admin']),
  new ClaimBasedGuard('department', 'engineering')
], 'AND');

app.delete('/api/critical-resource/:id',
  authenticate,
  createAuthorizeMiddleware(guard),
  (req, res) => {
    res.json({ deleted: true });
  }
);
```

## 📚 Core Concepts

### User Model

```typescript
interface User {
  id: string;
  username: string;
  email: string;
  passwordHash: string;
  roles?: string[];
  claims?: Claim[];
  emailConfirmed?: boolean;
  twoFactorEnabled?: boolean;
  lockoutEnd?: Date | null;
  lockoutEnabled?: boolean;
  accessFailedCount?: number;
}
```

### Roles

```typescript
// Add role to user
await authStore.addUserToRole(userId, 'Admin');

// Check if user has role
const isAdmin = await authStore.isUserInRole(userId, 'Admin');

// Get all user roles
const roles = await authStore.getUserRoles(userId);
```

### Claims

```typescript
// Add claim to user
await authStore.addUserClaim(userId, {
  type: 'permission',
  value: 'write:documents'
});

// Check if user has claim
const hasClaim = await authStore.hasUserClaim(
  userId, 
  'permission', 
  'write:documents'
);

// Get all user claims
const claims = await authStore.getUserClaims(userId);
```

## 🗄️ Database Integration

Implement `IAuthStore` for your database:

```typescript
import { IAuthStore, User } from '@struktos/auth';
import { PrismaClient } from '@prisma/client';

class PrismaAuthStore implements IAuthStore<User> {
  constructor(private prisma: PrismaClient) {}
  
  async findUserById(userId: string): Promise<User | null> {
    return await this.prisma.user.findUnique({
      where: { id: userId },
      include: { roles: true, claims: true }
    });
  }
  
  async findUserByUsername(username: string): Promise<User | null> {
    return await this.prisma.user.findUnique({
      where: { username },
      include: { roles: true, claims: true }
    });
  }
  
  // ... implement other methods
}

// Use with AuthService
const authStore = new PrismaAuthStore(prisma);
const authService = new AuthService(authStore, options);
```

## ⚡ Performance Features

### Token Caching

```typescript
const authService = new AuthService(authStore, {
  jwtSecret: 'secret',
  enableTokenCache: true,
  tokenCacheTTL: 30 * 60 * 1000  // 30 minutes
});
```

### Claims Caching

```typescript
const authService = new AuthService(authStore, {
  jwtSecret: 'secret',
  enableClaimsCache: true,
  claimsCacheTTL: 15 * 60 * 1000  // 15 minutes
});
```

## 🔒 Security Features

### Account Lockout

```typescript
const authService = new AuthService(authStore, {
  jwtSecret: 'secret',
  maxAccessAttempts: 5,        // Lock after 5 failed attempts
  lockoutDuration: 15          // Lock for 15 minutes
});
```

### Password Hashing

Automatic bcrypt hashing with configurable rounds:

```typescript
const authService = new AuthService(authStore, {
  jwtSecret: 'secret',
  bcryptRounds: 12  // More rounds = more security, slower
});
```

### Password Change

```typescript
const success = await authService.changePassword(
  userId,
  currentPassword,
  newPassword
);
```

## 🔗 Context Integration

User automatically injected into @struktos/core Context:

```typescript
import { RequestContext } from '@struktos/core';

async function someBusinessLogic() {
  const ctx = RequestContext.current();
  const userId = ctx?.get('userId');
  const user = ctx?.get('user');
  
  console.log(`Processing request for user: ${userId}`);
}
```

## 📖 API Reference

### AuthService

```typescript
class AuthService<TUser extends User> {
  // Registration
  register(data: RegistrationData): Promise<AuthenticationResult>
  
  // Authentication
  login(credentials: LoginCredentials): Promise<AuthenticationResult>
  validateToken(token: string): Promise<TUser | null>
  
  // Context
  getCurrentUser(): TUser | undefined
  getCurrentUserId(): string | undefined
  
  // Password
  changePassword(userId, currentPassword, newPassword): Promise<boolean>
}
```

### Middleware

```typescript
// Authentication
createAuthenticateMiddleware(authService)
createOptionalAuthMiddleware(authService)

// Authorization
requireRoles(...roles: string[])
requireClaim(type: string, value?: string)
createAuthorizeMiddleware(guard: IAuthGuard)
```

### Guards

```typescript
// Built-in guards
new RoleBasedGuard(['Admin', 'Moderator'])
new ClaimBasedGuard('permission', 'write:documents')
new ResourceBasedGuard()
new CompositeGuard([guard1, guard2], 'AND' | 'OR')
```

## 🧪 Testing

```typescript
import { InMemoryAuthStore, AuthService } from '@struktos/auth';

describe('Authentication', () => {
  let authStore: InMemoryAuthStore;
  let authService: AuthService;
  
  beforeEach(() => {
    authStore = new InMemoryAuthStore();
    authService = new AuthService(authStore, {
      jwtSecret: 'test-secret'
    });
  });
  
  it('should register user', async () => {
    const result = await authService.register({
      username: 'test',
      email: 'test@example.com',
      password: 'password123'
    });
    
    expect(result.success).toBe(true);
    expect(result.accessToken).toBeDefined();
  });
});
```

## 📊 Architecture

```
HTTP Request with JWT
    ↓
createAuthenticateMiddleware
    ↓
Extract & Validate Token
    ↓
AuthService.validateToken()
    ↓
Check Cache → If miss → Verify JWT → Load User from Store
    ↓
Inject User into Context
    ↓
[Your Route Handlers]
    ↓
Authorization Guards (if configured)
    ↓
Check Roles/Claims
    ↓
Grant/Deny Access
```

## 🎯 Use Cases

### Basic Authentication

```typescript
// Registration and login with JWT tokens
const result = await authService.login(credentials);
// User automatically in Context for all subsequent operations
```

### Enterprise RBAC

```typescript
// Hierarchical role system
await authStore.addUserToRole(userId, 'Admin');
app.get('/admin/*', authenticate, requireRoles('Admin'), ...);
```

### Fine-Grained Permissions

```typescript
// Permission-based access control
await authStore.addUserClaim(userId, {
  type: 'permission',
  value: 'read:sensitive-data'
});
```

### Multi-Tenant Applications

```typescript
// Tenant-specific claims
await authStore.addUserClaim(userId, {
  type: 'tenant',
  value: 'acme-corp'
});
```

## 🤝 Related Packages

- **[@struktos/core](https://www.npmjs.com/package/@struktos/core)** - Context propagation and caching
- **[@struktos/adapter-express](https://www.npmjs.com/package/@struktos/adapter-express)** - Express integration
- **@struktos/adapter-fastify** (coming soon) - Fastify integration

## 📄 License

MIT © Struktos.js Team

## 🔗 Links

- [GitHub Repository](https://github.com/struktosjs/auth)
- [Issue Tracker](https://github.com/struktosjs/auth/issues)
- [NPM Package](https://www.npmjs.com/package/@struktos/auth)
- [@struktos/core Documentation](https://www.npmjs.com/package/@struktos/core)

---

**Built with ❤️ for enterprise Node.js security**