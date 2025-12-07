import express from 'express';
import { createStruktosMiddleware } from '@struktos/adapter-express';
import {
  AuthService,
  InMemoryAuthStore,
  createAuthenticateMiddleware,
  requireRoles,
  requireClaim,
  AuthenticatedRequest
} from '../src/index';

const app = express();
const PORT = 3000;

// Parse JSON bodies
app.use(express.json());

// Initialize Struktos Context middleware
app.use(createStruktosMiddleware({
  generateTraceId: () => `trace-${Date.now()}`
}));

// Initialize Auth Store and Auth Service
const authStore = new InMemoryAuthStore();
const authService = new AuthService(authStore, {
  jwtSecret: 'your-super-secret-key-change-in-production',
  jwtExpiresIn: '1h',
  refreshTokenExpiresIn: '7d',
  bcryptRounds: 10,
  enableTokenCache: true,
  enableClaimsCache: true,
  maxAccessAttempts: 5,
  lockoutDuration: 15
});

// Create authentication middleware
const authenticate = createAuthenticateMiddleware(authService);

// ==================== Public Routes ====================

/**
 * Register a new user
 */
app.post('/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Username, email, and password are required'
      });
    }
    
    const result = await authService.register({
      username,
      email,
      password
    });
    
    if (!result.success) {
      return res.status(400).json({
        error: 'Registration Failed',
        message: result.error
      });
    }
    
    res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: result.user?.id,
        username: result.user?.username,
        email: result.user?.email
      },
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      expiresIn: result.expiresIn
    });
  } catch (error) {
    res.status(500).json({
      error: 'Internal Server Error',
      message: error instanceof Error ? error.message : 'Registration failed'
    });
  }
});

/**
 * Login
 */
app.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Username and password are required'
      });
    }
    
    const result = await authService.login({ username, password });
    
    if (!result.success) {
      return res.status(401).json({
        error: 'Authentication Failed',
        message: result.error,
        isLockedOut: result.isLockedOut,
        requiresTwoFactor: result.requiresTwoFactor
      });
    }
    
    res.json({
      message: 'Login successful',
      user: {
        id: result.user?.id,
        username: result.user?.username,
        email: result.user?.email,
        roles: result.user?.roles
      },
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      expiresIn: result.expiresIn
    });
  } catch (error) {
    res.status(500).json({
      error: 'Internal Server Error',
      message: error instanceof Error ? error.message : 'Login failed'
    });
  }
});

// ==================== Protected Routes ====================

/**
 * Get current user profile
 * Requires authentication
 */
app.get('/api/profile', authenticate, (req: AuthenticatedRequest, res) => {
  const user = req.user;
  
  res.json({
    user: {
      id: user?.id,
      username: user?.username,
      email: user?.email,
      roles: user?.roles,
      claims: user?.claims
    }
  });
});

/**
 * Admin-only endpoint
 * Requires "Admin" role
 */
app.get('/api/admin/users', authenticate, requireRoles('Admin'), async (_req, res) => {
  // In real app, fetch users from database
  res.json({
    message: 'Welcome Admin!',
    users: [
      { id: '1', username: 'user1', email: 'user1@example.com' },
      { id: '2', username: 'user2', email: 'user2@example.com' }
    ]
  });
});

/**
 * Moderator or Admin endpoint
 * Requires either "Moderator" or "Admin" role
 */
app.get('/api/moderation/reports', 
  authenticate, 
  requireRoles('Moderator', 'Admin'), 
  async (_req, res) => {
    res.json({
      message: 'Moderation reports',
      reports: [
        { id: '1', type: 'spam', status: 'pending' },
        { id: '2', type: 'harassment', status: 'resolved' }
      ]
    });
  }
);

/**
 * Endpoint requiring specific permission
 * Requires claim: permission=write:documents
 */
app.post('/api/documents', 
  authenticate,
  requireClaim('permission', 'write:documents'),
  async (req: AuthenticatedRequest, res) => {
    const { title, content } = req.body;
    
    res.status(201).json({
      message: 'Document created',
      document: {
        id: `doc-${Date.now()}`,
        title,
        content,
        createdBy: req.user?.username
      }
    });
  }
);

// ==================== Admin Setup Routes ====================

/**
 * Assign role to user (for demo purposes)
 * In production, this would be protected
 */
app.post('/admin/users/:userId/roles', async (req, res) => {
  try {
    const { userId } = req.params;
    const { role } = req.body;
    
    if (!role) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Role is required'
      });
    }
    
    await authStore.addUserToRole(userId, role);
    
    res.json({
      message: `Role '${role}' assigned to user successfully`
    });
  } catch (error) {
    res.status(500).json({
      error: 'Internal Server Error',
      message: error instanceof Error ? error.message : 'Failed to assign role'
    });
  }
});

/**
 * Assign claim to user (for demo purposes)
 * In production, this would be protected
 */
app.post('/admin/users/:userId/claims', async (req, res) => {
  try {
    const { userId } = req.params;
    const { type, value } = req.body;
    
    if (!type || !value) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Claim type and value are required'
      });
    }
    
    await authStore.addUserClaim(userId, { type, value });
    
    res.json({
      message: `Claim '${type}=${value}' assigned to user successfully`
    });
  } catch (error) {
    res.status(500).json({
      error: 'Internal Server Error',
      message: error instanceof Error ? error.message : 'Failed to assign claim'
    });
  }
});

// ==================== Start Server ====================

app.listen(PORT, () => {
  console.log('═══════════════════════════════════════════════════════════');
  console.log('  Struktos Auth Example Application');
  console.log('  C# Identity-inspired Authentication & Authorization');
  console.log('═══════════════════════════════════════════════════════════');
  console.log(`\n🚀 Server running at http://localhost:${PORT}`);
  console.log('\n📋 Available endpoints:');
  console.log('\n  Public:');
  console.log('    POST /auth/register      - Register new user');
  console.log('    POST /auth/login         - Login');
  console.log('\n  Protected (requires JWT):');
  console.log('    GET  /api/profile        - Get current user profile');
  console.log('\n  Role-based:');
  console.log('    GET  /api/admin/users    - Admin only');
  console.log('    GET  /api/moderation/reports - Moderator or Admin');
  console.log('\n  Claim-based:');
  console.log('    POST /api/documents      - Requires permission=write:documents');
  console.log('\n  Admin:');
  console.log('    POST /admin/users/:userId/roles  - Assign role');
  console.log('    POST /admin/users/:userId/claims - Assign claim');
  console.log('\n💡 Try these commands:');
  console.log('\n  # Register a user');
  console.log('  curl -X POST http://localhost:3000/auth/register \\');
  console.log('    -H "Content-Type: application/json" \\');
  console.log('    -d \'{"username":"john","email":"john@example.com","password":"password123"}\'');
  console.log('\n  # Login');
  console.log('  curl -X POST http://localhost:3000/auth/login \\');
  console.log('    -H "Content-Type: application/json" \\');
  console.log('    -d \'{"username":"john","password":"password123"}\'');
  console.log('\n  # Get profile (use token from login response)');
  console.log('  curl http://localhost:3000/api/profile \\');
  console.log('    -H "Authorization: Bearer YOUR_TOKEN_HERE"');
  console.log('\n  # Assign Admin role');
  console.log('  curl -X POST http://localhost:3000/admin/users/USER_ID/roles \\');
  console.log('    -H "Content-Type: application/json" \\');
  console.log('    -d \'{"role":"Admin"}\'');
  console.log('\n  # Assign permission claim');
  console.log('  curl -X POST http://localhost:3000/admin/users/USER_ID/claims \\');
  console.log('    -H "Content-Type: application/json" \\');
  console.log('    -d \'{"type":"permission","value":"write:documents"}\'');
  console.log('═══════════════════════════════════════════════════════════\n');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('\n🛑 SIGTERM received, shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('\n🛑 SIGINT received, shutting down gracefully...');
  process.exit(0);
});