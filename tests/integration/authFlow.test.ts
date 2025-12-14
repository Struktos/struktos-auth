/**
 * Integration Tests - Full Authentication Flow
 */

import { InMemoryAuthStore } from '../../src/interfaces/IAuthStore';
import { JwtTokenAdapter } from '../../src/adapters/jwt-token.adapter';
import { BcryptPasswordAdapter } from '../../src/adapters/bcrypt-password.adapter';
import {
  RoleBasedGuard,
  ClaimBasedGuard,
  CompositeGuard,
} from '../../src/interfaces/IAuthGuard';
import { User } from '../../src/models/auth.models';

describe('Integration Tests', () => {
  let authStore: InMemoryAuthStore;
  let tokenAdapter: JwtTokenAdapter;
  let passwordAdapter: BcryptPasswordAdapter;

  const TEST_SECRET = 'integration-test-secret-key-32-chars';

  beforeEach(() => {
    authStore = new InMemoryAuthStore();
    tokenAdapter = new JwtTokenAdapter({
      secret: TEST_SECRET,
      accessTokenExpiry: '1h',
      refreshTokenExpiry: '7d',
      issuer: 'test-app',
      audience: 'test-api',
    });
    passwordAdapter = new BcryptPasswordAdapter({
      defaultRounds: 4, // Fast for tests
    });
  });

  afterEach(() => {
    authStore.clear();
    tokenAdapter.clearRevokedTokens();
  });

  // ==================== Full Auth Flow ====================

  describe('Complete Authentication Flow', () => {
    it('should complete full registration and login flow', async () => {
      // Step 1: Register a new user
      const password = 'SecurePass123!';
      const passwordHash = await passwordAdapter.hash(password);

      const user = await authStore.createUser({
        username: 'newuser',
        email: 'newuser@example.com',
        passwordHash,
        emailConfirmed: false,
        lockoutEnabled: true,
        accessFailedCount: 0,
      });

      expect(user.id).toBeDefined();
      expect(user.username).toBe('newuser');

      // Step 2: Login - verify password
      const storedUser = await authStore.findUserByUsername('newuser');
      expect(storedUser).not.toBeNull();

      const isPasswordValid = await passwordAdapter.verify(
        password,
        storedUser!.passwordHash
      );
      expect(isPasswordValid).toBe(true);

      // Step 3: Generate tokens
      const tokens = await tokenAdapter.generateTokenPair(storedUser!);
      expect(tokens.accessToken.token).toBeDefined();
      expect(tokens.refreshToken.token).toBeDefined();

      // Step 4: Verify access token
      const payload = await tokenAdapter.verifyToken(tokens.accessToken.token);
      expect(payload.sub).toBe(user.id);
      expect(payload.username).toBe(user.username);

      // Step 5: Use refresh token
      const refreshPayload = await tokenAdapter.verifyToken(tokens.refreshToken.token);
      expect(refreshPayload.sub).toBe(user.id);
      expect(refreshPayload.type).toBe('refresh');
    });

    it('should reject login with wrong password', async () => {
      const passwordHash = await passwordAdapter.hash('correctpassword');

      await authStore.createUser({
        username: 'testuser',
        email: 'test@example.com',
        passwordHash,
      });

      const user = await authStore.findUserByUsername('testuser');
      const isValid = await passwordAdapter.verify('wrongpassword', user!.passwordHash);

      expect(isValid).toBe(false);
    });
  });

  // ==================== Role-Based Access ====================

  describe('Role-Based Access Control', () => {
    let adminUser: User;
    let regularUser: User;
    let moderatorUser: User;

    beforeEach(async () => {
      // Create users
      adminUser = await authStore.createUser({
        username: 'admin',
        email: 'admin@example.com',
        passwordHash: 'hash',
      });
      await authStore.addUserToRole(adminUser.id, 'Admin');
      await authStore.addUserToRole(adminUser.id, 'User');
      adminUser = (await authStore.findUserById(adminUser.id))!;

      regularUser = await authStore.createUser({
        username: 'regular',
        email: 'regular@example.com',
        passwordHash: 'hash',
      });
      await authStore.addUserToRole(regularUser.id, 'User');
      regularUser = (await authStore.findUserById(regularUser.id))!;

      moderatorUser = await authStore.createUser({
        username: 'moderator',
        email: 'moderator@example.com',
        passwordHash: 'hash',
      });
      await authStore.addUserToRole(moderatorUser.id, 'Moderator');
      await authStore.addUserToRole(moderatorUser.id, 'User');
      moderatorUser = (await authStore.findUserById(moderatorUser.id))!;
    });

    it('should include roles in JWT token', async () => {
      const tokens = await tokenAdapter.generateTokenPair(adminUser);
      const payload = await tokenAdapter.verifyToken(tokens.accessToken.token);

      expect(payload.roles).toContain('Admin');
      expect(payload.roles).toContain('User');
    });

    it('should authorize admin for admin-only resources', async () => {
      const guard = new RoleBasedGuard(['Admin']);
      const context = { resource: 'admin-panel', action: 'access' };

      const adminResult = await guard.authorize(adminUser, context);
      const regularResult = await guard.authorize(regularUser, context);
      const modResult = await guard.authorize(moderatorUser, context);

      expect(adminResult.granted).toBe(true);
      expect(regularResult.granted).toBe(false);
      expect(modResult.granted).toBe(false);
    });

    it('should authorize multiple roles (OR logic)', async () => {
      const guard = new RoleBasedGuard(['Admin', 'Moderator']);
      const context = { resource: 'moderation', action: 'access' };

      expect((await guard.authorize(adminUser, context)).granted).toBe(true);
      expect((await guard.authorize(moderatorUser, context)).granted).toBe(true);
      expect((await guard.authorize(regularUser, context)).granted).toBe(false);
    });
  });

  // ==================== Claims-Based Access ====================

  describe('Claims-Based Access Control', () => {
    let userWithClaims: User;
    let userWithoutClaims: User;

    beforeEach(async () => {
      userWithClaims = await authStore.createUser({
        username: 'claimuser',
        email: 'claim@example.com',
        passwordHash: 'hash',
      });

      // Add various claims
      await authStore.addUserClaim(userWithClaims.id, {
        type: 'permission',
        value: 'read:documents',
      });
      await authStore.addUserClaim(userWithClaims.id, {
        type: 'permission',
        value: 'write:documents',
      });
      await authStore.addUserClaim(userWithClaims.id, {
        type: 'department',
        value: 'engineering',
      });
      await authStore.addUserClaim(userWithClaims.id, {
        type: 'subscription',
        value: 'premium',
      });

      userWithClaims = (await authStore.findUserById(userWithClaims.id))!;

      userWithoutClaims = await authStore.createUser({
        username: 'noclaimuser',
        email: 'noclaim@example.com',
        passwordHash: 'hash',
      });
    });

    it('should include claims in JWT token', async () => {
      const tokens = await tokenAdapter.generateTokenPair(userWithClaims);
      const payload = await tokenAdapter.verifyToken(tokens.accessToken.token);

      expect(payload.claims).toHaveLength(4);
      expect(payload.claims).toContainEqual({
        type: 'permission',
        value: 'read:documents',
      });
    });

    it('should authorize based on claim type', async () => {
      const guard = new ClaimBasedGuard('subscription');
      const context = { resource: 'premium-feature', action: 'use' };

      expect((await guard.authorize(userWithClaims, context)).granted).toBe(true);
      expect((await guard.authorize(userWithoutClaims, context)).granted).toBe(false);
    });

    it('should authorize based on claim type and value', async () => {
      const premiumGuard = new ClaimBasedGuard('subscription', 'premium');
      const basicGuard = new ClaimBasedGuard('subscription', 'basic');
      const context = { resource: 'feature', action: 'use' };

      expect((await premiumGuard.authorize(userWithClaims, context)).granted).toBe(true);
      expect((await basicGuard.authorize(userWithClaims, context)).granted).toBe(false);
    });
  });

  // ==================== Account Lockout ====================

  describe('Account Lockout', () => {
    it('should track failed login attempts', async () => {
      const user = await authStore.createUser({
        username: 'locktest',
        email: 'lock@example.com',
        passwordHash: await passwordAdapter.hash('correctpassword'),
        accessFailedCount: 0,
        lockoutEnabled: true,
      });

      // Simulate 3 failed attempts
      await authStore.incrementAccessFailedCount(user.id);
      await authStore.incrementAccessFailedCount(user.id);
      await authStore.incrementAccessFailedCount(user.id);

      const updatedUser = await authStore.findUserById(user.id);
      expect(updatedUser!.accessFailedCount).toBe(3);
    });

    it('should lockout user after max attempts', async () => {
      const maxAttempts = 5;
      const lockoutDuration = 15 * 60 * 1000; // 15 minutes

      const user = await authStore.createUser({
        username: 'locktest',
        email: 'lock@example.com',
        passwordHash: await passwordAdapter.hash('correctpassword'),
        accessFailedCount: 0,
        lockoutEnabled: true,
      });

      // Simulate reaching max attempts
      for (let i = 0; i < maxAttempts; i++) {
        const count = await authStore.incrementAccessFailedCount(user.id);
        if (count >= maxAttempts) {
          await authStore.setLockoutEnd(
            user.id,
            new Date(Date.now() + lockoutDuration)
          );
        }
      }

      const lockedUser = await authStore.findUserById(user.id);
      expect(lockedUser!.lockoutEnd).toBeDefined();
      expect(lockedUser!.lockoutEnd!.getTime()).toBeGreaterThan(Date.now());
    });

    it('should reset failed count on successful login', async () => {
      const user = await authStore.createUser({
        username: 'resettest',
        email: 'reset@example.com',
        passwordHash: await passwordAdapter.hash('password'),
        accessFailedCount: 3,
        lockoutEnabled: true,
      });

      // Successful login resets count
      await authStore.resetAccessFailedCount(user.id);

      const resetUser = await authStore.findUserById(user.id);
      expect(resetUser!.accessFailedCount).toBe(0);
    });

    it('should clear lockout on successful login', async () => {
      const user = await authStore.createUser({
        username: 'cleartest',
        email: 'clear@example.com',
        passwordHash: await passwordAdapter.hash('password'),
        lockoutEnd: new Date(Date.now() + 1000000),
      });

      // Successful login clears lockout
      await authStore.setLockoutEnd(user.id, null);
      await authStore.resetAccessFailedCount(user.id);

      const clearedUser = await authStore.findUserById(user.id);
      expect(clearedUser!.lockoutEnd).toBeNull();
    });
  });

  // ==================== Token Lifecycle ====================

  describe('Token Lifecycle', () => {
    it('should invalidate access after logout (token revocation)', async () => {
      const user = await authStore.createUser({
        username: 'logouttest',
        email: 'logout@example.com',
        passwordHash: 'hash',
      });

      // Generate tokens
      const tokens = await tokenAdapter.generateTokenPair(user);

      // Verify token works
      await expect(
        tokenAdapter.verifyToken(tokens.accessToken.token)
      ).resolves.toBeDefined();

      // Logout (revoke token)
      await tokenAdapter.revokeToken(tokens.accessToken.token);

      // Token should now be rejected
      await expect(
        tokenAdapter.verifyToken(tokens.accessToken.token)
      ).rejects.toThrow();
    });

    it('should allow refresh token to get new access token', async () => {
      const user = await authStore.createUser({
        username: 'refreshtest',
        email: 'refresh@example.com',
        passwordHash: 'hash',
      });

      // Generate initial tokens
      const initialTokens = await tokenAdapter.generateTokenPair(user);

      // Verify refresh token
      const refreshPayload = await tokenAdapter.verifyToken(
        initialTokens.refreshToken.token
      );
      expect(refreshPayload.type).toBe('refresh');

      // Use refresh token to get user and generate new access token
      const refreshedUser = await authStore.findUserById(refreshPayload.sub);
      expect(refreshedUser).not.toBeNull();

      const newAccessToken = await tokenAdapter.generateAccessToken(refreshedUser!);
      const newPayload = await tokenAdapter.verifyToken(newAccessToken.token);

      expect(newPayload.sub).toBe(user.id);
      expect(newPayload.type).toBe('access');
    });
  });

  // ==================== Complex Authorization ====================

  describe('Complex Authorization Scenarios', () => {
    it('should handle department + role combination', async () => {
      // Create engineering admin
      const engAdmin = await authStore.createUser({
        username: 'engadmin',
        email: 'engadmin@example.com',
        passwordHash: 'hash',
      });
      await authStore.addUserToRole(engAdmin.id, 'Admin');
      await authStore.addUserClaim(engAdmin.id, {
        type: 'department',
        value: 'engineering',
      });
      const engAdminUser = (await authStore.findUserById(engAdmin.id))!;

      // Create sales admin
      const salesAdmin = await authStore.createUser({
        username: 'salesadmin',
        email: 'salesadmin@example.com',
        passwordHash: 'hash',
      });
      await authStore.addUserToRole(salesAdmin.id, 'Admin');
      await authStore.addUserClaim(salesAdmin.id, {
        type: 'department',
        value: 'sales',
      });
      const salesAdminUser = (await authStore.findUserById(salesAdmin.id))!;

      // Engineering resource guard
      const engResourceGuard = new CompositeGuard(
        [
          new RoleBasedGuard(['Admin']),
          new ClaimBasedGuard('department', 'engineering'),
        ],
        'AND'
      );

      const context = { resource: 'engineering-data', action: 'read' };

      expect((await engResourceGuard.authorize(engAdminUser, context)).granted).toBe(
        true
      );
      expect((await engResourceGuard.authorize(salesAdminUser, context)).granted).toBe(
        false
      );
    });

    it('should handle tiered access (free/premium/enterprise)', async () => {
      const createUserWithTier = async (username: string, tier: string) => {
        const user = await authStore.createUser({
          username,
          email: `${username}@example.com`,
          passwordHash: 'hash',
        });
        await authStore.addUserClaim(user.id, { type: 'tier', value: tier });
        return (await authStore.findUserById(user.id))!;
      };

      const freeUser = await createUserWithTier('freeuser', 'free');
      const premiumUser = await createUserWithTier('premiumuser', 'premium');
      const enterpriseUser = await createUserWithTier('enterpriseuser', 'enterprise');

      // Basic feature - all tiers
      const basicGuard = new CompositeGuard(
        [
          new ClaimBasedGuard('tier', 'free'),
          new ClaimBasedGuard('tier', 'premium'),
          new ClaimBasedGuard('tier', 'enterprise'),
        ],
        'OR'
      );

      // Premium feature
      const premiumGuard = new CompositeGuard(
        [
          new ClaimBasedGuard('tier', 'premium'),
          new ClaimBasedGuard('tier', 'enterprise'),
        ],
        'OR'
      );

      // Enterprise feature
      const enterpriseGuard = new ClaimBasedGuard('tier', 'enterprise');

      const context = { resource: 'feature', action: 'use' };

      // Basic feature - all can access
      expect((await basicGuard.authorize(freeUser, context)).granted).toBe(true);
      expect((await basicGuard.authorize(premiumUser, context)).granted).toBe(true);
      expect((await basicGuard.authorize(enterpriseUser, context)).granted).toBe(true);

      // Premium feature - free cannot access
      expect((await premiumGuard.authorize(freeUser, context)).granted).toBe(false);
      expect((await premiumGuard.authorize(premiumUser, context)).granted).toBe(true);
      expect((await premiumGuard.authorize(enterpriseUser, context)).granted).toBe(
        true
      );

      // Enterprise feature - only enterprise
      expect((await enterpriseGuard.authorize(freeUser, context)).granted).toBe(false);
      expect((await enterpriseGuard.authorize(premiumUser, context)).granted).toBe(
        false
      );
      expect((await enterpriseGuard.authorize(enterpriseUser, context)).granted).toBe(
        true
      );
    });
  });
});