/**
 * Authorization Guards Unit Tests
 */

import {
  AuthorizationContext,
  RoleBasedGuard,
  ClaimBasedGuard,
  ResourceBasedGuard,
  OwnerBasedGuard,
  CompositeGuard,
  ConditionalGuard,
} from '../../src/interfaces/IAuthGuard';
import { User } from '../../src/models/auth.models';

describe('Authorization Guards', () => {
  // Helper to create test users
  const createUser = (overrides: Partial<User> = {}): User => ({
    id: 'user-123',
    username: 'testuser',
    email: 'test@example.com',
    passwordHash: 'hash',
    roles: ['User'],
    claims: [],
    ...overrides,
  });

  // Helper to create authorization context
  const createContext = (overrides: Partial<AuthorizationContext> = {}): AuthorizationContext => ({
    resource: 'document',
    action: 'read',
    ...overrides,
  });

  // ==================== RoleBasedGuard ====================

  describe('RoleBasedGuard', () => {
    describe('OR logic (default)', () => {
      it('should grant access if user has one of required roles', async () => {
        const guard = new RoleBasedGuard(['Admin', 'Moderator']);
        const user = createUser({ roles: ['User', 'Moderator'] });

        const result = await guard.authorize(user, createContext());

        expect(result.granted).toBe(true);
      });

      it('should deny access if user has none of required roles', async () => {
        const guard = new RoleBasedGuard(['Admin', 'SuperAdmin']);
        const user = createUser({ roles: ['User', 'Moderator'] });

        const result = await guard.authorize(user, createContext());

        expect(result.granted).toBe(false);
        expect(result.reason).toContain('Admin');
        expect(result.reason).toContain('SuperAdmin');
      });

      it('should deny access if user has no roles', async () => {
        const guard = new RoleBasedGuard(['Admin']);
        const user = createUser({ roles: [] });

        const result = await guard.authorize(user, createContext());

        expect(result.granted).toBe(false);
        expect(result.reason).toContain('no roles assigned');
      });

      it('should deny access if roles is undefined', async () => {
        const guard = new RoleBasedGuard(['Admin']);
        const user = createUser({ roles: undefined });

        const result = await guard.authorize(user, createContext());

        expect(result.granted).toBe(false);
      });
    });

    describe('AND logic', () => {
      it('should grant access if user has all required roles', async () => {
        const guard = new RoleBasedGuard(['Admin', 'Moderator'], 'AND');
        const user = createUser({ roles: ['Admin', 'Moderator', 'User'] });

        const result = await guard.authorize(user, createContext());

        expect(result.granted).toBe(true);
      });

      it('should deny access if user missing any required role', async () => {
        const guard = new RoleBasedGuard(['Admin', 'SuperAdmin'], 'AND');
        const user = createUser({ roles: ['Admin', 'User'] });

        const result = await guard.authorize(user, createContext());

        expect(result.granted).toBe(false);
        expect(result.reason).toContain('all of');
      });
    });
  });

  // ==================== ClaimBasedGuard ====================

  describe('ClaimBasedGuard', () => {
    describe('with claim type only', () => {
      it('should grant access if user has claim of type', async () => {
        const guard = new ClaimBasedGuard('permission');
        const user = createUser({
          claims: [{ type: 'permission', value: 'read:users' }],
        });

        const result = await guard.authorize(user, createContext());

        expect(result.granted).toBe(true);
      });

      it('should deny access if user lacks claim type', async () => {
        const guard = new ClaimBasedGuard('admin-access');
        const user = createUser({
          claims: [{ type: 'permission', value: 'read:users' }],
        });

        const result = await guard.authorize(user, createContext());

        expect(result.granted).toBe(false);
        expect(result.reason).toContain('admin-access');
      });
    });

    describe('with claim type and value', () => {
      it('should grant access if user has exact claim', async () => {
        const guard = new ClaimBasedGuard('permission', 'write:documents');
        const user = createUser({
          claims: [
            { type: 'permission', value: 'read:users' },
            { type: 'permission', value: 'write:documents' },
          ],
        });

        const result = await guard.authorize(user, createContext());

        expect(result.granted).toBe(true);
      });

      it('should deny access if value does not match', async () => {
        const guard = new ClaimBasedGuard('permission', 'write:documents');
        const user = createUser({
          claims: [{ type: 'permission', value: 'read:documents' }],
        });

        const result = await guard.authorize(user, createContext());

        expect(result.granted).toBe(false);
        expect(result.reason).toContain('write:documents');
      });
    });

    it('should deny access if user has no claims', async () => {
      const guard = new ClaimBasedGuard('permission');
      const user = createUser({ claims: [] });

      const result = await guard.authorize(user, createContext());

      expect(result.granted).toBe(false);
      expect(result.reason).toContain('no claims');
    });

    it('should deny access if claims is undefined', async () => {
      const guard = new ClaimBasedGuard('permission');
      const user = createUser({ claims: undefined });

      const result = await guard.authorize(user, createContext());

      expect(result.granted).toBe(false);
    });
  });

  // ==================== ResourceBasedGuard ====================

  describe('ResourceBasedGuard', () => {
    it('should grant access if user has matching permission claim', async () => {
      const guard = new ResourceBasedGuard();
      const user = createUser({
        claims: [{ type: 'permission', value: 'read:document' }],
      });
      const context = createContext({ action: 'read', resource: 'document' });

      const result = await guard.authorize(user, context);

      expect(result.granted).toBe(true);
    });

    it('should deny access if permission claim does not match', async () => {
      const guard = new ResourceBasedGuard();
      const user = createUser({
        claims: [{ type: 'permission', value: 'read:user' }],
      });
      const context = createContext({ action: 'read', resource: 'document' });

      const result = await guard.authorize(user, context);

      expect(result.granted).toBe(false);
      expect(result.reason).toContain('read:document');
    });

    it('should deny access if action does not match', async () => {
      const guard = new ResourceBasedGuard();
      const user = createUser({
        claims: [{ type: 'permission', value: 'read:document' }],
      });
      const context = createContext({ action: 'write', resource: 'document' });

      const result = await guard.authorize(user, context);

      expect(result.granted).toBe(false);
      expect(result.reason).toContain('write:document');
    });

    it('should deny access if user has no claims', async () => {
      const guard = new ResourceBasedGuard();
      const user = createUser({ claims: undefined });

      const result = await guard.authorize(user, createContext());

      expect(result.granted).toBe(false);
      expect(result.reason).toContain('no permissions');
    });
  });

  // ==================== OwnerBasedGuard ====================

  describe('OwnerBasedGuard', () => {
    describe('with default extractor (from metadata)', () => {
      it('should grant access if user is owner', async () => {
        const guard = new OwnerBasedGuard();
        const user = createUser({ id: 'user-123' });
        const context = createContext({
          metadata: { ownerId: 'user-123' },
        });

        const result = await guard.authorize(user, context);

        expect(result.granted).toBe(true);
      });

      it('should deny access if user is not owner', async () => {
        const guard = new OwnerBasedGuard();
        const user = createUser({ id: 'user-123' });
        const context = createContext({
          metadata: { ownerId: 'user-456' },
        });

        const result = await guard.authorize(user, context);

        expect(result.granted).toBe(false);
        expect(result.reason).toContain('not the owner');
      });

      it('should deny access if owner cannot be determined', async () => {
        const guard = new OwnerBasedGuard();
        const user = createUser();
        const context = createContext({
          metadata: {},
        });

        const result = await guard.authorize(user, context);

        expect(result.granted).toBe(false);
        expect(result.reason).toContain('Cannot determine');
      });
    });

    describe('with custom extractor', () => {
      it('should use custom extractor to get owner id', async () => {
        const guard = new OwnerBasedGuard((ctx) => ctx.metadata?.createdBy as string);
        const user = createUser({ id: 'user-123' });
        const context = createContext({
          metadata: { createdBy: 'user-123' },
        });

        const result = await guard.authorize(user, context);

        expect(result.granted).toBe(true);
      });
    });
  });

  // ==================== CompositeGuard ====================

  describe('CompositeGuard', () => {
    describe('AND logic', () => {
      it('should grant access if all guards pass', async () => {
        const roleGuard = new RoleBasedGuard(['Admin']);
        const claimGuard = new ClaimBasedGuard('verified', 'true');

        const composite = new CompositeGuard([roleGuard, claimGuard], 'AND');

        const user = createUser({
          roles: ['Admin'],
          claims: [{ type: 'verified', value: 'true' }],
        });

        const result = await composite.authorize(user, createContext());

        expect(result.granted).toBe(true);
      });

      it('should deny access if any guard fails', async () => {
        const roleGuard = new RoleBasedGuard(['Admin']);
        const claimGuard = new ClaimBasedGuard('premium', 'true');

        const composite = new CompositeGuard([roleGuard, claimGuard], 'AND');

        const user = createUser({
          roles: ['Admin'],
          claims: [], // Missing premium claim
        });

        const result = await composite.authorize(user, createContext());

        expect(result.granted).toBe(false);
      });

      it('should combine failure reasons', async () => {
        const guard1 = new RoleBasedGuard(['Admin']);
        const guard2 = new ClaimBasedGuard('premium');

        const composite = new CompositeGuard([guard1, guard2], 'AND');

        const user = createUser({ roles: [], claims: [] });

        const result = await composite.authorize(user, createContext());

        expect(result.granted).toBe(false);
        expect(result.reason).toContain('roles');
        expect(result.reason).toContain('claims');
      });
    });

    describe('OR logic', () => {
      it('should grant access if any guard passes', async () => {
        const adminGuard = new RoleBasedGuard(['Admin']);
        const premiumGuard = new ClaimBasedGuard('subscription', 'premium');

        const composite = new CompositeGuard([adminGuard, premiumGuard], 'OR');

        const user = createUser({
          roles: ['User'],
          claims: [{ type: 'subscription', value: 'premium' }],
        });

        const result = await composite.authorize(user, createContext());

        expect(result.granted).toBe(true);
      });

      it('should deny access if all guards fail', async () => {
        const adminGuard = new RoleBasedGuard(['Admin']);
        const premiumGuard = new ClaimBasedGuard('subscription', 'premium');

        const composite = new CompositeGuard([adminGuard, premiumGuard], 'OR');

        const user = createUser({
          roles: ['User'],
          claims: [{ type: 'subscription', value: 'free' }],
        });

        const result = await composite.authorize(user, createContext());

        expect(result.granted).toBe(false);
      });
    });

    it('should support nested composite guards', async () => {
      const roleGuard = new RoleBasedGuard(['Admin', 'SuperAdmin'], 'OR');
      const claimGuard1 = new ClaimBasedGuard('department', 'engineering');
      const claimGuard2 = new ClaimBasedGuard('level', 'senior');

      const claimComposite = new CompositeGuard([claimGuard1, claimGuard2], 'AND');
      const mainComposite = new CompositeGuard([roleGuard, claimComposite], 'OR');

      // User with Admin role (passes)
      const adminUser = createUser({ roles: ['Admin'] });
      expect((await mainComposite.authorize(adminUser, createContext())).granted).toBe(true);

      // User with both claims (passes)
      const seniorEngineer = createUser({
        roles: ['User'],
        claims: [
          { type: 'department', value: 'engineering' },
          { type: 'level', value: 'senior' },
        ],
      });
      expect((await mainComposite.authorize(seniorEngineer, createContext())).granted).toBe(true);

      // User with neither (fails)
      const regularUser = createUser({ roles: ['User'], claims: [] });
      expect((await mainComposite.authorize(regularUser, createContext())).granted).toBe(false);
    });
  });

  // ==================== ConditionalGuard ====================

  describe('ConditionalGuard', () => {
    it('should grant access if condition returns true', async () => {
      const guard = new ConditionalGuard(
        (user) => user.email.endsWith('@company.com'),
        'Must have company email'
      );

      const user = createUser({ email: 'john@company.com' });

      const result = await guard.authorize(user, createContext());

      expect(result.granted).toBe(true);
    });

    it('should deny access if condition returns false', async () => {
      const guard = new ConditionalGuard(
        (user) => user.email.endsWith('@company.com'),
        'Must have company email'
      );

      const user = createUser({ email: 'john@gmail.com' });

      const result = await guard.authorize(user, createContext());

      expect(result.granted).toBe(false);
      expect(result.reason).toBe('Must have company email');
    });

    it('should support async conditions', async () => {
      const guard = new ConditionalGuard(
        async (user, ctx): Promise<boolean> => {
          // Simulate async check
          await new Promise((resolve) => setTimeout(resolve, 10));
          return ctx.resource === 'public' || (user.roles?.includes('Admin') ?? false);
        },
        'Access denied'
      );

      const adminUser = createUser({ roles: ['Admin'] });
      const regularUser = createUser({ roles: ['User'] });

      const adminResult = await guard.authorize(adminUser, createContext());
      expect(adminResult.granted).toBe(true);

      const publicResult = await guard.authorize(
        regularUser,
        createContext({ resource: 'public' })
      );
      expect(publicResult.granted).toBe(true);

      const privateResult = await guard.authorize(
        regularUser,
        createContext({ resource: 'private' })
      );
      expect(privateResult.granted).toBe(false);
    });

    it('should use context in condition', async () => {
      const guard = new ConditionalGuard((user, ctx) => {
        // Only owners can delete
        if (ctx.action === 'delete') {
          return ctx.metadata?.ownerId === user.id;
        }
        return true;
      }, 'Only owners can delete');

      const user = createUser({ id: 'user-123' });

      // Can read
      const readResult = await guard.authorize(
        user,
        createContext({ action: 'read' })
      );
      expect(readResult.granted).toBe(true);

      // Can delete own resource
      const deleteOwnResult = await guard.authorize(
        user,
        createContext({ action: 'delete', metadata: { ownerId: 'user-123' } })
      );
      expect(deleteOwnResult.granted).toBe(true);

      // Cannot delete others' resource
      const deleteOtherResult = await guard.authorize(
        user,
        createContext({ action: 'delete', metadata: { ownerId: 'user-456' } })
      );
      expect(deleteOtherResult.granted).toBe(false);
    });
  });

  // ==================== Edge Cases ====================

  describe('Edge Cases', () => {
    it('should handle user with empty strings in roles', async () => {
      const guard = new RoleBasedGuard(['Admin']);
      const user = createUser({ roles: ['', 'User'] });

      const result = await guard.authorize(user, createContext());

      expect(result.granted).toBe(false);
    });

    it('should handle claims with empty values', async () => {
      const guard = new ClaimBasedGuard('permission', '');
      const user = createUser({
        claims: [{ type: 'permission', value: '' }],
      });

      const result = await guard.authorize(user, createContext());

      expect(result.granted).toBe(true);
    });

    it('should handle context without metadata', async () => {
      const guard = new OwnerBasedGuard();
      const user = createUser();
      const context: AuthorizationContext = {
        resource: 'test',
        action: 'read',
        // No metadata
      };

      const result = await guard.authorize(user, context);

      expect(result.granted).toBe(false);
    });
  });
});