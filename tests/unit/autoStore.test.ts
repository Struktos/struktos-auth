/**
 * InMemoryAuthStore Unit Tests
 */

import { InMemoryAuthStore } from '../../src/interfaces/IAuthStore';
import { Claim } from '../../src/models/auth.models';

describe('InMemoryAuthStore', () => {
  let store: InMemoryAuthStore;

  beforeEach(() => {
    store = new InMemoryAuthStore();
  });

  afterEach(() => {
    store.clear();
  });

  // ==================== User CRUD ====================

  describe('User CRUD Operations', () => {
    const createTestUser = () => ({
      username: 'testuser',
      email: 'test@example.com',
      passwordHash: 'hashedpassword123',
      emailConfirmed: false,
      lockoutEnabled: true,
      accessFailedCount: 0,
    });

    describe('createUser', () => {
      it('should create a new user with auto-generated id', async () => {
        const userData = createTestUser();
        const user = await store.createUser(userData);

        expect(user.id).toBeDefined();
        expect(user.id).toMatch(/^user-\d+-\d+$/);
        expect(user.username).toBe(userData.username);
        expect(user.email).toBe(userData.email);
        expect(user.passwordHash).toBe(userData.passwordHash);
      });

      it('should set createdAt and updatedAt timestamps', async () => {
        const userData = createTestUser();
        const before = new Date();
        const user = await store.createUser(userData);
        const after = new Date();

        expect(user.createdAt).toBeDefined();
        expect(user.updatedAt).toBeDefined();
        expect(user.createdAt!.getTime()).toBeGreaterThanOrEqual(before.getTime());
        expect(user.createdAt!.getTime()).toBeLessThanOrEqual(after.getTime());
      });

      it('should create multiple users with unique ids', async () => {
        const user1 = await store.createUser(createTestUser());
        const user2 = await store.createUser({
          ...createTestUser(),
          username: 'testuser2',
          email: 'test2@example.com',
        });

        expect(user1.id).not.toBe(user2.id);
        expect(store.getUserCount()).toBe(2);
      });
    });

    describe('findUserById', () => {
      it('should find existing user by id', async () => {
        const created = await store.createUser(createTestUser());
        const found = await store.findUserById(created.id);

        expect(found).not.toBeNull();
        expect(found!.id).toBe(created.id);
        expect(found!.username).toBe(created.username);
      });

      it('should return null for non-existent id', async () => {
        const found = await store.findUserById('non-existent-id');
        expect(found).toBeNull();
      });
    });

    describe('findUserByUsername', () => {
      it('should find user by username (case-insensitive)', async () => {
        await store.createUser(createTestUser());

        const found1 = await store.findUserByUsername('testuser');
        const found2 = await store.findUserByUsername('TESTUSER');
        const found3 = await store.findUserByUsername('TestUser');

        expect(found1).not.toBeNull();
        expect(found2).not.toBeNull();
        expect(found3).not.toBeNull();
      });

      it('should return null for non-existent username', async () => {
        const found = await store.findUserByUsername('nonexistent');
        expect(found).toBeNull();
      });
    });

    describe('findUserByEmail', () => {
      it('should find user by email (case-insensitive)', async () => {
        await store.createUser(createTestUser());

        const found1 = await store.findUserByEmail('test@example.com');
        const found2 = await store.findUserByEmail('TEST@EXAMPLE.COM');

        expect(found1).not.toBeNull();
        expect(found2).not.toBeNull();
      });

      it('should return null for non-existent email', async () => {
        const found = await store.findUserByEmail('nonexistent@example.com');
        expect(found).toBeNull();
      });
    });

    describe('updateUser', () => {
      it('should update user properties', async () => {
        const created = await store.createUser(createTestUser());
        const updated = await store.updateUser(created.id, {
          username: 'updateduser',
          emailConfirmed: true,
        });

        expect(updated).not.toBeNull();
        expect(updated!.username).toBe('updateduser');
        expect(updated!.emailConfirmed).toBe(true);
        expect(updated!.email).toBe(created.email); // Unchanged
      });

      it('should update updatedAt timestamp', async () => {
        const created = await store.createUser(createTestUser());
        const originalUpdatedAt = created.updatedAt;

        // Small delay to ensure different timestamp
        await new Promise((resolve) => setTimeout(resolve, 10));

        const updated = await store.updateUser(created.id, { username: 'newname' });

        expect(updated!.updatedAt!.getTime()).toBeGreaterThan(originalUpdatedAt!.getTime());
      });

      it('should not change user id', async () => {
        const created = await store.createUser(createTestUser());
        const updated = await store.updateUser(created.id, { id: 'new-id' } as any);

        expect(updated!.id).toBe(created.id);
      });

      it('should return null for non-existent user', async () => {
        const updated = await store.updateUser('non-existent', { username: 'test' });
        expect(updated).toBeNull();
      });
    });

    describe('deleteUser', () => {
      it('should delete existing user', async () => {
        const created = await store.createUser(createTestUser());
        const deleted = await store.deleteUser(created.id);

        expect(deleted).toBe(true);
        expect(await store.findUserById(created.id)).toBeNull();
        expect(store.getUserCount()).toBe(0);
      });

      it('should return false for non-existent user', async () => {
        const deleted = await store.deleteUser('non-existent');
        expect(deleted).toBe(false);
      });

      it('should also delete user roles and claims', async () => {
        const created = await store.createUser(createTestUser());
        await store.addUserToRole(created.id, 'Admin');
        await store.addUserClaim(created.id, { type: 'permission', value: 'read' });

        await store.deleteUser(created.id);

        // Roles and claims should also be deleted
        expect(await store.getUserRoles(created.id)).toEqual([]);
        expect(await store.getUserClaims(created.id)).toEqual([]);
      });
    });
  });

  // ==================== Roles ====================

  describe('Role Operations', () => {
    let userId: string;

    beforeEach(async () => {
      const user = await store.createUser({
        username: 'roletest',
        email: 'role@test.com',
        passwordHash: 'hash',
      });
      userId = user.id;
    });

    describe('addUserToRole', () => {
      it('should add role to user', async () => {
        const result = await store.addUserToRole(userId, 'Admin');

        expect(result).toBe(true);
        expect(await store.getUserRoles(userId)).toContain('Admin');
      });

      it('should add multiple roles', async () => {
        await store.addUserToRole(userId, 'Admin');
        await store.addUserToRole(userId, 'Moderator');
        await store.addUserToRole(userId, 'User');

        const roles = await store.getUserRoles(userId);
        expect(roles).toHaveLength(3);
        expect(roles).toContain('Admin');
        expect(roles).toContain('Moderator');
        expect(roles).toContain('User');
      });

      it('should update user.roles array', async () => {
        await store.addUserToRole(userId, 'Admin');
        const user = await store.findUserById(userId);

        expect(user!.roles).toContain('Admin');
      });

      it('should return false for non-existent user', async () => {
        const result = await store.addUserToRole('non-existent', 'Admin');
        expect(result).toBe(false);
      });
    });

    describe('removeUserFromRole', () => {
      it('should remove role from user', async () => {
        await store.addUserToRole(userId, 'Admin');
        await store.addUserToRole(userId, 'User');

        const result = await store.removeUserFromRole(userId, 'Admin');

        expect(result).toBe(true);
        expect(await store.getUserRoles(userId)).not.toContain('Admin');
        expect(await store.getUserRoles(userId)).toContain('User');
      });

      it('should return false if role does not exist', async () => {
        const result = await store.removeUserFromRole(userId, 'NonExistent');
        expect(result).toBe(false);
      });

      it('should return false for non-existent user', async () => {
        const result = await store.removeUserFromRole('non-existent', 'Admin');
        expect(result).toBe(false);
      });
    });

    describe('isUserInRole', () => {
      it('should return true if user has role', async () => {
        await store.addUserToRole(userId, 'Admin');
        expect(await store.isUserInRole(userId, 'Admin')).toBe(true);
      });

      it('should return false if user does not have role', async () => {
        expect(await store.isUserInRole(userId, 'Admin')).toBe(false);
      });

      it('should return false for non-existent user', async () => {
        expect(await store.isUserInRole('non-existent', 'Admin')).toBe(false);
      });
    });
  });

  // ==================== Claims ====================

  describe('Claim Operations', () => {
    let userId: string;

    beforeEach(async () => {
      const user = await store.createUser({
        username: 'claimtest',
        email: 'claim@test.com',
        passwordHash: 'hash',
      });
      userId = user.id;
    });

    describe('addUserClaim', () => {
      it('should add claim to user', async () => {
        const claim: Claim = { type: 'permission', value: 'read:users' };
        const result = await store.addUserClaim(userId, claim);

        expect(result).toBe(true);
        const claims = await store.getUserClaims(userId);
        expect(claims).toContainEqual(claim);
      });

      it('should add multiple claims', async () => {
        await store.addUserClaim(userId, { type: 'permission', value: 'read' });
        await store.addUserClaim(userId, { type: 'permission', value: 'write' });
        await store.addUserClaim(userId, { type: 'department', value: 'engineering' });

        const claims = await store.getUserClaims(userId);
        expect(claims).toHaveLength(3);
      });

      it('should not add duplicate claim', async () => {
        const claim: Claim = { type: 'permission', value: 'read' };
        await store.addUserClaim(userId, claim);
        const result = await store.addUserClaim(userId, claim);

        expect(result).toBe(false);
        expect(await store.getUserClaims(userId)).toHaveLength(1);
      });

      it('should update user.claims array', async () => {
        const claim: Claim = { type: 'permission', value: 'admin' };
        await store.addUserClaim(userId, claim);
        const user = await store.findUserById(userId);

        expect(user!.claims).toContainEqual(claim);
      });

      it('should return false for non-existent user', async () => {
        const result = await store.addUserClaim('non-existent', {
          type: 'test',
          value: 'test',
        });
        expect(result).toBe(false);
      });
    });

    describe('removeUserClaim', () => {
      it('should remove claim by type and value', async () => {
        await store.addUserClaim(userId, { type: 'permission', value: 'read' });
        await store.addUserClaim(userId, { type: 'permission', value: 'write' });

        const result = await store.removeUserClaim(userId, 'permission', 'read');

        expect(result).toBe(true);
        const claims = await store.getUserClaims(userId);
        expect(claims).not.toContainEqual({ type: 'permission', value: 'read' });
        expect(claims).toContainEqual({ type: 'permission', value: 'write' });
      });

      it('should remove all claims of type if value not specified', async () => {
        await store.addUserClaim(userId, { type: 'permission', value: 'read' });
        await store.addUserClaim(userId, { type: 'permission', value: 'write' });
        await store.addUserClaim(userId, { type: 'department', value: 'eng' });

        const result = await store.removeUserClaim(userId, 'permission');

        expect(result).toBe(true);
        const claims = await store.getUserClaims(userId);
        expect(claims).toHaveLength(1);
        expect(claims[0].type).toBe('department');
      });

      it('should return false if claim does not exist', async () => {
        const result = await store.removeUserClaim(userId, 'nonexistent', 'value');
        expect(result).toBe(false);
      });
    });
  });

  // ==================== Security ====================

  describe('Security Operations', () => {
    let userId: string;

    beforeEach(async () => {
      const user = await store.createUser({
        username: 'securitytest',
        email: 'security@test.com',
        passwordHash: 'hash',
        accessFailedCount: 0,
        lockoutEnabled: true,
      });
      userId = user.id;
    });

    describe('incrementAccessFailedCount', () => {
      it('should increment access failed count', async () => {
        expect(await store.incrementAccessFailedCount(userId)).toBe(1);
        expect(await store.incrementAccessFailedCount(userId)).toBe(2);
        expect(await store.incrementAccessFailedCount(userId)).toBe(3);

        const user = await store.findUserById(userId);
        expect(user!.accessFailedCount).toBe(3);
      });

      it('should return 0 for non-existent user', async () => {
        const count = await store.incrementAccessFailedCount('non-existent');
        expect(count).toBe(0);
      });
    });

    describe('resetAccessFailedCount', () => {
      it('should reset access failed count to 0', async () => {
        await store.incrementAccessFailedCount(userId);
        await store.incrementAccessFailedCount(userId);
        await store.resetAccessFailedCount(userId);

        const user = await store.findUserById(userId);
        expect(user!.accessFailedCount).toBe(0);
      });
    });

    describe('setLockoutEnd', () => {
      it('should set lockout end date', async () => {
        const lockoutEnd = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
        await store.setLockoutEnd(userId, lockoutEnd);

        const user = await store.findUserById(userId);
        expect(user!.lockoutEnd).toEqual(lockoutEnd);
      });

      it('should clear lockout end date when set to null', async () => {
        await store.setLockoutEnd(userId, new Date());
        await store.setLockoutEnd(userId, null);

        const user = await store.findUserById(userId);
        expect(user!.lockoutEnd).toBeNull();
      });
    });
  });

  // ==================== Utilities ====================

  describe('Utility Methods', () => {
    it('clear should remove all data', async () => {
      await store.createUser({
        username: 'user1',
        email: 'user1@test.com',
        passwordHash: 'hash',
      });
      await store.createUser({
        username: 'user2',
        email: 'user2@test.com',
        passwordHash: 'hash',
      });

      expect(store.getUserCount()).toBe(2);

      store.clear();

      expect(store.getUserCount()).toBe(0);
      expect(store.getAllUsers()).toHaveLength(0);
    });

    it('getAllUsers should return all users', async () => {
      await store.createUser({
        username: 'user1',
        email: 'user1@test.com',
        passwordHash: 'hash',
      });
      await store.createUser({
        username: 'user2',
        email: 'user2@test.com',
        passwordHash: 'hash',
      });

      const users = store.getAllUsers();
      expect(users).toHaveLength(2);
    });
  });
});