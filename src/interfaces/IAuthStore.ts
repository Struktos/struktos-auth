/**
 * @struktos/auth - IAuthStore Interface
 * 
 * Database-agnostic interface for user storage operations.
 * Implementations can use any database (PostgreSQL, MongoDB, etc.)
 */

import { User, Role, Claim } from '../models/auth.models';

/**
 * IAuthStore - User storage interface
 * 
 * Provides abstraction for CRUD operations on users and their roles/claims.
 * Implementations should be provided for specific databases.
 * 
 * @example
 * ```typescript
 * class PostgresAuthStore implements IAuthStore<User> {
 *   constructor(private pool: Pool) {}
 *   
 *   async findUserById(userId: string): Promise<User | null> {
 *     const result = await this.pool.query('SELECT * FROM users WHERE id = $1', [userId]);
 *     return result.rows[0] || null;
 *   }
 * }
 * ```
 */
export interface IAuthStore<TUser extends User = User> {
  // ==================== User CRUD ====================

  /**
   * Find user by ID
   */
  findUserById(userId: string): Promise<TUser | null>;

  /**
   * Find user by username
   */
  findUserByUsername(username: string): Promise<TUser | null>;

  /**
   * Find user by email
   */
  findUserByEmail(email: string): Promise<TUser | null>;

  /**
   * Create a new user
   */
  createUser(
    userData: Omit<TUser, 'id' | 'createdAt' | 'updatedAt'>
  ): Promise<TUser>;

  /**
   * Update an existing user
   */
  updateUser(userId: string, updates: Partial<TUser>): Promise<TUser | null>;

  /**
   * Delete a user
   */
  deleteUser(userId: string): Promise<boolean>;

  // ==================== Roles ====================

  /**
   * Get user's roles
   */
  getUserRoles(userId: string): Promise<string[]>;

  /**
   * Add user to role
   */
  addUserToRole(userId: string, roleName: string): Promise<boolean>;

  /**
   * Remove user from role
   */
  removeUserFromRole(userId: string, roleName: string): Promise<boolean>;

  /**
   * Check if user is in role
   */
  isUserInRole(userId: string, roleName: string): Promise<boolean>;

  // ==================== Claims ====================

  /**
   * Get user's claims
   */
  getUserClaims(userId: string): Promise<Claim[]>;

  /**
   * Add claim to user
   */
  addUserClaim(userId: string, claim: Claim): Promise<boolean>;

  /**
   * Remove claim from user
   */
  removeUserClaim(userId: string, claimType: string, claimValue?: string): Promise<boolean>;

  // ==================== Security ====================

  /**
   * Increment access failed count
   */
  incrementAccessFailedCount(userId: string): Promise<number>;

  /**
   * Reset access failed count
   */
  resetAccessFailedCount(userId: string): Promise<void>;

  /**
   * Set lockout end date
   */
  setLockoutEnd(userId: string, lockoutEnd: Date | null): Promise<void>;
}

/**
 * In-Memory Auth Store Implementation
 * For development and testing purposes
 */
export class InMemoryAuthStore<TUser extends User = User>
  implements IAuthStore<TUser>
{
  private users: Map<string, TUser> = new Map();
  private roles: Map<string, Role> = new Map();
  private userRoles: Map<string, Set<string>> = new Map();
  private userClaims: Map<string, Claim[]> = new Map();
  private idCounter = 0;

  // ==================== User CRUD ====================

  async findUserById(userId: string): Promise<TUser | null> {
    return this.users.get(userId) || null;
  }

  async findUserByUsername(username: string): Promise<TUser | null> {
    for (const user of this.users.values()) {
      if (user.username.toLowerCase() === username.toLowerCase()) {
        return user;
      }
    }
    return null;
  }

  async findUserByEmail(email: string): Promise<TUser | null> {
    for (const user of this.users.values()) {
      if (user.email.toLowerCase() === email.toLowerCase()) {
        return user;
      }
    }
    return null;
  }

  async createUser(
    userData: Omit<TUser, 'id' | 'createdAt' | 'updatedAt'>
  ): Promise<TUser> {
    const id = `user-${++this.idCounter}-${Date.now()}`;
    const now = new Date();

    const user = {
      ...userData,
      id,
      createdAt: now,
      updatedAt: now,
    } as TUser;

    this.users.set(id, user);
    this.userRoles.set(id, new Set());
    this.userClaims.set(id, []);

    return user;
  }

  async updateUser(userId: string, updates: Partial<TUser>): Promise<TUser | null> {
    const user = this.users.get(userId);
    if (!user) return null;

    const updatedUser = {
      ...user,
      ...updates,
      id: user.id, // Prevent ID change
      updatedAt: new Date(),
    } as TUser;

    this.users.set(userId, updatedUser);
    return updatedUser;
  }

  async deleteUser(userId: string): Promise<boolean> {
    const deleted = this.users.delete(userId);
    if (deleted) {
      this.userRoles.delete(userId);
      this.userClaims.delete(userId);
    }
    return deleted;
  }

  // ==================== Roles ====================

  async getUserRoles(userId: string): Promise<string[]> {
    const roles = this.userRoles.get(userId);
    return roles ? Array.from(roles) : [];
  }

  async addUserToRole(userId: string, roleName: string): Promise<boolean> {
    const user = this.users.get(userId);
    if (!user) return false;

    let roles = this.userRoles.get(userId);
    if (!roles) {
      roles = new Set();
      this.userRoles.set(userId, roles);
    }

    roles.add(roleName);

    // Update user.roles array
    const updatedUser = {
      ...user,
      roles: Array.from(roles),
      updatedAt: new Date(),
    } as TUser;
    this.users.set(userId, updatedUser);

    return true;
  }

  async removeUserFromRole(userId: string, roleName: string): Promise<boolean> {
    const user = this.users.get(userId);
    if (!user) return false;

    const roles = this.userRoles.get(userId);
    if (!roles) return false;

    const deleted = roles.delete(roleName);

    if (deleted) {
      const updatedUser = {
        ...user,
        roles: Array.from(roles),
        updatedAt: new Date(),
      } as TUser;
      this.users.set(userId, updatedUser);
    }

    return deleted;
  }

  async isUserInRole(userId: string, roleName: string): Promise<boolean> {
    const roles = this.userRoles.get(userId);
    return roles?.has(roleName) ?? false;
  }

  // ==================== Claims ====================

  async getUserClaims(userId: string): Promise<Claim[]> {
    return this.userClaims.get(userId) || [];
  }

  async addUserClaim(userId: string, claim: Claim): Promise<boolean> {
    const user = this.users.get(userId);
    if (!user) return false;

    let claims = this.userClaims.get(userId);
    if (!claims) {
      claims = [];
      this.userClaims.set(userId, claims);
    }

    // Check if claim already exists
    const exists = claims.some(
      (c) => c.type === claim.type && c.value === claim.value
    );
    if (exists) return false;

    claims.push(claim);

    // Update user.claims array
    const updatedUser = {
      ...user,
      claims: [...claims],
      updatedAt: new Date(),
    } as TUser;
    this.users.set(userId, updatedUser);

    return true;
  }

  async removeUserClaim(
    userId: string,
    claimType: string,
    claimValue?: string
  ): Promise<boolean> {
    const user = this.users.get(userId);
    if (!user) return false;

    const claims = this.userClaims.get(userId);
    if (!claims) return false;

    const initialLength = claims.length;
    const filteredClaims = claims.filter((c) => {
      if (c.type !== claimType) return true;
      if (claimValue !== undefined && c.value !== claimValue) return true;
      return false;
    });

    if (filteredClaims.length === initialLength) return false;

    this.userClaims.set(userId, filteredClaims);

    // Update user.claims array
    const updatedUser = {
      ...user,
      claims: [...filteredClaims],
      updatedAt: new Date(),
    } as TUser;
    this.users.set(userId, updatedUser);

    return true;
  }

  // ==================== Security ====================

  async incrementAccessFailedCount(userId: string): Promise<number> {
    const user = this.users.get(userId);
    if (!user) return 0;

    const count = (user.accessFailedCount || 0) + 1;
    await this.updateUser(userId, { accessFailedCount: count } as Partial<TUser>);
    return count;
  }

  async resetAccessFailedCount(userId: string): Promise<void> {
    await this.updateUser(userId, { accessFailedCount: 0 } as Partial<TUser>);
  }

  async setLockoutEnd(userId: string, lockoutEnd: Date | null): Promise<void> {
    await this.updateUser(userId, { lockoutEnd } as Partial<TUser>);
  }

  // ==================== Utilities ====================

  /**
   * Clear all data (for testing)
   */
  clear(): void {
    this.users.clear();
    this.roles.clear();
    this.userRoles.clear();
    this.userClaims.clear();
    this.idCounter = 0;
  }

  /**
   * Get user count
   */
  getUserCount(): number {
    return this.users.size;
  }

  /**
   * Get all users (for testing/debugging)
   */
  getAllUsers(): TUser[] {
    return Array.from(this.users.values());
  }
}