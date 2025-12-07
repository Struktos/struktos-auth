import { User, Role, Claim } from '../models/auth.models';

/**
 * IAuthStore - Database-agnostic authentication storage interface
 * Inspired by C# Identity's IUserStore<TUser>
 * 
 * This interface abstracts all database operations for authentication,
 * allowing the auth system to work with any database (PostgreSQL, MongoDB, etc.)
 */
export interface IAuthStore<TUser extends User = User> {
  // ==================== User Management ====================
  
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
  createUser(user: Omit<TUser, 'id' | 'createdAt' | 'updatedAt'>): Promise<TUser>;
  
  /**
   * Update an existing user
   */
  updateUser(userId: string, updates: Partial<TUser>): Promise<TUser | null>;
  
  /**
   * Delete a user
   */
  deleteUser(userId: string): Promise<boolean>;
  
  // ==================== Role Management ====================
  
  /**
   * Get all roles for a user
   */
  getUserRoles(userId: string): Promise<string[]>;
  
  /**
   * Add role to user
   */
  addUserToRole(userId: string, roleName: string): Promise<void>;
  
  /**
   * Remove role from user
   */
  removeUserFromRole(userId: string, roleName: string): Promise<void>;
  
  /**
   * Check if user is in role
   */
  isUserInRole(userId: string, roleName: string): Promise<boolean>;
  
  /**
   * Get role by name
   */
  findRoleByName(roleName: string): Promise<Role | null>;
  
  /**
   * Create a new role
   */
  createRole(role: Omit<Role, 'id'>): Promise<Role>;
  
  // ==================== Claim Management ====================
  
  /**
   * Get all claims for a user
   */
  getUserClaims(userId: string): Promise<Claim[]>;
  
  /**
   * Add claim to user
   */
  addUserClaim(userId: string, claim: Claim): Promise<void>;
  
  /**
   * Remove claim from user
   */
  removeUserClaim(userId: string, claimType: string, claimValue: string): Promise<void>;
  
  /**
   * Check if user has specific claim
   */
  hasUserClaim(userId: string, claimType: string, claimValue?: string): Promise<boolean>;
  
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
export class InMemoryAuthStore implements IAuthStore<User> {
  private users: Map<string, User> = new Map();
  private roles: Map<string, Role> = new Map();
  private userRoles: Map<string, Set<string>> = new Map();
  private userClaims: Map<string, Claim[]> = new Map();
  
  async findUserById(userId: string): Promise<User | null> {
    return this.users.get(userId) || null;
  }
  
  async findUserByUsername(username: string): Promise<User | null> {
    for (const user of this.users.values()) {
      if (user.username === username) {
        return user;
      }
    }
    return null;
  }
  
  async findUserByEmail(email: string): Promise<User | null> {
    for (const user of this.users.values()) {
      if (user.email === email) {
        return user;
      }
    }
    return null;
  }
  
  async createUser(userData: Omit<User, 'id' | 'createdAt' | 'updatedAt'>): Promise<User> {
    const user: User = {
      ...userData,
      id: `user-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      createdAt: new Date(),
      updatedAt: new Date()
    };
    
    this.users.set(user.id, user);
    this.userRoles.set(user.id, new Set());
    this.userClaims.set(user.id, []);
    
    return user;
  }
  
  async updateUser(userId: string, updates: Partial<User>): Promise<User | null> {
    const user = this.users.get(userId);
    if (!user) return null;
    
    const updatedUser = {
      ...user,
      ...updates,
      updatedAt: new Date()
    };
    
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
  
  async getUserRoles(userId: string): Promise<string[]> {
    const roles = this.userRoles.get(userId);
    return roles ? Array.from(roles) : [];
  }
  
  async addUserToRole(userId: string, roleName: string): Promise<void> {
    let roles = this.userRoles.get(userId);
    if (!roles) {
      roles = new Set();
      this.userRoles.set(userId, roles);
    }
    roles.add(roleName);
  }
  
  async removeUserFromRole(userId: string, roleName: string): Promise<void> {
    const roles = this.userRoles.get(userId);
    if (roles) {
      roles.delete(roleName);
    }
  }
  
  async isUserInRole(userId: string, roleName: string): Promise<boolean> {
    const roles = this.userRoles.get(userId);
    return roles ? roles.has(roleName) : false;
  }
  
  async findRoleByName(roleName: string): Promise<Role | null> {
    return this.roles.get(roleName) || null;
  }
  
  async createRole(roleData: Omit<Role, 'id'>): Promise<Role> {
    const role: Role = {
      ...roleData,
      id: `role-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
    };
    
    this.roles.set(role.name, role);
    return role;
  }
  
  async getUserClaims(userId: string): Promise<Claim[]> {
    return this.userClaims.get(userId) || [];
  }
  
  async addUserClaim(userId: string, claim: Claim): Promise<void> {
    let claims = this.userClaims.get(userId);
    if (!claims) {
      claims = [];
      this.userClaims.set(userId, claims);
    }
    claims.push(claim);
  }
  
  async removeUserClaim(userId: string, claimType: string, claimValue: string): Promise<void> {
    const claims = this.userClaims.get(userId);
    if (claims) {
      const index = claims.findIndex(c => c.type === claimType && c.value === claimValue);
      if (index !== -1) {
        claims.splice(index, 1);
      }
    }
  }
  
  async hasUserClaim(userId: string, claimType: string, claimValue?: string): Promise<boolean> {
    const claims = this.userClaims.get(userId);
    if (!claims) return false;
    
    if (claimValue) {
      return claims.some(c => c.type === claimType && c.value === claimValue);
    } else {
      return claims.some(c => c.type === claimType);
    }
  }
  
  async incrementAccessFailedCount(userId: string): Promise<number> {
    const user = this.users.get(userId);
    if (!user) return 0;
    
    const count = (user.accessFailedCount || 0) + 1;
    await this.updateUser(userId, { accessFailedCount: count });
    return count;
  }
  
  async resetAccessFailedCount(userId: string): Promise<void> {
    await this.updateUser(userId, { accessFailedCount: 0 });
  }
  
  async setLockoutEnd(userId: string, lockoutEnd: Date | null): Promise<void> {
    await this.updateUser(userId, { lockoutEnd });
  }
}