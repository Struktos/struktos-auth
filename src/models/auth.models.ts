/**
 * User Claim - represents a claim that a user possesses
 * Inspired by C# Identity's IdentityUserClaim
 */
export interface Claim {
  /**
   * Type of the claim (e.g., "permission", "feature", "department")
   */
  type: string;
  
  /**
   * Value of the claim (e.g., "read:users", "beta-features", "engineering")
   */
  value: string;
}

/**
 * User Role - represents a role that a user belongs to
 * Inspired by C# Identity's IdentityRole
 */
export interface Role {
  /**
   * Unique identifier for the role
   */
  id: string;
  
  /**
   * Name of the role (e.g., "Admin", "User", "Moderator")
   */
  name: string;
  
  /**
   * Optional description of the role
   */
  description?: string;
  
  /**
   * Claims associated with this role
   */
  claims?: Claim[];
}

/**
 * Base User interface
 * Inspired by C# Identity's IdentityUser
 * 
 * This is a generic interface that can be extended with custom properties
 */
export interface User {
  /**
   * Unique identifier for the user
   */
  id: string;
  
  /**
   * Username for authentication
   */
  username: string;
  
  /**
   * Email address
   */
  email: string;
  
  /**
   * Hashed password
   * NEVER store plain text passwords!
   */
  passwordHash: string;
  
  /**
   * Email confirmation status
   */
  emailConfirmed?: boolean;
  
  /**
   * Phone number
   */
  phoneNumber?: string;
  
  /**
   * Phone number confirmation status
   */
  phoneNumberConfirmed?: boolean;
  
  /**
   * Two-factor authentication enabled
   */
  twoFactorEnabled?: boolean;
  
  /**
   * Lockout end date (null if not locked out)
   */
  lockoutEnd?: Date | null;
  
  /**
   * Lockout enabled for this user
   */
  lockoutEnabled?: boolean;
  
  /**
   * Failed access attempts count
   */
  accessFailedCount?: number;
  
  /**
   * Roles assigned to this user
   */
  roles?: string[];
  
  /**
   * Claims assigned directly to this user
   */
  claims?: Claim[];
  
  /**
   * Timestamps
   */
  createdAt?: Date;
  updatedAt?: Date;
}

/**
 * Authentication Result
 */
export interface AuthenticationResult {
  /**
   * Whether authentication was successful
   */
  success: boolean;
  
  /**
   * Authenticated user (if successful)
   */
  user?: User;
  
  /**
   * JWT access token (if successful)
   */
  accessToken?: string;
  
  /**
   * JWT refresh token (if successful)
   */
  refreshToken?: string;
  
  /**
   * Token expiration time in seconds
   */
  expiresIn?: number;
  
  /**
   * Error message (if failed)
   */
  error?: string;
  
  /**
   * Whether the account is locked out
   */
  isLockedOut?: boolean;
  
  /**
   * Whether two-factor authentication is required
   */
  requiresTwoFactor?: boolean;
}

/**
 * Token Payload
 * Data stored in JWT tokens
 */
export interface TokenPayload {
  /**
   * User ID (subject)
   */
  sub: string;
  
  /**
   * Username
   */
  username: string;
  
  /**
   * Email
   */
  email: string;
  
  /**
   * Roles
   */
  roles?: string[];
  
  /**
   * Claims
   */
  claims?: Claim[];
  
  /**
   * Issued at (timestamp)
   */
  iat?: number;
  
  /**
   * Expiration (timestamp)
   */
  exp?: number;
  
  /**
   * Issuer
   */
  iss?: string;
  
  /**
   * Audience
   */
  aud?: string;
}

/**
 * User Registration Data
 */
export interface RegistrationData {
  username: string;
  email: string;
  password: string;
  phoneNumber?: string;
}

/**
 * User Login Credentials
 */
export interface LoginCredentials {
  username: string;
  password: string;
}