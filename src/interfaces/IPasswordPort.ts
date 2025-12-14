/**
 * @struktos/auth - IPasswordPort Interface
 * 
 * Port interface for password hashing operations.
 * Abstracts bcrypt/argon2/scrypt libraries.
 * 
 * Follows Hexagonal Architecture (Ports & Adapters) pattern.
 */

/**
 * Password hashing options
 */
export interface PasswordHashOptions {
  /** Number of salt rounds (for bcrypt) */
  rounds?: number;
  /** Memory cost (for argon2) */
  memoryCost?: number;
  /** Time cost (for argon2) */
  timeCost?: number;
  /** Parallelism (for argon2) */
  parallelism?: number;
}

/**
 * Password validation result
 */
export interface PasswordValidationResult {
  /** Whether the password is valid */
  isValid: boolean;
  /** Validation errors */
  errors: string[];
}

/**
 * Password strength levels
 */
export enum PasswordStrength {
  VERY_WEAK = 0,
  WEAK = 1,
  FAIR = 2,
  STRONG = 3,
  VERY_STRONG = 4,
}

/**
 * Password strength result
 */
export interface PasswordStrengthResult {
  /** Strength level */
  strength: PasswordStrength;
  /** Score (0-100) */
  score: number;
  /** Feedback messages */
  feedback: string[];
}

/**
 * IPasswordPort - Password operations port interface
 * 
 * Abstracts password hashing library operations for:
 * - Password hashing
 * - Password verification
 * - Password validation
 * - Password strength checking
 * 
 * @example
 * ```typescript
 * class BcryptPasswordAdapter implements IPasswordPort {
 *   async hash(password: string): Promise<string> {
 *     return bcrypt.hash(password, 10);
 *   }
 * }
 * ```
 */
export interface IPasswordPort {
  // ==================== Hashing ====================

  /**
   * Hash a password
   * 
   * @param password - Plain text password
   * @param options - Hashing options
   * @returns Hashed password
   */
  hash(password: string, options?: PasswordHashOptions): Promise<string>;

  /**
   * Verify a password against a hash
   * 
   * @param password - Plain text password
   * @param hash - Password hash
   * @returns true if password matches, false otherwise
   */
  verify(password: string, hash: string): Promise<boolean>;

  // ==================== Validation ====================

  /**
   * Validate password against policy
   * 
   * @param password - Password to validate
   * @returns Validation result with errors
   */
  validate(password: string): PasswordValidationResult;

  /**
   * Check password strength
   * 
   * @param password - Password to check
   * @returns Strength result with score and feedback
   */
  checkStrength(password: string): PasswordStrengthResult;

  // ==================== Utilities ====================

  /**
   * Generate a random password
   * 
   * @param length - Password length (default: 16)
   * @param options - Generation options
   * @returns Generated password
   */
  generatePassword(
    length?: number,
    options?: {
      includeUppercase?: boolean;
      includeLowercase?: boolean;
      includeNumbers?: boolean;
      includeSymbols?: boolean;
    }
  ): string;

  /**
   * Check if a hash needs rehashing
   * Useful when updating hashing parameters
   * 
   * @param hash - Current password hash
   * @returns true if should rehash
   */
  needsRehash(hash: string): boolean;
}

/**
 * Default password validation rules
 */
export interface PasswordPolicy {
  /** Minimum length */
  minLength: number;
  /** Maximum length */
  maxLength: number;
  /** Require uppercase letter */
  requireUppercase: boolean;
  /** Require lowercase letter */
  requireLowercase: boolean;
  /** Require number */
  requireNumber: boolean;
  /** Require special character */
  requireSpecialChar: boolean;
  /** Disallowed passwords (common passwords) */
  disallowedPasswords?: string[];
}

/**
 * Default password policy
 */
export const DEFAULT_PASSWORD_POLICY: PasswordPolicy = {
  minLength: 8,
  maxLength: 128,
  requireUppercase: true,
  requireLowercase: true,
  requireNumber: true,
  requireSpecialChar: false,
};