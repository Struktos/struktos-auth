/**
 * @struktos/auth - Bcrypt Password Adapter
 * 
 * Implementation of IPasswordPort using bcryptjs library.
 * Follows Hexagonal Architecture (Ports & Adapters) pattern.
 */

import { hash, compare, getRounds } from 'bcryptjs';
import {
  IPasswordPort,
  PasswordHashOptions,
  PasswordValidationResult,
  PasswordStrengthResult,
  PasswordStrength,
  PasswordPolicy,
  DEFAULT_PASSWORD_POLICY,
} from '../interfaces/IPasswordPort';

/**
 * Bcrypt Adapter Options
 */
export interface BcryptAdapterOptions {
  /** Default number of salt rounds (default: 10) */
  defaultRounds?: number;
  /** Target rounds for rehashing check */
  targetRounds?: number;
  /** Password policy */
  policy?: Partial<PasswordPolicy>;
}

/**
 * Common passwords list (subset for demo)
 */
const COMMON_PASSWORDS = [
  'password',
  '123456',
  '12345678',
  'qwerty',
  'abc123',
  'monkey',
  'letmein',
  'password1',
  'iloveyou',
  'trustno1',
];

/**
 * BcryptPasswordAdapter - Bcrypt implementation of IPasswordPort
 * 
 * @example
 * ```typescript
 * const passwordAdapter = new BcryptPasswordAdapter({
 *   defaultRounds: 12,
 *   policy: {
 *     minLength: 10,
 *     requireSpecialChar: true
 *   }
 * });
 * 
 * const hash = await passwordAdapter.hash('myPassword123!');
 * const isValid = await passwordAdapter.verify('myPassword123!', hash);
 * ```
 */
export class BcryptPasswordAdapter implements IPasswordPort {
  private readonly options: Required<BcryptAdapterOptions>;
  private readonly policy: PasswordPolicy;

  constructor(options: BcryptAdapterOptions = {}) {
    this.options = {
      defaultRounds: options.defaultRounds ?? 10,
      targetRounds: options.targetRounds ?? options.defaultRounds ?? 10,
      policy: options.policy ?? {},
    };

    this.policy = {
      ...DEFAULT_PASSWORD_POLICY,
      ...options.policy,
    };
  }

  // ==================== Hashing ====================

  async hash(password: string, options?: PasswordHashOptions): Promise<string> {
    const rounds = options?.rounds ?? this.options.defaultRounds;
    return hash(password, rounds);
  }

  async verify(password: string, passwordHash: string): Promise<boolean> {
    try {
      return await compare(password, passwordHash);
    } catch {
      return false;
    }
  }

  // ==================== Validation ====================

  validate(password: string): PasswordValidationResult {
    const errors: string[] = [];

    // Check length
    if (password.length < this.policy.minLength) {
      errors.push(`Password must be at least ${this.policy.minLength} characters long`);
    }

    if (password.length > this.policy.maxLength) {
      errors.push(`Password must be at most ${this.policy.maxLength} characters long`);
    }

    // Check uppercase
    if (this.policy.requireUppercase && !/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }

    // Check lowercase
    if (this.policy.requireLowercase && !/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }

    // Check numbers
    if (this.policy.requireNumber && !/[0-9]/.test(password)) {
      errors.push('Password must contain at least one number');
    }

    // Check special characters
    if (this.policy.requireSpecialChar && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      errors.push('Password must contain at least one special character');
    }

    // Check common passwords
    if (this.policy.disallowedPasswords?.includes(password.toLowerCase()) ||
        COMMON_PASSWORDS.includes(password.toLowerCase())) {
      errors.push('This password is too common. Please choose a more unique password');
    }

    return {
      isValid: errors.length === 0,
      errors,
    };
  }

  checkStrength(password: string): PasswordStrengthResult {
    let score = 0;
    const feedback: string[] = [];

    // Length scoring
    if (password.length >= 8) score += 10;
    if (password.length >= 12) score += 15;
    if (password.length >= 16) score += 10;

    // Character variety
    if (/[a-z]/.test(password)) {
      score += 10;
    } else {
      feedback.push('Add lowercase letters');
    }

    if (/[A-Z]/.test(password)) {
      score += 15;
    } else {
      feedback.push('Add uppercase letters');
    }

    if (/[0-9]/.test(password)) {
      score += 15;
    } else {
      feedback.push('Add numbers');
    }

    if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      score += 20;
    } else {
      feedback.push('Add special characters');
    }

    // Pattern penalties
    if (/(.)\1{2,}/.test(password)) {
      score -= 10;
      feedback.push('Avoid repeated characters');
    }

    if (/^[a-zA-Z]+$/.test(password)) {
      score -= 5;
      feedback.push('Mix letters with numbers and symbols');
    }

    if (/^[0-9]+$/.test(password)) {
      score -= 15;
      feedback.push('Add letters and symbols');
    }

    // Common password check
    if (COMMON_PASSWORDS.includes(password.toLowerCase())) {
      score = Math.min(score, 10);
      feedback.push('This is a commonly used password');
    }

    // Normalize score
    score = Math.max(0, Math.min(100, score));

    // Determine strength level
    let strength: PasswordStrength;
    if (score < 20) {
      strength = PasswordStrength.VERY_WEAK;
    } else if (score < 40) {
      strength = PasswordStrength.WEAK;
    } else if (score < 60) {
      strength = PasswordStrength.FAIR;
    } else if (score < 80) {
      strength = PasswordStrength.STRONG;
    } else {
      strength = PasswordStrength.VERY_STRONG;
    }

    return {
      strength,
      score,
      feedback,
    };
  }

  // ==================== Utilities ====================

  generatePassword(
    length: number = 16,
    options?: {
      includeUppercase?: boolean;
      includeLowercase?: boolean;
      includeNumbers?: boolean;
      includeSymbols?: boolean;
    }
  ): string {
    const defaultOptions = {
      includeUppercase: true,
      includeLowercase: true,
      includeNumbers: true,
      includeSymbols: true,
      ...options,
    };

    let chars = '';
    if (defaultOptions.includeLowercase) chars += 'abcdefghijklmnopqrstuvwxyz';
    if (defaultOptions.includeUppercase) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (defaultOptions.includeNumbers) chars += '0123456789';
    if (defaultOptions.includeSymbols) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';

    if (chars.length === 0) {
      chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    }

    let password = '';
    for (let i = 0; i < length; i++) {
      password += chars.charAt(Math.floor(Math.random() * chars.length));
    }

    return password;
  }

  needsRehash(passwordHash: string): boolean {
    try {
      const rounds = getRounds(passwordHash);
      return rounds < this.options.targetRounds;
    } catch {
      return true;
    }
  }

  // ==================== Policy Access ====================

  /**
   * Get current password policy
   */
  getPolicy(): PasswordPolicy {
    return { ...this.policy };
  }
}

/**
 * Factory function
 */
export function createBcryptPasswordAdapter(options?: BcryptAdapterOptions): BcryptPasswordAdapter {
  return new BcryptPasswordAdapter(options);
}