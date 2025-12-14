/**
 * BcryptPasswordAdapter Unit Tests
 */

import {
  BcryptPasswordAdapter,
  createBcryptPasswordAdapter,
} from '../../src/adapters/bcrypt-password.adapter';
import { PasswordStrength } from '../../src/interfaces/IPasswordPort';

describe('BcryptPasswordAdapter', () => {
  let adapter: BcryptPasswordAdapter;

  beforeEach(() => {
    adapter = new BcryptPasswordAdapter({
      defaultRounds: 4, // Low rounds for faster tests
      policy: {
        minLength: 8,
        maxLength: 128,
        requireUppercase: true,
        requireLowercase: true,
        requireNumber: true,
        requireSpecialChar: false,
      },
    });
  });

  // ==================== Hashing ====================

  describe('Password Hashing', () => {
    describe('hash', () => {
      it('should hash a password', async () => {
        const password = 'SecurePassword123';
        const hash = await adapter.hash(password);

        expect(hash).toBeDefined();
        expect(hash).not.toBe(password);
        expect(hash.startsWith('$2')).toBe(true); // bcrypt hash prefix
      });

      it('should generate different hashes for same password', async () => {
        const password = 'SecurePassword123';
        const hash1 = await adapter.hash(password);
        const hash2 = await adapter.hash(password);

        expect(hash1).not.toBe(hash2); // Salt should differ
      });

      it('should respect custom rounds option', async () => {
        const password = 'Test123';

        // Hash with more rounds (takes longer)
        const start = Date.now();
        await adapter.hash(password, { rounds: 10 });
        const duration10 = Date.now() - start;

        // Compare with default low rounds
        const start2 = Date.now();
        await adapter.hash(password);
        const duration4 = Date.now() - start2;

        // 10 rounds should take significantly longer than 4 rounds
        expect(duration10).toBeGreaterThan(duration4);
      });
    });

    describe('verify', () => {
      it('should verify correct password', async () => {
        const password = 'CorrectPassword123';
        const hash = await adapter.hash(password);

        const isValid = await adapter.verify(password, hash);
        expect(isValid).toBe(true);
      });

      it('should reject incorrect password', async () => {
        const password = 'CorrectPassword123';
        const hash = await adapter.hash(password);

        const isValid = await adapter.verify('WrongPassword123', hash);
        expect(isValid).toBe(false);
      });

      it('should handle case-sensitive passwords', async () => {
        const password = 'CaseSensitive123';
        const hash = await adapter.hash(password);

        expect(await adapter.verify('casesensitive123', hash)).toBe(false);
        expect(await adapter.verify('CASESENSITIVE123', hash)).toBe(false);
        expect(await adapter.verify('CaseSensitive123', hash)).toBe(true);
      });

      it('should return false for invalid hash', async () => {
        const isValid = await adapter.verify('password', 'invalid-hash');
        expect(isValid).toBe(false);
      });

      it('should handle empty password', async () => {
        const hash = await adapter.hash('validpassword123');
        const isValid = await adapter.verify('', hash);
        expect(isValid).toBe(false);
      });
    });
  });

  // ==================== Validation ====================

  describe('Password Validation', () => {
    describe('validate', () => {
      it('should validate strong password', () => {
        const result = adapter.validate('StrongPass123');

        expect(result.isValid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('should reject password below minimum length', () => {
        const result = adapter.validate('Short1A');

        expect(result.isValid).toBe(false);
        expect(result.errors).toContain(
          'Password must be at least 8 characters long'
        );
      });

      it('should reject password without uppercase', () => {
        const result = adapter.validate('lowercase123');

        expect(result.isValid).toBe(false);
        expect(result.errors).toContain(
          'Password must contain at least one uppercase letter'
        );
      });

      it('should reject password without lowercase', () => {
        const result = adapter.validate('UPPERCASE123');

        expect(result.isValid).toBe(false);
        expect(result.errors).toContain(
          'Password must contain at least one lowercase letter'
        );
      });

      it('should reject password without numbers', () => {
        const result = adapter.validate('NoNumbersHere');

        expect(result.isValid).toBe(false);
        expect(result.errors).toContain(
          'Password must contain at least one number'
        );
      });

      it('should reject common passwords', () => {
        const result = adapter.validate('password');

        expect(result.isValid).toBe(false);
        expect(result.errors.some((e) => e.includes('too common'))).toBe(true);
      });

      it('should reject password exceeding max length', () => {
        const longPassword = 'A'.repeat(200) + 'a1';
        const result = adapter.validate(longPassword);

        expect(result.isValid).toBe(false);
        expect(result.errors).toContain(
          'Password must be at most 128 characters long'
        );
      });

      it('should collect multiple errors', () => {
        const result = adapter.validate('short'); // Too short, no uppercase, no numbers

        expect(result.isValid).toBe(false);
        expect(result.errors.length).toBeGreaterThanOrEqual(3);
      });
    });

    describe('validate with special char requirement', () => {
      it('should require special character when policy specifies', () => {
        const strictAdapter = new BcryptPasswordAdapter({
          defaultRounds: 4,
          policy: {
            minLength: 8,
            requireSpecialChar: true,
          },
        });

        const result = strictAdapter.validate('Password123');
        expect(result.isValid).toBe(false);
        expect(result.errors).toContain(
          'Password must contain at least one special character'
        );

        const validResult = strictAdapter.validate('Password123!');
        expect(validResult.isValid).toBe(true);
      });
    });
  });

  // ==================== Strength Checking ====================

  describe('Password Strength', () => {
    describe('checkStrength', () => {
      it('should rate very weak password', () => {
        const result = adapter.checkStrength('123');

        expect(result.strength).toBe(PasswordStrength.VERY_WEAK);
        expect(result.score).toBeLessThan(20);
      });

      it('should rate weak password', () => {
        const result = adapter.checkStrength('password');

        expect(result.strength).toBeLessThanOrEqual(PasswordStrength.WEAK);
        expect(result.feedback.length).toBeGreaterThan(0);
      });

      it('should rate fair password', () => {
        const result = adapter.checkStrength('Password123');

        expect(result.strength).toBeGreaterThanOrEqual(PasswordStrength.FAIR);
      });

      it('should rate strong password', () => {
        const result = adapter.checkStrength('StrongP@ssw0rd!');

        expect(result.strength).toBeGreaterThanOrEqual(PasswordStrength.STRONG);
        expect(result.score).toBeGreaterThanOrEqual(60);
      });

      it('should rate very strong password', () => {
        const result = adapter.checkStrength('V3ryStr0ng&C0mpl3x!P@ss');

        expect(result.strength).toBe(PasswordStrength.VERY_STRONG);
        expect(result.score).toBeGreaterThanOrEqual(80);
      });

      it('should penalize repeated characters', () => {
        const noRepeat = adapter.checkStrength('abcdefghij');
        const withRepeat = adapter.checkStrength('aaaaabbbbb');

        expect(noRepeat.score).toBeGreaterThan(withRepeat.score);
      });

      it('should provide helpful feedback', () => {
        const result = adapter.checkStrength('alllowercase');

        expect(result.feedback).toContain('Add uppercase letters');
        expect(result.feedback).toContain('Add numbers');
        expect(result.feedback).toContain('Add special characters');
      });

      it('should give length bonus', () => {
        const short = adapter.checkStrength('Abc123!');
        const medium = adapter.checkStrength('Abc123!Abc123!');
        const long = adapter.checkStrength('Abc123!Abc123!Abc123!');

        expect(medium.score).toBeGreaterThan(short.score);
        expect(long.score).toBeGreaterThan(medium.score);
      });
    });
  });

  // ==================== Password Generation ====================

  describe('Password Generation', () => {
    describe('generatePassword', () => {
      it('should generate password of specified length', () => {
        const password = adapter.generatePassword(16);
        expect(password.length).toBe(16);
      });

      it('should generate default length password', () => {
        const password = adapter.generatePassword();
        expect(password.length).toBe(16);
      });

      it('should include all character types by default', () => {
        const password = adapter.generatePassword(50);

        expect(/[a-z]/.test(password)).toBe(true);
        expect(/[A-Z]/.test(password)).toBe(true);
        expect(/[0-9]/.test(password)).toBe(true);
        expect(/[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password)).toBe(true);
      });

      it('should respect character type options', () => {
        const numbersOnly = adapter.generatePassword(20, {
          includeUppercase: false,
          includeLowercase: false,
          includeNumbers: true,
          includeSymbols: false,
        });

        expect(/^[0-9]+$/.test(numbersOnly)).toBe(true);
      });

      it('should generate unique passwords', () => {
        const passwords = new Set<string>();
        for (let i = 0; i < 100; i++) {
          passwords.add(adapter.generatePassword(16));
        }
        expect(passwords.size).toBe(100);
      });

      it('should default to alphanumeric if all options disabled', () => {
        const password = adapter.generatePassword(20, {
          includeUppercase: false,
          includeLowercase: false,
          includeNumbers: false,
          includeSymbols: false,
        });

        // Should fall back to alphanumeric
        expect(password.length).toBe(20);
        expect(/^[a-zA-Z0-9]+$/.test(password)).toBe(true);
      });
    });
  });

  // ==================== Rehashing ====================

  describe('Rehashing', () => {
    describe('needsRehash', () => {
      it('should return true for hash with fewer rounds', async () => {
        // Create adapter with higher target rounds
        const highRoundsAdapter = new BcryptPasswordAdapter({
          defaultRounds: 4,
          targetRounds: 10,
        });

        const hash = await adapter.hash('password');
        expect(highRoundsAdapter.needsRehash(hash)).toBe(true);
      });

      it('should return false for hash with sufficient rounds', async () => {
        const hash = await adapter.hash('password');
        expect(adapter.needsRehash(hash)).toBe(false);
      });

      it('should handle invalid hash gracefully', () => {
        // bcryptjs may or may not throw for invalid hashes
        // Just verify it doesn't crash
        const result = adapter.needsRehash('invalid-hash');
        expect(typeof result).toBe('boolean');
      });
    });
  });

  // ==================== Policy Access ====================

  describe('Policy Access', () => {
    it('should return current policy', () => {
      const policy = adapter.getPolicy();

      expect(policy.minLength).toBe(8);
      expect(policy.maxLength).toBe(128);
      expect(policy.requireUppercase).toBe(true);
      expect(policy.requireLowercase).toBe(true);
      expect(policy.requireNumber).toBe(true);
      expect(policy.requireSpecialChar).toBe(false);
    });

    it('should return copy of policy (immutable)', () => {
      const policy1 = adapter.getPolicy();
      policy1.minLength = 999;

      const policy2 = adapter.getPolicy();
      expect(policy2.minLength).toBe(8);
    });
  });

  // ==================== Factory Function ====================

  describe('Factory Function', () => {
    it('createBcryptPasswordAdapter should create adapter instance', () => {
      const instance = createBcryptPasswordAdapter({ defaultRounds: 5 });
      expect(instance).toBeInstanceOf(BcryptPasswordAdapter);
    });

    it('should use default options', () => {
      const instance = createBcryptPasswordAdapter();
      const policy = instance.getPolicy();

      expect(policy.minLength).toBe(8);
    });
  });

  // ==================== Edge Cases ====================

  describe('Edge Cases', () => {
    it('should handle unicode passwords', async () => {
      const unicodePassword = '日本語パスワード123';
      const hash = await adapter.hash(unicodePassword);
      const isValid = await adapter.verify(unicodePassword, hash);

      expect(isValid).toBe(true);
    });

    it('should handle passwords with spaces', async () => {
      const spacedPassword = 'Password With Spaces 123';
      const hash = await adapter.hash(spacedPassword);
      const isValid = await adapter.verify(spacedPassword, hash);

      expect(isValid).toBe(true);
    });

    it('should handle very long passwords', async () => {
      // bcrypt has a max length of 72 bytes
      const longPassword = 'A'.repeat(100) + '123';
      const hash = await adapter.hash(longPassword);
      const isValid = await adapter.verify(longPassword, hash);

      expect(isValid).toBe(true);
    });
  });
});