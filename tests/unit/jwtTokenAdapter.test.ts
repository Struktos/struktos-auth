/**
 * JwtTokenAdapter Unit Tests
 */

import { JwtTokenAdapter, createJwtTokenAdapter } from '../../src/adapters/jwt-token.adapter';
import { TokenVerificationError, TokenErrorType } from '../../src/interfaces/ITokenPort';
import { User } from '../../src/models/auth.models';

describe('JwtTokenAdapter', () => {
  let adapter: JwtTokenAdapter;
  const TEST_SECRET = 'test-secret-key-that-is-at-least-32-characters';

  const createTestUser = (): User => ({
    id: 'user-123',
    username: 'testuser',
    email: 'test@example.com',
    passwordHash: 'hash',
    roles: ['User', 'Admin'],
    claims: [
      { type: 'permission', value: 'read:users' },
      { type: 'department', value: 'engineering' },
    ],
  });

  beforeEach(() => {
    adapter = new JwtTokenAdapter({
      secret: TEST_SECRET,
      accessTokenExpiry: '1h',
      refreshTokenExpiry: '7d',
      issuer: 'test-issuer',
      audience: 'test-audience',
    });
  });

  afterEach(() => {
    adapter.clearRevokedTokens();
  });

  // ==================== Token Generation ====================

  describe('Token Generation', () => {
    describe('generateAccessToken', () => {
      it('should generate a valid access token', async () => {
        const user = createTestUser();
        const result = await adapter.generateAccessToken(user);

        expect(result.token).toBeDefined();
        expect(typeof result.token).toBe('string');
        expect(result.token.split('.')).toHaveLength(3); // JWT has 3 parts
      });

      it('should include expiration info', async () => {
        const user = createTestUser();
        const result = await adapter.generateAccessToken(user);

        expect(result.expiresAt).toBeDefined();
        expect(result.expiresIn).toBeDefined();
        expect(result.expiresIn).toBeGreaterThan(0);
        expect(result.expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
      });

      it('should include user data in token payload', async () => {
        const user = createTestUser();
        const result = await adapter.generateAccessToken(user);
        const payload = adapter.decodeToken(result.token);

        expect(payload).not.toBeNull();
        expect(payload!.sub).toBe(user.id);
        expect(payload!.username).toBe(user.username);
        expect(payload!.email).toBe(user.email);
        expect(payload!.roles).toEqual(user.roles);
        expect(payload!.claims).toEqual(user.claims);
        expect(payload!.type).toBe('access');
      });

      it('should respect custom expiration', async () => {
        const user = createTestUser();
        const result = await adapter.generateAccessToken(user, { expiresIn: '5m' });

        // Should expire in approximately 5 minutes (300 seconds)
        expect(result.expiresIn).toBeLessThanOrEqual(300 + 5);
        expect(result.expiresIn).toBeGreaterThanOrEqual(295);
      });

      it('should include custom additional claims', async () => {
        const user = createTestUser();
        const result = await adapter.generateAccessToken(user, {
          additionalClaims: { customField: 'customValue' },
        });
        const payload = adapter.decodeToken(result.token);

        expect((payload as any).customField).toBe('customValue');
      });
    });

    describe('generateRefreshToken', () => {
      it('should generate a valid refresh token', async () => {
        const user = createTestUser();
        const result = await adapter.generateRefreshToken(user);

        expect(result.token).toBeDefined();
        expect(result.token.split('.')).toHaveLength(3);
      });

      it('should have type "refresh" in payload', async () => {
        const user = createTestUser();
        const result = await adapter.generateRefreshToken(user);
        const payload = adapter.decodeToken(result.token);

        expect(payload!.type).toBe('refresh');
      });

      it('should have longer expiration than access token', async () => {
        const user = createTestUser();
        const access = await adapter.generateAccessToken(user);
        const refresh = await adapter.generateRefreshToken(user);

        expect(refresh.expiresIn).toBeGreaterThan(access.expiresIn);
      });
    });

    describe('generateTokenPair', () => {
      it('should generate both access and refresh tokens', async () => {
        const user = createTestUser();
        const result = await adapter.generateTokenPair(user);

        expect(result.accessToken).toBeDefined();
        expect(result.refreshToken).toBeDefined();
        expect(result.accessToken.token).not.toBe(result.refreshToken.token);
      });

      it('should respect separate options for each token', async () => {
        const user = createTestUser();
        const result = await adapter.generateTokenPair(
          user,
          { expiresIn: '15m' },
          { expiresIn: '1d' }
        );

        // Access token: ~15 minutes
        expect(result.accessToken.expiresIn).toBeLessThanOrEqual(900 + 5);

        // Refresh token: ~1 day
        expect(result.refreshToken.expiresIn).toBeLessThanOrEqual(86400 + 5);
      });
    });
  });

  // ==================== Token Verification ====================

  describe('Token Verification', () => {
    describe('verifyToken', () => {
      it('should verify valid token', async () => {
        const user = createTestUser();
        const generated = await adapter.generateAccessToken(user);
        const payload = await adapter.verifyToken(generated.token);

        expect(payload.sub).toBe(user.id);
        expect(payload.username).toBe(user.username);
      });

      it('should verify token synchronously', async () => {
        const user = createTestUser();
        const generated = await adapter.generateAccessToken(user);
        const payload = adapter.verifyTokenSync(generated.token);

        expect(payload.sub).toBe(user.id);
      });

      it('should throw for expired token', async () => {
        const shortAdapter = new JwtTokenAdapter({
          secret: TEST_SECRET,
          accessTokenExpiry: '1ms',
        });

        const user = createTestUser();
        const generated = await shortAdapter.generateAccessToken(user);

        // Wait for token to expire
        await new Promise((resolve) => setTimeout(resolve, 50));

        await expect(shortAdapter.verifyToken(generated.token)).rejects.toThrow(
          TokenVerificationError
        );
        await expect(shortAdapter.verifyToken(generated.token)).rejects.toMatchObject({
          type: TokenErrorType.EXPIRED_TOKEN,
        });
      });

      it('should throw for invalid token', async () => {
        await expect(adapter.verifyToken('invalid.token.here')).rejects.toThrow(
          TokenVerificationError
        );
      });

      it('should throw for tampered token', async () => {
        const user = createTestUser();
        const generated = await adapter.generateAccessToken(user);

        // Tamper with the token
        const parts = generated.token.split('.');
        parts[1] = 'tamperedpayload';
        const tamperedToken = parts.join('.');

        await expect(adapter.verifyToken(tamperedToken)).rejects.toThrow(
          TokenVerificationError
        );
      });

      it('should throw for token signed with different secret', async () => {
        const otherAdapter = new JwtTokenAdapter({
          secret: 'different-secret-key-that-is-also-32-characters',
        });

        const user = createTestUser();
        const generated = await otherAdapter.generateAccessToken(user);

        await expect(adapter.verifyToken(generated.token)).rejects.toThrow(
          TokenVerificationError
        );
      });

      it('should verify issuer and audience', async () => {
        const strictAdapter = new JwtTokenAdapter({
          secret: TEST_SECRET,
          issuer: 'correct-issuer',
          audience: 'correct-audience',
        });

        const user = createTestUser();
        const generated = await strictAdapter.generateAccessToken(user);

        // Should succeed with correct issuer/audience
        await expect(strictAdapter.verifyToken(generated.token)).resolves.toBeDefined();

        // Different adapter with different issuer should fail
        const wrongIssuerAdapter = new JwtTokenAdapter({
          secret: TEST_SECRET,
          issuer: 'wrong-issuer',
          audience: 'correct-audience',
        });

        await expect(wrongIssuerAdapter.verifyToken(generated.token)).rejects.toThrow();
      });
    });

    describe('isTokenValid', () => {
      it('should return true for valid token', async () => {
        const user = createTestUser();
        const generated = await adapter.generateAccessToken(user);
        const isValid = await adapter.isTokenValid(generated.token);

        expect(isValid).toBe(true);
      });

      it('should return false for invalid token', async () => {
        const isValid = await adapter.isTokenValid('invalid.token');
        expect(isValid).toBe(false);
      });

      it('should return false for expired token', async () => {
        const shortAdapter = new JwtTokenAdapter({
          secret: TEST_SECRET,
          accessTokenExpiry: '1ms',
        });

        const user = createTestUser();
        const generated = await shortAdapter.generateAccessToken(user);

        await new Promise((resolve) => setTimeout(resolve, 50));

        const isValid = await shortAdapter.isTokenValid(generated.token);
        expect(isValid).toBe(false);
      });
    });
  });

  // ==================== Token Decoding ====================

  describe('Token Decoding', () => {
    describe('decodeToken', () => {
      it('should decode token without verification', async () => {
        const user = createTestUser();
        const generated = await adapter.generateAccessToken(user);
        const payload = adapter.decodeToken(generated.token);

        expect(payload).not.toBeNull();
        expect(payload!.sub).toBe(user.id);
      });

      it('should decode expired token', async () => {
        const shortAdapter = new JwtTokenAdapter({
          secret: TEST_SECRET,
          accessTokenExpiry: '1ms',
        });

        const user = createTestUser();
        const generated = await shortAdapter.generateAccessToken(user);

        await new Promise((resolve) => setTimeout(resolve, 50));

        // Should still decode even though expired
        const payload = adapter.decodeToken(generated.token);
        expect(payload).not.toBeNull();
        expect(payload!.sub).toBe(user.id);
      });

      it('should return null for invalid token', () => {
        const payload = adapter.decodeToken('not-a-valid-token');
        expect(payload).toBeNull();
      });
    });
  });

  // ==================== Token Revocation ====================

  describe('Token Revocation', () => {
    describe('revokeToken', () => {
      it('should revoke a token', async () => {
        const user = createTestUser();
        const generated = await adapter.generateAccessToken(user);

        // Token should be valid initially
        expect(await adapter.isTokenValid(generated.token)).toBe(true);

        // Revoke the token
        await adapter.revokeToken(generated.token);

        // Token should now fail verification
        await expect(adapter.verifyToken(generated.token)).rejects.toThrow(
          TokenVerificationError
        );
        await expect(adapter.verifyToken(generated.token)).rejects.toMatchObject({
          type: TokenErrorType.REVOKED_TOKEN,
        });
      });

      it('should track revoked tokens', async () => {
        const user = createTestUser();
        const token1 = await adapter.generateAccessToken(user);
        const token2 = await adapter.generateAccessToken(user);

        await adapter.revokeToken(token1.token);

        expect(await adapter.isTokenRevoked(token1.token)).toBe(true);
        expect(await adapter.isTokenRevoked(token2.token)).toBe(false);
      });
    });

    describe('clearRevokedTokens', () => {
      it('should clear all revoked tokens', async () => {
        const user = createTestUser();
        const token1 = await adapter.generateAccessToken(user);
        const token2 = await adapter.generateAccessToken(user);

        await adapter.revokeToken(token1.token);
        await adapter.revokeToken(token2.token);

        expect(adapter.getRevokedCount()).toBe(2);

        adapter.clearRevokedTokens();

        expect(adapter.getRevokedCount()).toBe(0);
        expect(await adapter.isTokenRevoked(token1.token)).toBe(false);
      });
    });
  });

  // ==================== Factory Function ====================

  describe('Factory Function', () => {
    it('createJwtTokenAdapter should create adapter instance', () => {
      const instance = createJwtTokenAdapter({ secret: TEST_SECRET });

      expect(instance).toBeInstanceOf(JwtTokenAdapter);
    });
  });

  // ==================== Edge Cases ====================

  describe('Edge Cases', () => {
    it('should handle user with no roles or claims', async () => {
      const user: User = {
        id: 'user-no-extras',
        username: 'minimal',
        email: 'minimal@test.com',
        passwordHash: 'hash',
      };

      const generated = await adapter.generateAccessToken(user);
      const payload = await adapter.verifyToken(generated.token);

      expect(payload.sub).toBe(user.id);
      expect(payload.roles).toBeUndefined();
      expect(payload.claims).toBeUndefined();
    });

    it('should handle empty roles array', async () => {
      const user: User = {
        id: 'user-empty-roles',
        username: 'emptyroles',
        email: 'empty@test.com',
        passwordHash: 'hash',
        roles: [],
        claims: [],
      };

      const generated = await adapter.generateAccessToken(user);
      const payload = await adapter.verifyToken(generated.token);

      expect(payload.roles).toEqual([]);
      expect(payload.claims).toEqual([]);
    });

    it('should include JTI (JWT ID) in token', async () => {
      const user = createTestUser();
      const generated = await adapter.generateAccessToken(user);
      const payload = adapter.decodeToken(generated.token);

      expect(payload!.jti).toBeDefined();
      expect(typeof payload!.jti).toBe('string');
    });

    it('should generate unique JTI for each token', async () => {
      const user = createTestUser();
      const token1 = await adapter.generateAccessToken(user);
      const token2 = await adapter.generateAccessToken(user);

      const payload1 = adapter.decodeToken(token1.token);
      const payload2 = adapter.decodeToken(token2.token);

      expect(payload1!.jti).not.toBe(payload2!.jti);
    });
  });
});