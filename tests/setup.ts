/**
 * Jest Test Setup for @struktos/auth
 */

// Increase timeout for async tests
jest.setTimeout(10000);

// Mock console.error to reduce noise in tests
const originalConsoleError = console.error;
beforeAll(() => {
  console.error = jest.fn();
});

afterAll(() => {
  console.error = originalConsoleError;
});

// Global test utilities
export const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));