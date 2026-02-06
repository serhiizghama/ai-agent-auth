/**
 * Tests for Session
 */

import { describe, it, expect, vi } from 'vitest';
import { Session } from '../src/session';

describe('Session', () => {
  const createTestSession = (expiresIn: number = 3600) => {
    const expiresAt = new Date(Date.now() + expiresIn * 1000);
    return new Session(
      'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.test.signature',
      expiresAt,
      {
        did: 'did:key:z6MkTest',
        name: 'TestAgent',
        capabilities: ['read', 'write'],
      }
    );
  };

  describe('constructor', () => {
    it('should create session with all properties', () => {
      const token = 'test.jwt.token';
      const expiresAt = new Date(Date.now() + 3600 * 1000);
      const agentInfo = {
        did: 'did:key:z6MkTest',
        name: 'TestAgent',
        capabilities: ['read'],
      };

      const session = new Session(token, expiresAt, agentInfo);

      expect(session.token).toBe(token);
      expect(session.expiresAt).toEqual(expiresAt);
      expect(session.agent).toEqual(agentInfo);
    });
  });

  describe('isExpired', () => {
    it('should return false for valid session', () => {
      const session = createTestSession(3600); // Expires in 1 hour
      expect(session.isExpired).toBe(false);
    });

    it('should return true for expired session', () => {
      const session = createTestSession(-120); // Expired 2 minutes ago
      expect(session.isExpired).toBe(true);
    });

    it('should apply 60-second grace period', () => {
      const session = createTestSession(-30); // Expired 30 seconds ago
      expect(session.isExpired).toBe(false); // Within 60s grace period

      const expired = createTestSession(-90); // Expired 90 seconds ago
      expect(expired.isExpired).toBe(true); // Beyond grace period
    });
  });

  describe('willExpireIn()', () => {
    it('should return false if token has plenty of time left', () => {
      const session = createTestSession(3600); // 1 hour
      expect(session.willExpireIn(300)).toBe(false); // Check 5 minutes
    });

    it('should return true if token expires soon', () => {
      const session = createTestSession(120); // 2 minutes
      expect(session.willExpireIn(300)).toBe(true); // Check 5 minutes
    });

    it('should handle edge cases', () => {
      const session = createTestSession(300); // Exactly 5 minutes

      // Just before threshold
      expect(session.willExpireIn(299)).toBe(false);

      // At threshold
      expect(session.willExpireIn(300)).toBe(false);

      // Just after threshold
      expect(session.willExpireIn(301)).toBe(true);
    });
  });

  describe('toAuthorizationHeader()', () => {
    it('should return Bearer token format', () => {
      const session = createTestSession();
      const header = session.toAuthorizationHeader();

      expect(header).toBe(`Bearer ${session.token}`);
      expect(header).toMatch(/^Bearer /);
    });
  });

  describe('toJSON()', () => {
    it('should serialize to plain object', () => {
      const expiresAt = new Date(Date.now() + 3600 * 1000);
      const session = new Session(
        'test.token',
        expiresAt,
        {
          did: 'did:key:z6MkTest',
          name: 'TestAgent',
          capabilities: ['read'],
        }
      );

      const json = session.toJSON();

      expect(json).toEqual({
        token: 'test.token',
        expiresAt: expiresAt.toISOString(),
        agent: {
          did: 'did:key:z6MkTest',
          name: 'TestAgent',
          capabilities: ['read'],
        },
      });
    });

    it('should be JSON-stringifiable', () => {
      const session = createTestSession();
      const jsonString = JSON.stringify(session.toJSON());

      expect(jsonString).toBeTruthy();
      expect(() => JSON.parse(jsonString)).not.toThrow();
    });
  });

  describe('fromJSON()', () => {
    it('should restore session from plain object', () => {
      const original = createTestSession();
      const json = original.toJSON();

      const restored = Session.fromJSON(json);

      expect(restored.token).toBe(original.token);
      expect(restored.expiresAt.toISOString()).toBe(original.expiresAt.toISOString());
      expect(restored.agent).toEqual(original.agent);
    });

    it('should round-trip through JSON', () => {
      const original = createTestSession();
      const json = original.toJSON();
      const jsonString = JSON.stringify(json);
      const parsed = JSON.parse(jsonString);
      const restored = Session.fromJSON(parsed);

      expect(restored.token).toBe(original.token);
      expect(restored.agent).toEqual(original.agent);
    });

    it('should preserve expiry state', () => {
      const expiredSession = createTestSession(-120);
      const json = expiredSession.toJSON();
      const restored = Session.fromJSON(json);

      expect(restored.isExpired).toBe(true);
    });
  });
});
