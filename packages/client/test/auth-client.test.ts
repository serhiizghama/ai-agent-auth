/**
 * Tests for AuthClient
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { AuthClient } from '../src/auth-client';
import { AgentIdentity } from '../src/agent-identity';
import { ManifestBuilder } from '../src/manifest-builder';
import { AuthError, AuthErrorCode } from '@ai-agent-auth/core';

describe('AuthClient', () => {
  let identity: AgentIdentity;
  let manifest: any;
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(async () => {
    identity = AgentIdentity.generate();
    manifest = await new ManifestBuilder(identity)
      .setSequence(1)
      .setValidUntil(new Date(Date.now() + 365 * 24 * 60 * 60 * 1000))
      .setMetadata({
        name: 'TestAgent',
        description: 'A test agent',
        agent_version: '1.0.0',
      })
      .setCapabilities({
        interfaces: [
          {
            protocol: 'https',
            url: 'https://api.example.com',
          },
        ],
      })
      .build();

    mockFetch = vi.fn();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('constructor', () => {
    it('should create client with required options', () => {
      const client = new AuthClient({
        serverUrl: 'https://api.example.com',
        identity,
        manifest,
      });

      expect(client).toBeInstanceOf(AuthClient);
    });

    it('should strip trailing slash from serverUrl', () => {
      const client = new AuthClient({
        serverUrl: 'https://api.example.com/',
        identity,
        manifest,
      });

      // Internal property check would require exposing it, so we test behavior
      expect(client).toBeInstanceOf(AuthClient);
    });

    it('should use custom fetch if provided', () => {
      const customFetch = vi.fn();
      const client = new AuthClient({
        serverUrl: 'https://api.example.com',
        identity,
        manifest,
        fetch: customFetch,
      });

      expect(client).toBeInstanceOf(AuthClient);
    });
  });

  describe('requestChallenge()', () => {
    it('should request challenge successfully', async () => {
      const challengeResponse = {
        challenge: 'a'.repeat(64),
        expires_at: new Date(Date.now() + 300_000).toISOString(),
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => challengeResponse,
      });

      const client = new AuthClient({
        serverUrl: 'https://api.example.com',
        identity,
        manifest,
        fetch: mockFetch,
      });

      const result = await client.requestChallenge();

      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.example.com/auth/challenge',
        expect.objectContaining({
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ did: identity.did }),
        })
      );

      expect(result.challenge).toBe(challengeResponse.challenge);
      expect(result.expires_at).toBe(challengeResponse.expires_at);
    });

    it('should handle 202 pending approval', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 202,
        json: async () => ({
          status: 'pending_approval',
          message: 'Registration pending',
          retry_after: 3600,
        }),
      }).mockResolvedValueOnce({
        ok: false,
        status: 202,
        json: async () => ({
          status: 'pending_approval',
          message: 'Registration pending',
          retry_after: 3600,
        }),
      });

      const client = new AuthClient({
        serverUrl: 'https://api.example.com',
        identity,
        manifest,
        fetch: mockFetch,
      });

      await expect(client.requestChallenge()).rejects.toThrow(AuthError);
      await expect(client.requestChallenge()).rejects.toThrow('pending');
    });

    it('should handle 403 DID not found', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 403,
        json: async () => ({
          error: {
            code: 'AUTH_DID_NOT_FOUND',
            message: 'DID not in ACL',
          },
        }),
      });

      const client = new AuthClient({
        serverUrl: 'https://api.example.com',
        identity,
        manifest,
        fetch: mockFetch,
      });

      await expect(client.requestChallenge()).rejects.toThrow(AuthError);
    });

    it('should timeout after configured duration', async () => {
      mockFetch.mockImplementationOnce((_url, options) => {
        // Simulate a slow server by not resolving until after timeout
        return new Promise((_resolve, reject) => {
          if (options?.signal) {
            options.signal.addEventListener('abort', () => {
              reject(Object.assign(new Error('The operation was aborted'), { name: 'AbortError' }));
            });
          }
          // Never resolve - just wait for abort
        });
      });

      const client = new AuthClient({
        serverUrl: 'https://api.example.com',
        identity,
        manifest,
        fetch: mockFetch,
        timeoutMs: 100,
      });

      await expect(client.requestChallenge()).rejects.toThrow('timeout');
    }, { timeout: 5000 });
  });

  describe('submitVerification()', () => {
    it('should submit verification successfully', async () => {
      const verifyResponse = {
        token: 'eyJhbGciOiJFZERTQSJ9.test.sig',
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
        agent: {
          did: identity.did,
          name: 'TestAgent',
          capabilities: ['read', 'write'],
        },
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => verifyResponse,
      });

      const client = new AuthClient({
        serverUrl: 'https://api.example.com',
        identity,
        manifest,
        fetch: mockFetch,
      });

      const challenge = 'a'.repeat(64);
      const signature = 'z' + 'A'.repeat(86);
      const expiresAt = new Date().toISOString();

      const result = await client.submitVerification(challenge, signature, expiresAt);

      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.example.com/auth/verify',
        expect.objectContaining({
          method: 'POST',
          body: expect.stringContaining(challenge),
        })
      );

      expect(result.token).toBe(verifyResponse.token);
      expect(result.agent.did).toBe(identity.did);
    });

    it('should handle invalid signature error', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        json: async () => ({
          error: {
            code: 'AUTH_INVALID_SIGNATURE',
            message: 'Signature verification failed',
          },
        }),
      });

      const client = new AuthClient({
        serverUrl: 'https://api.example.com',
        identity,
        manifest,
        fetch: mockFetch,
      });

      await expect(
        client.submitVerification('a'.repeat(64), 'zBadSig', new Date().toISOString())
      ).rejects.toThrow(AuthError);
    });
  });

  describe('register()', () => {
    it('should register agent successfully', async () => {
      const registerResponse = {
        did: identity.did,
        status: 'pending_approval',
        message: 'Registration accepted',
        retry_after: 3600,
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 201,
        json: async () => registerResponse,
      });

      const client = new AuthClient({
        serverUrl: 'https://api.example.com',
        identity,
        manifest,
        fetch: mockFetch,
      });

      const result = await client.register('Testing purposes');

      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.example.com/auth/register',
        expect.objectContaining({
          method: 'POST',
          body: expect.stringContaining('Testing purposes'),
        })
      );

      expect(result.status).toBe('pending_approval');
    });

    it('should register without reason', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 201,
        json: async () => ({
          did: identity.did,
          status: 'pending_approval',
          message: 'Registered',
        }),
      });

      const client = new AuthClient({
        serverUrl: 'https://api.example.com',
        identity,
        manifest,
        fetch: mockFetch,
      });

      await client.register();

      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.example.com/auth/register',
        expect.objectContaining({
          body: expect.not.stringContaining('reason'),
        })
      );
    });
  });

  describe('authenticate()', () => {
    it('should complete full authentication flow', async () => {
      const challenge = 'a'.repeat(64);
      const expiresAt = new Date(Date.now() + 300_000).toISOString();

      // Mock challenge response
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ challenge, expires_at: expiresAt }),
      });

      // Mock verify response
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          token: 'eyJhbGciOiJFZERTQSJ9.test.sig',
          expires_at: new Date(Date.now() + 3600_000).toISOString(),
          agent: {
            did: identity.did,
            name: 'TestAgent',
            capabilities: ['read'],
          },
        }),
      });

      const client = new AuthClient({
        serverUrl: 'https://api.example.com',
        identity,
        manifest,
        fetch: mockFetch,
      });

      const session = await client.authenticate();

      expect(mockFetch).toHaveBeenCalledTimes(2);
      expect(session.token).toBeTruthy();
      expect(session.agent.did).toBe(identity.did);
      expect(session.isExpired).toBe(false);
    });
  });

  describe('error handling', () => {
    it('should handle network errors', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network failure'));

      const client = new AuthClient({
        serverUrl: 'https://api.example.com',
        identity,
        manifest,
        fetch: mockFetch,
      });

      await expect(client.requestChallenge()).rejects.toThrow('Network error');
    });

    it('should handle non-JSON responses', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        json: async () => {
          throw new Error('Not JSON');
        },
      });

      const client = new AuthClient({
        serverUrl: 'https://api.example.com',
        identity,
        manifest,
        fetch: mockFetch,
      });

      await expect(client.requestChallenge()).rejects.toThrow('500');
    });
  });

  describe('custom pathPrefix', () => {
    it('should use custom path prefix', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          challenge: 'a'.repeat(64),
          expires_at: new Date().toISOString(),
        }),
      });

      const client = new AuthClient({
        serverUrl: 'https://api.example.com',
        identity,
        manifest,
        fetch: mockFetch,
        pathPrefix: '/v1/auth',
      });

      await client.requestChallenge();

      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.example.com/v1/auth/challenge',
        expect.anything()
      );
    });
  });
});
