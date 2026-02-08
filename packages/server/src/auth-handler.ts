/**
 * AgentAuthHandler — Core authentication flow logic
 */

import {
  AuthError,
  AuthErrorCode,
  verifyManifest,
  verifyChallengeSignature,
  resolveDID,
  generateChallenge,
  type AgentManifest,
  type ACLEntry,
  type ChallengeResponse,
  type VerifyResponse,
  type RegisterResponse,
  ChallengeRequestSchema,
  VerifyRequestSchema,
  RegisterRequestSchema,
} from '@ai-agent-auth/core';
import type { ServerConfig } from './config';
import { InMemoryACL } from './acl';
import { InMemoryChallengeStore } from './challenge-store';
import { InMemoryManifestCache } from './manifest-cache';
import { signJWT, verifyJWT } from './jwt';

/**
 * AgentAuthHandler manages the challenge-response authentication flow.
 *
 * Handles three endpoints:
 * - POST /auth/challenge — Request challenge
 * - POST /auth/verify — Submit signed challenge + manifest
 * - POST /auth/register — Request access (if enabled)
 *
 * @example
 * ```typescript
 * const handler = new AgentAuthHandler({
 *   issuer: 'https://api.example.com',
 *   jwtSecret: keyPair,
 * });
 *
 * // Handle challenge request
 * const challengeResponse = await handler.handleChallenge({ did: 'did:key:z6Mk...' });
 *
 * // Handle verification
 * const verifyResponse = await handler.handleVerify({
 *   did: 'did:key:z6Mk...',
 *   challenge,
 *   signature,
 *   manifest,
 * });
 *
 * // Clean up on shutdown
 * handler.destroy();
 * ```
 */
export class AgentAuthHandler {
  private config: Omit<Required<ServerConfig>, 'onRegistration' | 'fetch' | 'rateLimiter' | 'revocationChecker'> & {
    onRegistration?: ServerConfig['onRegistration'];
    fetch: typeof globalThis.fetch;
    rateLimiter?: ServerConfig['rateLimiter'];
    revocationChecker?: ServerConfig['revocationChecker'];
  };

  constructor(config: ServerConfig) {
    // Set defaults
    this.config = {
      issuer: config.issuer,
      jwtSecret: config.jwtSecret,
      tokenLifetimeSeconds: config.tokenLifetimeSeconds ?? 3600,
      challengeLifetimeSeconds: config.challengeLifetimeSeconds ?? 300,
      clockSkewSeconds: config.clockSkewSeconds ?? 60,
      acl: config.acl ?? new InMemoryACL(),
      challengeStore: config.challengeStore ?? new InMemoryChallengeStore(),
      manifestCache:
        config.manifestCache ?? new InMemoryManifestCache(),
      scopes: config.scopes ?? 'read',
      pathPrefix: config.pathPrefix ?? '/auth',
      enableRegistration: config.enableRegistration ?? false,
      onRegistration: config.onRegistration,
      fetch: config.fetch ?? globalThis.fetch,
      didWebResolveTimeoutMs: config.didWebResolveTimeoutMs ?? 2000,
      didWebResolveMaxBytes: config.didWebResolveMaxBytes ?? 102400,
      didWebResolveMaxRedirects: config.didWebResolveMaxRedirects ?? 3,
      rateLimiter: config.rateLimiter,
      revocationChecker: config.revocationChecker,
    };
  }

  /**
   * Handle POST /auth/challenge
   *
   * Validates DID is in ACL and approved, generates a challenge.
   *
   * @param body - Request body (must have `did` field)
   * @param clientKey - Optional key for rate limiting (e.g., IP address)
   * @returns Challenge response with hex challenge and expiry
   * @throws {AuthError} if DID not found, rejected, or banned
   */
  async handleChallenge(body: unknown, clientKey?: string): Promise<ChallengeResponse> {
    // Rate limiting
    if (this.config.rateLimiter && clientKey) {
      const allowed = await this.config.rateLimiter.check(clientKey, 'challenge');
      if (!allowed) {
        throw new AuthError(
          AuthErrorCode.AUTH_RATE_LIMITED,
          'Rate limit exceeded. Please try again later.',
          { retry_after: 60 },
        );
      }
    }

    // Validate request body
    const validation = ChallengeRequestSchema.safeParse(body);
    if (!validation.success) {
      throw new AuthError(
        AuthErrorCode.AUTH_INVALID_REQUEST,
        'Invalid challenge request',
        { zodErrors: validation.error.errors },
      );
    }

    const { did } = validation.data;

    // Record rate limit after validation
    if (this.config.rateLimiter && clientKey) {
      await this.config.rateLimiter.record(clientKey, 'challenge');
    }

    // Check ACL
    const aclEntry = await this.config.acl.get(did);

    if (!aclEntry) {
      // DID not found in ACL
      if (this.config.enableRegistration) {
        // Registration enabled - suggest agent to register
        throw new AuthError(
          AuthErrorCode.AUTH_DID_NOT_FOUND,
          'DID not in ACL. Use /auth/register to request access.',
        );
      } else {
        // Registration disabled - just deny
        throw new AuthError(
          AuthErrorCode.AUTH_DID_NOT_FOUND,
          'DID not authorized',
        );
      }
    }

    // Check ACL status
    if (aclEntry.status === 'pending_approval') {
      throw new AuthError(
        AuthErrorCode.AUTH_DID_PENDING,
        'DID registration is pending approval',
        { retry_after: 3600 },
      );
    }

    if (aclEntry.status === 'rejected') {
      throw new AuthError(
        AuthErrorCode.AUTH_DID_REJECTED,
        'DID has been rejected',
      );
    }

    if (aclEntry.status === 'banned') {
      throw new AuthError(
        AuthErrorCode.AUTH_DID_BANNED,
        'DID has been banned',
      );
    }

    // Generate challenge
    const challenge = generateChallenge();
    const expiresAt = new Date(
      Date.now() + this.config.challengeLifetimeSeconds * 1000,
    );

    // Store challenge
    await this.config.challengeStore.store(challenge, did, expiresAt);

    return {
      challenge,
      expires_at: expiresAt.toISOString(),
    };
  }

  /**
   * Fetch manifest from remote endpoint for did:web agents.
   *
   * @param did - The DID to fetch manifest for
   * @returns Remote manifest or null if not fetchable
   */
  private async fetchRemoteManifest(
    did: string,
  ): Promise<AgentManifest | null> {
    // Only fetch for did:web
    if (!did.startsWith('did:web:')) {
      return null;
    }

    try {
      // Extract domain from did:web:domain
      // Format: did:web:example.com or did:web:example.com:path:to:agent
      const didParts = did.split(':');
      if (didParts.length < 3) {
        return null;
      }

      // Domain is the third part (index 2)
      const domain = didParts[2];

      // Build manifest URL: https://domain/.well-known/agent-manifest.json
      const manifestUrl = `https://${domain}/.well-known/agent-manifest.json`;

      // Fetch with same safety limits as did:web resolution
      const controller = new AbortController();
      const timeoutId = setTimeout(
        () => controller.abort(),
        this.config.didWebResolveTimeoutMs,
      );

      try {
        const response = await this.config.fetch(manifestUrl, {
          signal: controller.signal,
          headers: {
            Accept: 'application/json',
          },
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
          return null;
        }

        // Check content-length
        const contentLength = response.headers.get('content-length');
        if (contentLength && parseInt(contentLength, 10) > this.config.didWebResolveMaxBytes) {
          return null;
        }

        // Read response body with size limit
        const text = await response.text();
        if (text.length > this.config.didWebResolveMaxBytes) {
          return null;
        }

        const json = JSON.parse(text) as AgentManifest;

        // Verify manifest signature before using it
        const isValid = await verifyManifest(json);
        if (!isValid) {
          return null;
        }

        return json;
      } catch (error) {
        clearTimeout(timeoutId);
        // Network errors, timeouts, parse errors → return null (use fallback)
        return null;
      }
    } catch {
      // Any error in URL construction → return null
      return null;
    }
  }

  /**
   * Handle POST /auth/verify
   *
   * Verifies challenge signature and manifest, issues JWT token.
   *
   * @param body - Request body (did, challenge, signature, manifest)
   * @param clientKey - Optional key for rate limiting (e.g., IP address)
   * @returns Verification response with JWT token
   * @throws {AuthError} if verification fails
   */
  async handleVerify(body: unknown, clientKey?: string): Promise<VerifyResponse> {
    // Rate limiting
    if (this.config.rateLimiter && clientKey) {
      const allowed = await this.config.rateLimiter.check(clientKey, 'verify');
      if (!allowed) {
        throw new AuthError(
          AuthErrorCode.AUTH_RATE_LIMITED,
          'Rate limit exceeded. Please try again later.',
          { retry_after: 60 },
        );
      }
    }

    // Validate request body
    const validation = VerifyRequestSchema.safeParse(body);
    if (!validation.success) {
      throw new AuthError(
        AuthErrorCode.AUTH_INVALID_REQUEST,
        'Invalid verify request',
        { zodErrors: validation.error.errors },
      );
    }

    const { did, challenge, signature, manifest: requestManifest } = validation.data;

    // Record rate limit after validation
    if (this.config.rateLimiter && clientKey) {
      await this.config.rateLimiter.record(clientKey, 'verify');
    }

    // For did:web, attempt to fetch manifest remotely
    // Use remote manifest if available, otherwise fall back to request body
    const remoteManifest = await this.fetchRemoteManifest(did);
    const manifest = remoteManifest ?? requestManifest;

    // 1. Retrieve and validate challenge
    const storedChallenge = await this.config.challengeStore.get(challenge);
    if (!storedChallenge) {
      throw new AuthError(
        AuthErrorCode.AUTH_CHALLENGE_NOT_FOUND,
        'Challenge not found or expired',
      );
    }

    if (storedChallenge.used) {
      throw new AuthError(
        AuthErrorCode.AUTH_CHALLENGE_ALREADY_USED,
        'Challenge has already been used',
      );
    }

    if (storedChallenge.did !== did) {
      throw new AuthError(
        AuthErrorCode.AUTH_DID_MISMATCH,
        'Challenge was issued for a different DID',
      );
    }

    // Check challenge expiry with clock skew
    const now = Date.now();
    const expiryWithSkew =
      storedChallenge.expiresAt.getTime() + this.config.clockSkewSeconds * 1000;
    if (now > expiryWithSkew) {
      throw new AuthError(
        AuthErrorCode.AUTH_EXPIRED_CHALLENGE,
        'Challenge has expired',
      );
    }

    // 2. Verify challenge signature
    const publicKey = await resolveDID(did, undefined, {
      fetchFn: this.config.fetch,
      timeoutMs: this.config.didWebResolveTimeoutMs,
      maxBytes: this.config.didWebResolveMaxBytes,
      maxRedirects: this.config.didWebResolveMaxRedirects,
    });

    const signatureValid = await verifyChallengeSignature(
      challenge,
      did,
      storedChallenge.expiresAt.toISOString(),
      signature,
      publicKey,
    );

    if (!signatureValid) {
      throw new AuthError(
        AuthErrorCode.AUTH_INVALID_SIGNATURE,
        'Challenge signature verification failed',
      );
    }

    // 3. Verify manifest
    const manifestValid = await verifyManifest(manifest);
    if (!manifestValid) {
      throw new AuthError(
        AuthErrorCode.AUTH_INVALID_MANIFEST_SIGNATURE,
        'Manifest signature verification failed',
      );
    }

    // 3a. Check manifest revocation (if revocation checker is configured)
    if (this.config.revocationChecker) {
      await this.config.revocationChecker.check(manifest);
      // If revoked, this will throw AuthError with AUTH_MANIFEST_REVOKED
    }

    // 4. Validate manifest DID matches
    if (manifest.id !== did) {
      throw new AuthError(
        AuthErrorCode.AUTH_DID_MISMATCH,
        'Manifest DID does not match request DID',
      );
    }

    // 5. Check manifest expiry with clock skew
    const manifestExpiry = new Date(manifest.valid_until).getTime();
    const maxAllowedExpiry = now + 365 * 24 * 60 * 60 * 1000; // 1 year from now

    // Apply clock skew in past direction only
    const manifestExpiryWithSkew =
      manifestExpiry + this.config.clockSkewSeconds * 1000;

    if (now > manifestExpiryWithSkew) {
      throw new AuthError(
        AuthErrorCode.AUTH_MANIFEST_EXPIRED,
        'Manifest has expired',
      );
    }

    if (manifestExpiry > maxAllowedExpiry) {
      throw new AuthError(
        AuthErrorCode.AUTH_INVALID_REQUEST,
        'Manifest valid_until exceeds 1 year maximum',
      );
    }

    // 6. Check manifest sequence number
    const storedSequence = await this.config.acl.getMaxSequence(did);
    if (manifest.sequence <= storedSequence) {
      throw new AuthError(
        AuthErrorCode.AUTH_MANIFEST_ROLLBACK,
        `Manifest sequence ${manifest.sequence} is not greater than stored ${storedSequence}`,
      );
    }

    // 7. Update sequence number
    await this.config.acl.updateSequence(did, manifest.sequence);

    // 8. Cache manifest
    await this.config.manifestCache.set(
      did,
      manifest,
      this.config.tokenLifetimeSeconds,
    );

    // 9. Mark challenge as used
    await this.config.challengeStore.markUsed(challenge);

    // 10. Determine scopes
    const scopes =
      typeof this.config.scopes === 'function'
        ? this.config.scopes(did, manifest)
        : this.config.scopes;

    // 11. Issue JWT
    const token = await signJWT(
      {
        scope: scopes,
        agent_name: manifest.metadata.name,
        agent_version: manifest.metadata.agent_version,
        manifest_sequence: manifest.sequence,
      },
      did,
      {
        issuer: this.config.issuer,
        lifetimeSeconds: this.config.tokenLifetimeSeconds,
        secret: this.config.jwtSecret,
      },
    );

    const expiresAt = new Date(
      Date.now() + this.config.tokenLifetimeSeconds * 1000,
    );

    return {
      token,
      expires_at: expiresAt.toISOString(),
      agent: {
        did,
        name: manifest.metadata.name,
        capabilities: scopes.split(' '),
      },
    };
  }

  /**
   * Handle POST /auth/register
   *
   * Registers a new agent for access approval.
   *
   * @param body - Request body (manifest, optional reason)
   * @param clientKey - Optional key for rate limiting (e.g., IP address)
   * @returns Registration response with status
   * @throws {AuthError} if registration disabled or invalid
   */
  async handleRegister(body: unknown, clientKey?: string): Promise<RegisterResponse> {
    if (!this.config.enableRegistration) {
      throw new AuthError(
        AuthErrorCode.AUTH_INVALID_REQUEST,
        'Registration endpoint is disabled',
      );
    }

    // Rate limiting
    if (this.config.rateLimiter && clientKey) {
      const allowed = await this.config.rateLimiter.check(clientKey, 'register');
      if (!allowed) {
        throw new AuthError(
          AuthErrorCode.AUTH_RATE_LIMITED,
          'Rate limit exceeded. Please try again later.',
          { retry_after: 60 },
        );
      }
    }

    // Validate request body
    const validation = RegisterRequestSchema.safeParse(body);
    if (!validation.success) {
      throw new AuthError(
        AuthErrorCode.AUTH_INVALID_REQUEST,
        'Invalid register request',
        { zodErrors: validation.error.errors },
      );
    }

    const { manifest, reason } = validation.data;

    // Record rate limit after validation
    if (this.config.rateLimiter && clientKey) {
      await this.config.rateLimiter.record(clientKey, 'register');
    }

    // Verify manifest signature
    const manifestValid = await verifyManifest(manifest);
    if (!manifestValid) {
      throw new AuthError(
        AuthErrorCode.AUTH_INVALID_MANIFEST_SIGNATURE,
        'Manifest signature verification failed',
      );
    }

    const did = manifest.id;

    // Check if already exists
    const existing = await this.config.acl.get(did);
    if (existing) {
      // Already registered - return current status
      return {
        did,
        status: existing.status === 'approved' ? 'approved' : existing.status === 'pending_approval' ? 'pending_approval' : 'rejected',
        message:
          existing.status === 'approved'
            ? 'Agent already registered and approved'
            : existing.status === 'pending_approval'
              ? 'Registration already pending'
              : 'Agent registration was rejected',
        retry_after: existing.status === 'pending_approval' ? 3600 : undefined,
      };
    }

    // Create new ACL entry
    const now = new Date().toISOString();
    const entry: ACLEntry = {
      did,
      status: 'pending_approval',
      manifest_sequence: manifest.sequence,
      registered_at: now,
      updated_at: now,
      ...(reason && { reason }),
      metadata: {
        name: manifest.metadata.name,
        description: manifest.metadata.description,
        agent_version: manifest.metadata.agent_version,
      },
    };

    await this.config.acl.set(entry);

    // Call registration callback if provided
    if (this.config.onRegistration) {
      await this.config.onRegistration(entry);
    }

    return {
      did,
      status: 'pending_approval',
      message: 'Registration request received. Awaiting approval.',
      retry_after: 3600,
    };
  }

  /**
   * Validate a JWT token.
   *
   * Use this in guard middleware to protect routes.
   *
   * @param token - JWT token string (without "Bearer " prefix)
   * @returns Decoded agent token payload
   * @throws {AuthError} if token is invalid
   */
  async validateToken(token: string) {
    return verifyJWT(token, {
      issuer: this.config.issuer,
      secret: this.config.jwtSecret,
      clockSkewSeconds: this.config.clockSkewSeconds,
    });
  }

  /**
   * Clean up resources (stop background timers).
   *
   * Call this when shutting down the server.
   */
  destroy(): void {
    this.config.challengeStore.dispose();
  }
}
