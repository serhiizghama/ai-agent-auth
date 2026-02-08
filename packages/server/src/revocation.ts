/**
 * Revocation Checking
 *
 * Optional manifest revocation checking via remote endpoint polling.
 */

import { AuthError, AuthErrorCode, type AgentManifest } from '@ai-agent-auth/core';
import type { RevocationChecker, RevocationStatus } from './config';

// Re-export types
export type { RevocationChecker, RevocationStatus };

/**
 * Configuration for HTTP revocation checker.
 */
export interface HttpRevocationCheckerConfig {
  /**
   * Timeout for revocation endpoint requests in milliseconds.
   * Default: 2000 (2 seconds)
   */
  timeoutMs?: number;

  /**
   * Maximum response body size in bytes.
   * Default: 10240 (10 KB)
   */
  maxBytes?: number;

  /**
   * Cache duration for revocation check results in seconds.
   * Default: 300 (5 minutes)
   */
  cacheTtlSeconds?: number;

  /**
   * Custom fetch implementation.
   */
  fetch?: typeof globalThis.fetch;
}

interface CachedStatus {
  status: RevocationStatus;
  expiresAt: Date;
}

/**
 * HTTP-based revocation checker implementation.
 *
 * Queries the `revocation.endpoint` URL from the manifest and expects
 * a JSON response with `{ "revoked": boolean, "reason"?: string }`.
 *
 * @example
 * ```typescript
 * const checker = new HttpRevocationChecker({
 *   timeoutMs: 2000,
 *   cacheTtlSeconds: 300,
 * });
 *
 * const status = await checker.check(manifest);
 * if (status.revoked) {
 *   console.log('Manifest revoked:', status.reason);
 * }
 * ```
 */
export class HttpRevocationChecker implements RevocationChecker {
  private timeoutMs: number;
  private maxBytes: number;
  private cacheTtlSeconds: number;
  private fetch: typeof globalThis.fetch;
  private cache: Map<string, CachedStatus> = new Map();
  private cleanupTimer?: NodeJS.Timeout;

  constructor(config: HttpRevocationCheckerConfig = {}) {
    this.timeoutMs = config.timeoutMs ?? 2000;
    this.maxBytes = config.maxBytes ?? 10240;
    this.cacheTtlSeconds = config.cacheTtlSeconds ?? 300;
    this.fetch = config.fetch ?? globalThis.fetch;

    // Start cleanup timer (every 5 minutes)
    this.cleanupTimer = setInterval(() => this.cleanup(), 5 * 60 * 1000);
    this.cleanupTimer.unref();
  }

  /**
   * Check if a manifest has been revoked.
   */
  async check(manifest: AgentManifest): Promise<RevocationStatus> {
    // If no revocation config, assume not revoked
    if (!manifest.revocation?.endpoint) {
      return {
        revoked: false,
        checked_at: new Date(),
      };
    }

    const endpoint = manifest.revocation.endpoint;

    // Check cache first
    const cached = this.cache.get(manifest.id);
    if (cached && cached.expiresAt > new Date()) {
      return cached.status;
    }

    // Fetch revocation status
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

      try {
        const response = await this.fetch(endpoint, {
          signal: controller.signal,
          headers: {
            Accept: 'application/json',
          },
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
          // If endpoint is unreachable, assume not revoked (fail open)
          return this.cacheAndReturn(manifest.id, {
            revoked: false,
            checked_at: new Date(),
          });
        }

        // Check content-length
        const contentLength = response.headers.get('content-length');
        if (contentLength && parseInt(contentLength, 10) > this.maxBytes) {
          throw new Error('Response too large');
        }

        // Read response body with size limit
        const text = await response.text();
        if (text.length > this.maxBytes) {
          throw new Error('Response too large');
        }

        const data = JSON.parse(text) as {
          revoked: boolean;
          reason?: string;
        };

        const status: RevocationStatus = {
          revoked: data.revoked ?? false,
          reason: data.reason,
          checked_at: new Date(),
        };

        // Throw if revoked
        if (status.revoked) {
          throw new AuthError(
            AuthErrorCode.AUTH_MANIFEST_REVOKED,
            `Manifest has been revoked${status.reason ? `: ${status.reason}` : ''}`,
          );
        }

        return this.cacheAndReturn(manifest.id, status);
      } catch (error) {
        clearTimeout(timeoutId);

        // If this is an AuthError (revoked), rethrow it
        if (error instanceof AuthError) {
          throw error;
        }

        // Network/parse errors → fail open (assume not revoked)
        return this.cacheAndReturn(manifest.id, {
          revoked: false,
          checked_at: new Date(),
        });
      }
    } catch (error) {
      // Rethrow AuthError
      if (error instanceof AuthError) {
        throw error;
      }

      // Other errors → fail open
      return {
        revoked: false,
        checked_at: new Date(),
      };
    }
  }

  /**
   * Cache a status and return it.
   */
  private cacheAndReturn(did: string, status: RevocationStatus): RevocationStatus {
    const expiresAt = new Date(Date.now() + this.cacheTtlSeconds * 1000);
    this.cache.set(did, { status, expiresAt });
    return status;
  }

  /**
   * Clean up expired cache entries.
   */
  private cleanup(): void {
    const now = new Date();
    for (const [did, cached] of this.cache.entries()) {
      if (cached.expiresAt <= now) {
        this.cache.delete(did);
      }
    }
  }

  /**
   * Dispose of resources (stop cleanup timer).
   */
  dispose(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = undefined;
    }
    this.cache.clear();
  }
}

/**
 * No-op revocation checker that always returns not revoked.
 *
 * Useful for testing or when revocation checking is disabled.
 */
export class NoOpRevocationChecker implements RevocationChecker {
  async check(_manifest: AgentManifest): Promise<RevocationStatus> {
    return {
      revoked: false,
      checked_at: new Date(),
    };
  }
}
