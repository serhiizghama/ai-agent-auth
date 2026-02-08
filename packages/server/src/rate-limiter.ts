/**
 * Rate Limiting Implementation
 *
 * Provides in-memory rate limiting for authentication endpoints.
 */

import { AuthError, AuthErrorCode } from '@ai-agent-auth/core';
import type { RateLimiter } from './config';

/**
 * Configuration for in-memory rate limiter.
 */
export interface InMemoryRateLimiterConfig {
  /**
   * Maximum requests per window.
   * Default: 10 requests
   */
  maxRequests?: number;

  /**
   * Time window in seconds.
   * Default: 60 seconds (1 minute)
   */
  windowSeconds?: number;
}

interface RequestRecord {
  timestamps: number[];
}

/**
 * In-memory rate limiter implementation.
 *
 * Uses a sliding window algorithm to track requests per key.
 *
 * @example
 * ```typescript
 * const limiter = new InMemoryRateLimiter({
 *   maxRequests: 5,
 *   windowSeconds: 60,
 * });
 *
 * if (await limiter.check(ipAddress, 'challenge')) {
 *   await limiter.record(ipAddress, 'challenge');
 *   // Process request
 * } else {
 *   throw new Error('Rate limit exceeded');
 * }
 * ```
 */
export class InMemoryRateLimiter implements RateLimiter {
  private maxRequests: number;
  private windowMs: number;
  private records: Map<string, RequestRecord> = new Map();
  private cleanupTimer?: NodeJS.Timeout;

  constructor(config: InMemoryRateLimiterConfig = {}) {
    this.maxRequests = config.maxRequests ?? 10;
    this.windowMs = (config.windowSeconds ?? 60) * 1000;

    // Start cleanup timer (every 5 minutes)
    this.cleanupTimer = setInterval(() => this.cleanup(), 5 * 60 * 1000);
    this.cleanupTimer.unref();
  }

  /**
   * Check if request is within rate limit.
   */
  async check(key: string, endpoint: string): Promise<boolean> {
    const recordKey = `${endpoint}:${key}`;
    const now = Date.now();

    const record = this.records.get(recordKey);
    if (!record) {
      return true; // No requests yet
    }

    // Filter out timestamps outside the window
    const validTimestamps = record.timestamps.filter(
      (ts) => now - ts < this.windowMs,
    );

    return validTimestamps.length < this.maxRequests;
  }

  /**
   * Record a request for rate limiting.
   */
  async record(key: string, endpoint: string): Promise<void> {
    const recordKey = `${endpoint}:${key}`;
    const now = Date.now();

    const record = this.records.get(recordKey);
    if (!record) {
      this.records.set(recordKey, { timestamps: [now] });
      return;
    }

    // Filter out old timestamps and add new one
    record.timestamps = record.timestamps.filter(
      (ts) => now - ts < this.windowMs,
    );
    record.timestamps.push(now);
  }

  /**
   * Clean up expired records.
   */
  private cleanup(): void {
    const now = Date.now();

    for (const [key, record] of this.records.entries()) {
      record.timestamps = record.timestamps.filter(
        (ts) => now - ts < this.windowMs,
      );

      // Remove empty records
      if (record.timestamps.length === 0) {
        this.records.delete(key);
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
    this.records.clear();
  }
}

/**
 * Middleware-style rate limiter that throws AuthError.
 *
 * @example
 * ```typescript
 * const limiter = createRateLimitMiddleware(new InMemoryRateLimiter());
 *
 * await limiter.checkAndRecord(req.ip, 'challenge');
 * ```
 */
export class RateLimitMiddleware {
  constructor(private limiter: RateLimiter) {}

  /**
   * Check rate limit and record request, throwing if exceeded.
   *
   * @param key - Identifier (IP, DID, etc.)
   * @param endpoint - Endpoint name
   * @throws {AuthError} with AUTH_RATE_LIMITED if limit exceeded
   */
  async checkAndRecord(key: string, endpoint: string): Promise<void> {
    const allowed = await this.limiter.check(key, endpoint);

    if (!allowed) {
      throw new AuthError(
        AuthErrorCode.AUTH_RATE_LIMITED,
        'Rate limit exceeded. Please try again later.',
        { retry_after: 60 },
      );
    }

    await this.limiter.record(key, endpoint);
  }
}

/**
 * Create a rate limit middleware from a rate limiter instance.
 */
export function createRateLimitMiddleware(
  limiter: RateLimiter,
): RateLimitMiddleware {
  return new RateLimitMiddleware(limiter);
}
