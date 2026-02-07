/**
 * In-memory manifest cache with TTL support
 */

import type { AgentManifest } from '@ai-agent-auth/core';
import type { ManifestCacheStore } from './config';

/**
 * Cached manifest entry with expiry timestamp
 */
interface CachedManifest {
  manifest: AgentManifest;
  expiresAt: number; // Unix timestamp in milliseconds
}

/**
 * In-memory implementation of manifest cache storage.
 *
 * Caches validated agent manifests with a configurable TTL to reduce
 * redundant DID resolution and verification operations.
 *
 * For production, consider using Redis or Memcached for distributed caching.
 *
 * @example
 * ```typescript
 * const cache = new InMemoryManifestCache();
 *
 * // Cache a manifest for 5 minutes
 * await cache.set(did, manifest, 300);
 *
 * // Retrieve it
 * const cached = await cache.get(did);
 *
 * // Invalidate when manifest changes
 * await cache.invalidate(did);
 * ```
 */
export class InMemoryManifestCache implements ManifestCacheStore {
  private cache: Map<string, CachedManifest> = new Map();

  /**
   * Get cached manifest by DID.
   *
   * Returns null if not found or if the cached entry has expired.
   *
   * @param did - The DID to lookup
   * @returns Cached manifest or null
   */
  async get(did: string): Promise<AgentManifest | null> {
    const cached = this.cache.get(did);
    if (!cached) {
      return null;
    }

    // Check if expired
    const now = Date.now();
    if (cached.expiresAt < now) {
      this.cache.delete(did);
      return null;
    }

    return cached.manifest;
  }

  /**
   * Cache a validated manifest.
   *
   * @param did - The DID this manifest belongs to
   * @param manifest - The validated manifest to cache
   * @param ttlSeconds - Time-to-live in seconds
   */
  async set(
    did: string,
    manifest: AgentManifest,
    ttlSeconds: number,
  ): Promise<void> {
    const expiresAt = Date.now() + ttlSeconds * 1000;
    this.cache.set(did, { manifest, expiresAt });
  }

  /**
   * Invalidate cached manifest for a DID.
   *
   * Call this when you know a manifest has changed (e.g., sequence update).
   *
   * @param did - The DID to invalidate
   */
  async invalidate(did: string): Promise<void> {
    this.cache.delete(did);
  }

  /**
   * Remove all expired entries from the cache.
   *
   * @returns Number of entries removed
   */
  async cleanup(): Promise<number> {
    const now = Date.now();
    let removed = 0;

    for (const [did, cached] of this.cache.entries()) {
      if (cached.expiresAt < now) {
        this.cache.delete(did);
        removed++;
      }
    }

    return removed;
  }

  /**
   * Clear all cached manifests. Useful for testing.
   */
  clear(): void {
    this.cache.clear();
  }

  /**
   * Get total number of cached manifests.
   */
  get size(): number {
    return this.cache.size;
  }
}
