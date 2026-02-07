/**
 * In-memory challenge storage with automatic cleanup
 */

import type { ChallengeStore } from './config';

/**
 * Stored challenge data
 */
interface StoredChallenge {
  did: string;
  expiresAt: Date;
  used: boolean;
}

/**
 * In-memory implementation of challenge storage.
 *
 * Automatically removes expired challenges every 60 seconds.
 * The cleanup timer is unref'd to prevent blocking process exit.
 *
 * Call `dispose()` to stop the cleanup timer on graceful shutdown.
 *
 * @example
 * ```typescript
 * const store = new InMemoryChallengeStore();
 *
 * // Store a challenge
 * await store.store(challenge, did, new Date(Date.now() + 300_000));
 *
 * // Retrieve it
 * const data = await store.get(challenge);
 * if (data && !data.used) {
 *   await store.markUsed(challenge);
 * }
 *
 * // Clean up on shutdown
 * store.dispose();
 * ```
 */
export class InMemoryChallengeStore implements ChallengeStore {
  private challenges: Map<string, StoredChallenge> = new Map();
  private cleanupTimer: NodeJS.Timeout | null = null;
  private cleanupIntervalMs: number;

  /**
   * Create a new InMemoryChallengeStore.
   *
   * @param cleanupIntervalMs - How often to run cleanup (default: 60000 = 1 minute)
   */
  constructor(cleanupIntervalMs = 60_000) {
    this.cleanupIntervalMs = cleanupIntervalMs;
    this.startCleanupTimer();
  }

  /**
   * Store a new challenge.
   *
   * @param challenge - The challenge string (hex)
   * @param did - The DID this challenge is for
   * @param expiresAt - When the challenge expires
   */
  async store(challenge: string, did: string, expiresAt: Date): Promise<void> {
    this.challenges.set(challenge, {
      did,
      expiresAt,
      used: false,
    });
  }

  /**
   * Retrieve a stored challenge.
   *
   * Returns null if not found or if the challenge has expired.
   *
   * @param challenge - The challenge string to lookup
   * @returns Challenge data or null
   */
  async get(
    challenge: string,
  ): Promise<{ did: string; expiresAt: Date; used: boolean } | null> {
    const stored = this.challenges.get(challenge);
    if (!stored) {
      return null;
    }

    // Check if expired
    if (stored.expiresAt.getTime() < Date.now()) {
      this.challenges.delete(challenge);
      return null;
    }

    return stored;
  }

  /**
   * Mark a challenge as used (consumed).
   *
   * This prevents replay attacks by ensuring a challenge can only be
   * verified once.
   *
   * @param challenge - The challenge string to mark as used
   */
  async markUsed(challenge: string): Promise<void> {
    const stored = this.challenges.get(challenge);
    if (stored) {
      stored.used = true;
    }
  }

  /**
   * Remove expired challenges from storage.
   *
   * @returns The number of challenges removed
   */
  async cleanup(): Promise<number> {
    const now = Date.now();
    let removed = 0;

    for (const [challenge, data] of this.challenges.entries()) {
      if (data.expiresAt.getTime() < now) {
        this.challenges.delete(challenge);
        removed++;
      }
    }

    return removed;
  }

  /**
   * Graceful shutdown — stop the cleanup timer.
   *
   * Call this when shutting down the server to ensure the timer doesn't
   * prevent process exit.
   */
  dispose(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
  }

  /**
   * Start the automatic cleanup timer.
   *
   * The timer is unref'd so it doesn't prevent process exit.
   */
  private startCleanupTimer(): void {
    this.cleanupTimer = setInterval(() => {
      void this.cleanup();
    }, this.cleanupIntervalMs);

    // Unref so it doesn't block process exit
    this.cleanupTimer.unref();
  }

  /**
   * Clear all challenges. Useful for testing.
   */
  clear(): void {
    this.challenges.clear();
  }

  /**
   * Get total number of stored challenges.
   */
  get size(): number {
    return this.challenges.size;
  }
}
