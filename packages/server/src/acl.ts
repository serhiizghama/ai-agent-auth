/**
 * In-memory ACL (Access Control List) storage implementation
 */

import type { ACLEntry, ACLStatus } from '@ai-agent-auth/core';
import type { ACLStore } from './config';

/**
 * In-memory implementation of ACL storage.
 *
 * Stores agent access control entries and sequence numbers in memory.
 * Not suitable for production use across multiple instances - use a
 * persistent store (Redis, PostgreSQL, etc.) for production.
 *
 * @example
 * ```typescript
 * const acl = new InMemoryACL();
 *
 * await acl.set({
 *   did: 'did:key:z6Mk...',
 *   status: 'APPROVED',
 *   added_at: new Date().toISOString(),
 *   metadata: { name: 'MyAgent' },
 * });
 *
 * const entry = await acl.get('did:key:z6Mk...');
 * ```
 */
export class InMemoryACL implements ACLStore {
  private entries: Map<string, ACLEntry> = new Map();
  private sequences: Map<string, number> = new Map();

  /**
   * Get ACL entry by DID.
   *
   * @param did - The DID to lookup
   * @returns ACL entry or null if not found
   */
  async get(did: string): Promise<ACLEntry | null> {
    return this.entries.get(did) ?? null;
  }

  /**
   * Set/update an ACL entry.
   *
   * @param entry - The ACL entry to store
   */
  async set(entry: ACLEntry): Promise<void> {
    this.entries.set(entry.did, entry);
  }

  /**
   * Get the maximum manifest sequence seen for a DID.
   *
   * @param did - The DID to check
   * @returns Maximum sequence number, or 0 if not found
   */
  async getMaxSequence(did: string): Promise<number> {
    return this.sequences.get(did) ?? 0;
  }

  /**
   * Update the stored max sequence for a DID.
   *
   * Only updates if the new sequence is greater than the current max.
   *
   * @param did - The DID to update
   * @param sequence - The new sequence number
   */
  async updateSequence(did: string, sequence: number): Promise<void> {
    const current = this.sequences.get(did) ?? 0;
    if (sequence > current) {
      this.sequences.set(did, sequence);
    }
  }

  /**
   * List all entries, optionally filtered by status.
   *
   * @param status - Optional status filter (PENDING, APPROVED, REJECTED, BANNED)
   * @returns Array of ACL entries
   */
  async list(status?: ACLStatus): Promise<ACLEntry[]> {
    const allEntries = Array.from(this.entries.values());

    if (status === undefined) {
      return allEntries;
    }

    return allEntries.filter(entry => entry.status === status);
  }

  /**
   * Remove an entry from the ACL.
   *
   * @param did - The DID to remove
   * @returns true if entry was deleted, false if not found
   */
  async delete(did: string): Promise<boolean> {
    const existed = this.entries.has(did);
    this.entries.delete(did);
    this.sequences.delete(did);
    return existed;
  }

  /**
   * Clear all entries and sequences. Useful for testing.
   */
  clear(): void {
    this.entries.clear();
    this.sequences.clear();
  }

  /**
   * Get total number of entries.
   */
  get size(): number {
    return this.entries.size;
  }
}
