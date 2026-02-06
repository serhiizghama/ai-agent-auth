/**
 * Server configuration types and interfaces
 */

import type {
  ACLEntry,
  ACLStatus,
  AgentManifest,
  KeyPair,
  AgentTokenPayload,
} from '@ai-agent-auth/core';
import type { Request } from 'express';

/**
 * Server configuration
 */
export interface ServerConfig {
  /**
   * Server issuer identifier for JWT `iss` claim.
   * Example: "https://api.example.com"
   */
  issuer: string;

  /**
   * JWT signing secret or Ed25519 key pair.
   * If string: used as HMAC-SHA256 secret (HS256).
   * If KeyPair: signs JWT with Ed25519 (EdDSA).
   * Recommended: EdDSA for production.
   */
  jwtSecret: string | KeyPair;

  /**
   * JWT token lifetime in seconds. Default: 3600 (1 hour).
   * Range: 60 (1 min) to 43200 (12 hours).
   */
  tokenLifetimeSeconds?: number;

  /**
   * Challenge lifetime in seconds. Default: 300 (5 minutes).
   * Range: 30 to 600.
   */
  challengeLifetimeSeconds?: number;

  /**
   * Clock skew tolerance in seconds. Default: 60.
   */
  clockSkewSeconds?: number;

  /**
   * ACL store implementation. Default: InMemoryACL.
   */
  acl?: ACLStore;

  /**
   * Challenge store implementation. Default: InMemoryChallengeStore.
   */
  challengeStore?: ChallengeStore;

  /**
   * Manifest cache implementation. Default: InMemoryManifestCache.
   */
  manifestCache?: ManifestCacheStore;

  /**
   * Scopes to grant to authenticated agents.
   */
  scopes?: string | ((did: string, manifest: AgentManifest) => string);

  /**
   * Path prefix for auth endpoints. Default: "/auth".
   */
  pathPrefix?: string;

  /**
   * Enable the /auth/register endpoint. Default: false.
   */
  enableRegistration?: boolean;

  /**
   * Callback invoked when a new agent registers.
   */
  onRegistration?: (entry: ACLEntry) => void | Promise<void>;

  /**
   * Custom fetch for did:web resolution.
   */
  fetch?: typeof globalThis.fetch;

  /**
   * Timeout for did:web DID Document fetches in milliseconds.
   * Default: 2000 (2 seconds). Range: 500–10000.
   */
  didWebResolveTimeoutMs?: number;

  /**
   * Maximum response body size for did:web fetches in bytes.
   * Default: 102400 (100 KB). Range: 1024–1048576 (1 MB).
   */
  didWebResolveMaxBytes?: number;

  /**
   * Maximum HTTP redirects during did:web resolution.
   * Default: 3. Range: 0–5.
   */
  didWebResolveMaxRedirects?: number;
}

/**
 * ACL (Access Control List) storage interface
 */
export interface ACLStore {
  /**
   * Get ACL entry by DID. Returns null if not found.
   */
  get(did: string): Promise<ACLEntry | null>;

  /**
   * Set/update an ACL entry.
   */
  set(entry: ACLEntry): Promise<void>;

  /**
   * Get the maximum manifest sequence seen for a DID. Returns 0 if not found.
   */
  getMaxSequence(did: string): Promise<number>;

  /**
   * Update the stored max sequence for a DID.
   */
  updateSequence(did: string, sequence: number): Promise<void>;

  /**
   * List all entries. Optional status filter.
   */
  list(status?: ACLStatus): Promise<ACLEntry[]>;

  /**
   * Remove an entry.
   */
  delete(did: string): Promise<boolean>;
}

/**
 * Challenge storage interface
 */
export interface ChallengeStore {
  /**
   * Store a new challenge.
   */
  store(challenge: string, did: string, expiresAt: Date): Promise<void>;

  /**
   * Retrieve a stored challenge. Returns null if not found or expired.
   */
  get(challenge: string): Promise<{
    did: string;
    expiresAt: Date;
    used: boolean;
  } | null>;

  /**
   * Mark a challenge as used (consumed). Prevents replay.
   */
  markUsed(challenge: string): Promise<void>;

  /**
   * Remove expired challenges. Returns the number of entries removed.
   */
  cleanup(): Promise<number>;

  /**
   * Graceful shutdown — stop any internal timers / background tasks.
   */
  dispose(): void;
}

/**
 * Manifest cache storage interface
 */
export interface ManifestCacheStore {
  /**
   * Get cached manifest by DID.
   */
  get(did: string): Promise<AgentManifest | null>;

  /**
   * Cache a validated manifest.
   */
  set(did: string, manifest: AgentManifest, ttlSeconds: number): Promise<void>;

  /**
   * Invalidate cached manifest for a DID.
   */
  invalidate(did: string): Promise<void>;
}

/**
 * Extended Express request with authenticated agent info
 */
export interface AuthenticatedRequest extends Request {
  agent: AgentTokenPayload;
}
