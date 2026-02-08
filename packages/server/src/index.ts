/**
 * @ai-agent-auth/server — Server-side authentication middleware
 *
 * Provides Express/Fastify middleware for AI agent authentication using
 * challenge-response protocol with DIDs and Ed25519 signatures.
 *
 * @packageDocumentation
 */

// Configuration types
export type {
  ServerConfig,
  ACLStore,
  ChallengeStore,
  ManifestCacheStore,
  AuthenticatedRequest,
  RateLimiter,
  RevocationChecker,
  RevocationStatus,
} from './config';

// In-memory storage implementations
export { InMemoryACL } from './acl';
export { InMemoryChallengeStore } from './challenge-store';
export { InMemoryManifestCache } from './manifest-cache';

// Rate limiting
export {
  InMemoryRateLimiter,
  RateLimitMiddleware,
  createRateLimitMiddleware,
} from './rate-limiter';
export type { InMemoryRateLimiterConfig } from './rate-limiter';

// Revocation checking
export {
  HttpRevocationChecker,
  NoOpRevocationChecker,
} from './revocation';
export type { HttpRevocationCheckerConfig } from './revocation';

// JWT utilities
export { signJWT, verifyJWT } from './jwt';

// Authentication handler
export { AgentAuthHandler } from './auth-handler';

// Express middleware
export { agentAuthMiddleware } from './middleware';

// Re-export core types that server users need
export type {
  ACLEntry,
  ACLStatus,
  AgentManifest,
  KeyPair,
  AgentTokenPayload,
} from '@ai-agent-auth/core';

export { AuthError, AuthErrorCode } from '@ai-agent-auth/core';
