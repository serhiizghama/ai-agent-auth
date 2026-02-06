/**
 * @ai-agent-auth/client
 *
 * Client SDK for ai-agent-auth — Agent-side authentication library.
 *
 * Provides classes for managing agent identities, building manifests,
 * and executing the challenge-response authentication flow.
 *
 * @packageDocumentation
 */

// ─── Client SDK Classes ─────────────────────────────────────────────────

export { AgentIdentity } from './agent-identity';
export { ManifestBuilder } from './manifest-builder';
export { AuthClient, type AuthClientOptions } from './auth-client';
export { Session } from './session';

// ─── Re-export Core Types ───────────────────────────────────────────────

export type {
  // DID & Identity
  DIDMethod,
  ParsedDID,
  KeyPair,

  // Manifest
  AgentManifest,
  UnsignedManifest,
  ManifestMetadata,
  ManifestCapabilities,
  ManifestProof,
  AgentInterface,
  APIStandard,
  OperatorInfo,
  RevocationConfig,

  // Protocol
  ChallengeRequest,
  ChallengeResponse,
  VerifyRequest,
  VerifyResponse,
  RegisterRequest,
  RegisterResponse,

  // Errors
  AuthErrorBody,
} from '@ai-agent-auth/core';

// ─── Re-export Error Utilities ──────────────────────────────────────────

export { AuthError, AuthErrorCode } from '@ai-agent-auth/core';
