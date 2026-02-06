/**
 * @ai-agent-auth/core
 * Core cryptographic primitives and types for ai-agent-auth
 */

// ─── Types ──────────────────────────────────────────────────────────────
export type {
  DIDMethod,
  ParsedDID,
  KeyPair,
  AgentManifest,
  UnsignedManifest,
  RevocationConfig,
  ManifestMetadata,
  OperatorInfo,
  ManifestCapabilities,
  AgentInterface,
  APIStandard,
  ManifestProof,
  ChallengeRequest,
  ChallengeResponse,
  VerifyRequest,
  VerifyResponse,
  RegisterRequest,
  RegisterResponse,
  ACLStatus,
  ACLEntry,
  AuthErrorBody,
  AgentTokenPayload,
} from './types'

// ─── Schemas ────────────────────────────────────────────────────────────
export {
  didString,
  iso8601,
  httpsUrl,
  semver,
  base58btcSignature,
  hexString64,
  OperatorInfoSchema,
  ManifestMetadataSchema,
  AgentInterfaceSchema,
  ManifestCapabilitiesSchema,
  ManifestProofSchema,
  RevocationConfigSchema,
  AgentManifestSchema,
  UnsignedManifestSchema,
  ChallengeRequestSchema,
  ChallengeResponseSchema,
  VerifyRequestSchema,
  VerifyResponseSchema,
  RegisterRequestSchema,
  RegisterResponseSchema,
  ACLEntrySchema,
} from './schemas'

// ─── Errors ─────────────────────────────────────────────────────────────
export {
  AuthError,
  AuthErrorCode,
  ERROR_STATUS_MAP,
  ERROR_MESSAGES,
} from './errors'

// ─── Cryptography ──────────────────────────────────────────────────────
export {
  generateKeyPair,
  signBytes,
  verifySignature,
  signChallenge,
  verifyChallengeSignature,
  generateChallenge,
  hashSHA256,
  hexToBytes,
  bytesToHex,
} from './crypto'

export { randomBytes } from './random'

// ─── Base58 ─────────────────────────────────────────────────────────────
export { encodeBase58btc, decodeBase58btc, isValidBase58btc } from './base58'

// ─── JCS ────────────────────────────────────────────────────────────────
export {
  canonicalizeToBytes,
  canonicalizeToString,
  areCanonicallyEqual,
} from './jcs'

// ─── DID ────────────────────────────────────────────────────────────────
export {
  parseDID,
  publicKeyToDidKey,
  didKeyToPublicKey,
  resolveDidWeb,
  resolveDID,
} from './did'

// ─── Manifest ───────────────────────────────────────────────────────────
export {
  signManifest,
  verifyManifest,
  createVerificationMethod,
  validateManifestSequence,
} from './manifest'
