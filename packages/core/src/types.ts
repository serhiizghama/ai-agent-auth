/**
 * Core type definitions for ai-agent-auth
 * Based on AAA-SPEC.md Section 4.1
 */

// ─── DID ────────────────────────────────────────────────────────────────

/** Supported DID methods */
export type DIDMethod = 'key' | 'web'

/** A parsed DID string */
export interface ParsedDID {
  /** Full DID string, e.g. "did:web:agent.example.com" */
  did: string
  /** The DID method: "key" or "web" */
  method: DIDMethod
  /** Method-specific identifier (the part after "did:method:") */
  identifier: string
}

// ─── Manifest ───────────────────────────────────────────────────────────

export interface AgentManifest {
  $schema: string
  version: string
  id: string // DID
  sequence: number // ≥ 1, monotonically increasing
  created_at: string // ISO 8601
  updated_at: string // ISO 8601
  valid_until: string // ISO 8601
  revocation?: RevocationConfig
  metadata: ManifestMetadata
  capabilities: ManifestCapabilities
  proof: ManifestProof
}

/** Manifest without the proof field — used as the signing input */
export type UnsignedManifest = Omit<AgentManifest, 'proof'>

export interface RevocationConfig {
  endpoint: string // URL
  check_interval?: number // seconds, default 3600, min 60
}

export interface ManifestMetadata {
  name: string // max 128 chars
  description: string // max 1024 chars
  agent_version: string // SemVer
  tags?: string[] // max 10 items, each max 32 chars
  homepage?: string // URL
  logo?: string // URL (HTTPS only)
  operator?: OperatorInfo
}

export interface OperatorInfo {
  name: string
  url?: string // URL
  contact?: string // email or URL
}

export interface ManifestCapabilities {
  interfaces: AgentInterface[] // at least one
  categories?: string[] // max 5, dot-notation
  permissions_required?: string[]
}

export interface AgentInterface {
  protocol: 'https' | 'wss'
  url: string
  api_standard?: APIStandard
  methods?: string[]
  schema_ref?: string // URL
}

export type APIStandard =
  | 'openai-v1-chat'
  | 'openai-v1-embeddings'
  | 'anthropic-v1-messages'
  | 'mcp-v1'
  | 'a2a-v1'
  | 'custom'

export interface ManifestProof {
  type: 'Ed25519Signature2020'
  created: string // ISO 8601
  verification_method: string // DID URL, e.g. "did:web:example.com#key-1"
  proof_purpose: 'assertionMethod'
  proof_value: string // base58btc with 'z' prefix
}

// ─── Challenge-Response ─────────────────────────────────────────────────

export interface ChallengeRequest {
  did: string
}

export interface ChallengeResponse {
  challenge: string // 64-char hex string (256 bits)
  expires_at: string // ISO 8601
}

export interface VerifyRequest {
  did: string
  challenge: string
  signature: string // base58btc with 'z' prefix
  manifest: AgentManifest
}

export interface VerifyResponse {
  token: string // JWT
  expires_at: string // ISO 8601
  agent: {
    did: string
    name: string
    capabilities: string[] // flattened from manifest
  }
}

export interface RegisterRequest {
  manifest: AgentManifest
  reason?: string // max 1024 chars
}

export interface RegisterResponse {
  did: string
  status: ACLStatus
  message: string
  retry_after?: number // seconds
}

// ─── ACL ────────────────────────────────────────────────────────────────

export type ACLStatus = 'pending_approval' | 'approved' | 'rejected' | 'banned'

export interface ACLEntry {
  did: string
  status: ACLStatus
  manifest_sequence: number
  registered_at: string // ISO 8601
  updated_at: string // ISO 8601
  reason?: string
  metadata?: Record<string, unknown>
}

// ─── Errors ─────────────────────────────────────────────────────────────

export interface AuthErrorBody {
  error: {
    code: string // e.g. "AUTH_INVALID_SIGNATURE"
    message: string // human-readable
    details?: Record<string, unknown>
  }
}

// ─── Cryptography ───────────────────────────────────────────────────────

/** Ed25519 key pair */
export interface KeyPair {
  /** Private key: 32 bytes */
  privateKey: Uint8Array
  /** Public key: 32 bytes */
  publicKey: Uint8Array
}

// ─── JWT ────────────────────────────────────────────────────────────────

/** JWT payload for authenticated agent sessions */
export interface AgentTokenPayload {
  /** Issuer - server identifier */
  iss: string
  /** Subject - agent's DID */
  sub: string
  /** Issued at timestamp (Unix seconds) */
  iat: number
  /** Expiration timestamp (Unix seconds) */
  exp: number
  /** Unique token identifier (UUID v4) */
  jti: string
  /** Space-separated permission scopes */
  scope: string
  /** Agent display name */
  agent_name: string
  /** Agent version */
  agent_version: string
  /** Manifest sequence number */
  manifest_sequence: number
}
