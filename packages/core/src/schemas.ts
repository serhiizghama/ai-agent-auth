/**
 * Zod validation schemas for ai-agent-auth
 * Based on AAA-SPEC.md Section 4.2
 */

import { z } from 'zod'

// ─── Primitives ─────────────────────────────────────────────────────────

export const didString = z
  .string()
  .regex(/^did:(key|web):.+$/, 'Must be a valid did:key or did:web identifier')

export const iso8601 = z.string().datetime({ offset: true })

export const httpsUrl = z.string().url().startsWith('https://')

export const semver = z.string().regex(/^\d+\.\d+\.\d+/)

export const base58btcSignature = z.string().regex(/^z[1-9A-HJ-NP-Za-km-z]+$/)

export const hexString64 = z.string().regex(/^[0-9a-f]{64}$/)

// ─── Manifest Sub-schemas ───────────────────────────────────────────────

export const OperatorInfoSchema = z.object({
  name: z.string().min(1).max(256),
  url: httpsUrl.optional(),
  contact: z.string().max(256).optional(),
})

export const ManifestMetadataSchema = z.object({
  name: z.string().min(1).max(128),
  description: z.string().min(1).max(1024),
  agent_version: semver,
  tags: z.array(z.string().max(32)).max(10).optional(),
  homepage: httpsUrl.optional(),
  logo: httpsUrl.optional(),
  operator: OperatorInfoSchema.optional(),
})

export const AgentInterfaceSchema = z.object({
  protocol: z.enum(['https', 'wss']),
  url: z.string().url(),
  api_standard: z
    .enum([
      'openai-v1-chat',
      'openai-v1-embeddings',
      'anthropic-v1-messages',
      'mcp-v1',
      'a2a-v1',
      'custom',
    ])
    .optional(),
  methods: z.array(z.string()).optional(),
  schema_ref: httpsUrl.optional(),
})

export const ManifestCapabilitiesSchema = z.object({
  interfaces: z.array(AgentInterfaceSchema).min(1),
  categories: z.array(z.string().max(64)).max(5).optional(),
  permissions_required: z.array(z.string()).optional(),
})

export const ManifestProofSchema = z.object({
  type: z.literal('Ed25519Signature2020'),
  created: iso8601,
  verification_method: z.string().min(1),
  proof_purpose: z.literal('assertionMethod'),
  proof_value: base58btcSignature,
})

export const RevocationConfigSchema = z.object({
  endpoint: httpsUrl,
  check_interval: z.number().int().min(60).default(3600).optional(),
})

export const AgentManifestSchema = z.object({
  $schema: z.string().url(),
  version: semver,
  id: didString,
  sequence: z.number().int().min(1),
  created_at: iso8601,
  updated_at: iso8601,
  valid_until: iso8601,
  revocation: RevocationConfigSchema.optional(),
  metadata: ManifestMetadataSchema,
  capabilities: ManifestCapabilitiesSchema,
  proof: ManifestProofSchema,
})

export const UnsignedManifestSchema = AgentManifestSchema.omit({ proof: true })

// ─── Request/Response Schemas ───────────────────────────────────────────

export const ChallengeRequestSchema = z.object({
  did: didString,
})

export const ChallengeResponseSchema = z.object({
  challenge: hexString64,
  expires_at: iso8601,
})

export const VerifyRequestSchema = z.object({
  did: didString,
  challenge: hexString64,
  signature: base58btcSignature,
  manifest: AgentManifestSchema,
})

export const VerifyResponseSchema = z.object({
  token: z.string(),
  expires_at: iso8601,
  agent: z.object({
    did: didString,
    name: z.string(),
    capabilities: z.array(z.string()),
  }),
})

export const RegisterRequestSchema = z.object({
  manifest: AgentManifestSchema,
  reason: z.string().max(1024).optional(),
})

export const RegisterResponseSchema = z.object({
  did: didString,
  status: z.enum(['pending_approval', 'approved', 'rejected', 'banned']),
  message: z.string(),
  retry_after: z.number().int().optional(),
})

// ─── ACL Schema ─────────────────────────────────────────────────────────

export const ACLEntrySchema = z.object({
  did: didString,
  status: z.enum(['pending_approval', 'approved', 'rejected', 'banned']),
  manifest_sequence: z.number().int().min(0),
  registered_at: iso8601,
  updated_at: iso8601,
  reason: z.string().optional(),
  metadata: z.record(z.unknown()).optional(),
})
