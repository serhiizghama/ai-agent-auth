import { describe, it, expect } from 'vitest'
import {
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
  RegisterRequestSchema,
} from '../src/schemas'

describe('Primitive Schemas', () => {
  describe('didString', () => {
    it('should accept valid did:key', () => {
      const result = didString.safeParse(
        'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
      )
      expect(result.success).toBe(true)
    })

    it('should accept valid did:web', () => {
      const result = didString.safeParse('did:web:agent.example.com')
      expect(result.success).toBe(true)
    })

    it('should reject invalid DID method', () => {
      const result = didString.safeParse('did:pkh:0x1234')
      expect(result.success).toBe(false)
    })

    it('should reject non-DID string', () => {
      const result = didString.safeParse('not-a-did')
      expect(result.success).toBe(false)
    })
  })

  describe('iso8601', () => {
    it('should accept valid ISO 8601 with offset', () => {
      const result = iso8601.safeParse('2026-02-06T14:00:00Z')
      expect(result.success).toBe(true)
    })

    it('should accept ISO 8601 with timezone offset', () => {
      const result = iso8601.safeParse('2026-02-06T14:00:00+05:00')
      expect(result.success).toBe(true)
    })

    it('should reject invalid date string', () => {
      const result = iso8601.safeParse('2026-02-06')
      expect(result.success).toBe(false)
    })
  })

  describe('httpsUrl', () => {
    it('should accept HTTPS URL', () => {
      const result = httpsUrl.safeParse('https://example.com')
      expect(result.success).toBe(true)
    })

    it('should reject HTTP URL', () => {
      const result = httpsUrl.safeParse('http://example.com')
      expect(result.success).toBe(false)
    })

    it('should reject non-URL string', () => {
      const result = httpsUrl.safeParse('not-a-url')
      expect(result.success).toBe(false)
    })
  })

  describe('semver', () => {
    it('should accept valid semver', () => {
      const result = semver.safeParse('1.0.0')
      expect(result.success).toBe(true)
    })

    it('should accept semver with prerelease', () => {
      const result = semver.safeParse('2.1.0-beta.1')
      expect(result.success).toBe(true)
    })

    it('should reject invalid semver', () => {
      const result = semver.safeParse('1.0')
      expect(result.success).toBe(false)
    })
  })

  describe('base58btcSignature', () => {
    it('should accept valid base58btc with z prefix', () => {
      const result = base58btcSignature.safeParse(
        'z3FXQqFk3GFm8GpVNdYbKHcNrAiRnvP9xL4MzC7R2jB5n'
      )
      expect(result.success).toBe(true)
    })

    it('should reject signature without z prefix', () => {
      const result = base58btcSignature.safeParse('3FXQqFk3GFm8GpVNdYb')
      expect(result.success).toBe(false)
    })

    it('should reject signature with invalid base58 characters', () => {
      const result = base58btcSignature.safeParse('z0OIl')
      expect(result.success).toBe(false)
    })
  })

  describe('hexString64', () => {
    it('should accept 64-char hex string', () => {
      const result = hexString64.safeParse(
        'a'.repeat(64)
      )
      expect(result.success).toBe(true)
    })

    it('should reject shorter hex string', () => {
      const result = hexString64.safeParse('a'.repeat(32))
      expect(result.success).toBe(false)
    })

    it('should reject non-hex characters', () => {
      const result = hexString64.safeParse('g'.repeat(64))
      expect(result.success).toBe(false)
    })
  })
})

describe('Manifest Schemas', () => {
  describe('OperatorInfoSchema', () => {
    it('should accept valid operator info', () => {
      const result = OperatorInfoSchema.safeParse({
        name: 'Acme AI Labs',
        url: 'https://acme-ai.example.com',
        contact: 'ops@acme-ai.example.com',
      })
      expect(result.success).toBe(true)
    })

    it('should accept minimal operator info', () => {
      const result = OperatorInfoSchema.safeParse({
        name: 'Acme AI Labs',
      })
      expect(result.success).toBe(true)
    })

    it('should reject empty name', () => {
      const result = OperatorInfoSchema.safeParse({
        name: '',
      })
      expect(result.success).toBe(false)
    })
  })

  describe('AgentInterfaceSchema', () => {
    it('should accept valid interface', () => {
      const result = AgentInterfaceSchema.safeParse({
        protocol: 'https',
        url: 'https://agent.example.com/api/v1',
        api_standard: 'openai-v1-chat',
        methods: ['search', 'summarize'],
      })
      expect(result.success).toBe(true)
    })

    it('should accept minimal interface', () => {
      const result = AgentInterfaceSchema.safeParse({
        protocol: 'https',
        url: 'https://agent.example.com/api/v1',
      })
      expect(result.success).toBe(true)
    })

    it('should reject invalid protocol', () => {
      const result = AgentInterfaceSchema.safeParse({
        protocol: 'http',
        url: 'https://agent.example.com/api/v1',
      })
      expect(result.success).toBe(false)
    })
  })

  describe('ManifestCapabilitiesSchema', () => {
    it('should accept valid capabilities', () => {
      const result = ManifestCapabilitiesSchema.safeParse({
        interfaces: [
          {
            protocol: 'https',
            url: 'https://agent.example.com/api/v1',
          },
        ],
        categories: ['ai.text-generation'],
        permissions_required: ['read:data'],
      })
      expect(result.success).toBe(true)
    })

    it('should reject empty interfaces array', () => {
      const result = ManifestCapabilitiesSchema.safeParse({
        interfaces: [],
      })
      expect(result.success).toBe(false)
    })

    it('should reject too many categories', () => {
      const result = ManifestCapabilitiesSchema.safeParse({
        interfaces: [
          {
            protocol: 'https',
            url: 'https://agent.example.com/api/v1',
          },
        ],
        categories: ['cat1', 'cat2', 'cat3', 'cat4', 'cat5', 'cat6'],
      })
      expect(result.success).toBe(false)
    })
  })

  describe('ManifestProofSchema', () => {
    it('should accept valid proof', () => {
      const result = ManifestProofSchema.safeParse({
        type: 'Ed25519Signature2020',
        created: '2026-02-06T14:00:00Z',
        verification_method: 'did:web:agent.example.com#key-1',
        proof_purpose: 'assertionMethod',
        proof_value: 'z3FXQqFk3GFm8GpVNdYbKHcNrAiRnvP9xL4MzC7R2jB5n',
      })
      expect(result.success).toBe(true)
    })

    it('should reject wrong type', () => {
      const result = ManifestProofSchema.safeParse({
        type: 'RSASignature2018',
        created: '2026-02-06T14:00:00Z',
        verification_method: 'did:web:agent.example.com#key-1',
        proof_purpose: 'assertionMethod',
        proof_value: 'z3FXQqFk3GFm8GpVNdYbKHcNrAiRnvP9xL4MzC7R2jB5n',
      })
      expect(result.success).toBe(false)
    })

    it('should reject wrong proof_purpose', () => {
      const result = ManifestProofSchema.safeParse({
        type: 'Ed25519Signature2020',
        created: '2026-02-06T14:00:00Z',
        verification_method: 'did:web:agent.example.com#key-1',
        proof_purpose: 'authentication',
        proof_value: 'z3FXQqFk3GFm8GpVNdYbKHcNrAiRnvP9xL4MzC7R2jB5n',
      })
      expect(result.success).toBe(false)
    })
  })
})

describe('Request/Response Schemas', () => {
  describe('ChallengeRequestSchema', () => {
    it('should accept valid challenge request', () => {
      const result = ChallengeRequestSchema.safeParse({
        did: 'did:web:agent.example.com',
      })
      expect(result.success).toBe(true)
    })

    it('should reject missing did', () => {
      const result = ChallengeRequestSchema.safeParse({})
      expect(result.success).toBe(false)
    })
  })

  describe('ChallengeResponseSchema', () => {
    it('should accept valid challenge response', () => {
      const result = ChallengeResponseSchema.safeParse({
        challenge: 'a'.repeat(64),
        expires_at: '2026-02-06T12:05:00Z',
      })
      expect(result.success).toBe(true)
    })

    it('should reject invalid challenge format', () => {
      const result = ChallengeResponseSchema.safeParse({
        challenge: 'invalid',
        expires_at: '2026-02-06T12:05:00Z',
      })
      expect(result.success).toBe(false)
    })
  })
})
