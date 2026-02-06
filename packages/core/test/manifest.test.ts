import { describe, it, expect } from 'vitest'
import {
  signManifest,
  verifyManifest,
  createVerificationMethod,
  validateManifestSequence,
} from '../src/manifest'
import type { UnsignedManifest, AgentManifest } from '../src/types'
import { generateKeyPair } from '../src/crypto'
import { publicKeyToDidKey } from '../src/did'
import { AuthError, AuthErrorCode } from '../src/errors'

function createTestManifest(did: string): UnsignedManifest {
  const now = new Date()
  const validUntil = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000) // 30 days

  return {
    $schema: 'https://schema.agentauth.org/v1/manifest.json',
    version: '1.0.0',
    id: did,
    sequence: 1,
    created_at: now.toISOString(),
    updated_at: now.toISOString(),
    valid_until: validUntil.toISOString(),
    metadata: {
      name: 'TestAgent',
      description: 'A test agent for unit tests',
      agent_version: '1.0.0',
    },
    capabilities: {
      interfaces: [
        {
          protocol: 'https' as const,
          url: 'https://example.com/api',
        },
      ],
    },
  }
}

describe('Manifest Signing and Verification', () => {
  describe('signManifest', () => {
    it('should sign a manifest', async () => {
      const keyPair = generateKeyPair()
      const did = publicKeyToDidKey(keyPair.publicKey)
      const unsignedManifest = createTestManifest(did)
      const verificationMethod = createVerificationMethod(did)

      const signed = await signManifest(
        unsignedManifest,
        keyPair.privateKey,
        verificationMethod
      )

      expect(signed).toHaveProperty('proof')
      expect(signed.proof.type).toBe('Ed25519Signature2020')
      expect(signed.proof.proof_purpose).toBe('assertionMethod')
      expect(signed.proof.proof_value).toMatch(/^z[1-9A-HJ-NP-Za-km-z]+$/)
      expect(signed.proof.verification_method).toBe(verificationMethod)
    })

    it('should preserve all unsigned fields', async () => {
      const keyPair = generateKeyPair()
      const did = publicKeyToDidKey(keyPair.publicKey)
      const unsignedManifest = createTestManifest(did)
      const verificationMethod = createVerificationMethod(did)

      const signed = await signManifest(
        unsignedManifest,
        keyPair.privateKey,
        verificationMethod
      )

      expect(signed.id).toBe(unsignedManifest.id)
      expect(signed.version).toBe(unsignedManifest.version)
      expect(signed.sequence).toBe(unsignedManifest.sequence)
      expect(signed.metadata).toEqual(unsignedManifest.metadata)
      expect(signed.capabilities).toEqual(unsignedManifest.capabilities)
    })

    it('should add created timestamp to proof', async () => {
      const keyPair = generateKeyPair()
      const did = publicKeyToDidKey(keyPair.publicKey)
      const unsignedManifest = createTestManifest(did)
      const verificationMethod = createVerificationMethod(did)

      const before = Date.now()
      const signed = await signManifest(
        unsignedManifest,
        keyPair.privateKey,
        verificationMethod
      )
      const after = Date.now()

      const created = new Date(signed.proof.created).getTime()
      expect(created).toBeGreaterThanOrEqual(before)
      expect(created).toBeLessThanOrEqual(after)
    })
  })

  describe('verifyManifest', () => {
    it('should verify a valid manifest', async () => {
      const keyPair = generateKeyPair()
      const did = publicKeyToDidKey(keyPair.publicKey)
      const unsignedManifest = createTestManifest(did)
      const verificationMethod = createVerificationMethod(did)

      const signed = await signManifest(
        unsignedManifest,
        keyPair.privateKey,
        verificationMethod
      )

      const isValid = await verifyManifest(signed)
      expect(isValid).toBe(true)
    })

    it('should reject manifest with tampered data', async () => {
      const keyPair = generateKeyPair()
      const did = publicKeyToDidKey(keyPair.publicKey)
      const unsignedManifest = createTestManifest(did)
      const verificationMethod = createVerificationMethod(did)

      const signed = await signManifest(
        unsignedManifest,
        keyPair.privateKey,
        verificationMethod
      )

      // Tamper with the manifest
      const tampered = { ...signed }
      tampered.sequence = 999

      try {
        await verifyManifest(tampered)
        expect.fail('Should have thrown')
      } catch (error) {
        expect(error).toBeInstanceOf(AuthError)
        expect((error as AuthError).code).toBe(
          AuthErrorCode.AUTH_INVALID_MANIFEST_SIGNATURE
        )
      }
    })

    it('should reject manifest with wrong signature', async () => {
      const keyPair = generateKeyPair()
      const did = publicKeyToDidKey(keyPair.publicKey)
      const unsignedManifest = createTestManifest(did)
      const verificationMethod = createVerificationMethod(did)

      const signed = await signManifest(
        unsignedManifest,
        keyPair.privateKey,
        verificationMethod
      )

      // Replace with wrong signature
      const tampered: AgentManifest = {
        ...signed,
        proof: {
          ...signed.proof,
          proof_value: 'z' + '1'.repeat(87), // Wrong signature
        },
      }

      try {
        await verifyManifest(tampered)
        expect.fail('Should have thrown')
      } catch (error) {
        expect(error).toBeInstanceOf(AuthError)
      }
    })

    it('should reject manifest with wrong DID', async () => {
      const keyPair1 = generateKeyPair()
      const keyPair2 = generateKeyPair()
      const did1 = publicKeyToDidKey(keyPair1.publicKey)
      const did2 = publicKeyToDidKey(keyPair2.publicKey)

      const unsignedManifest = createTestManifest(did1)
      const verificationMethod = createVerificationMethod(did1)

      const signed = await signManifest(
        unsignedManifest,
        keyPair1.privateKey,
        verificationMethod
      )

      // Change DID to different agent
      const tampered: AgentManifest = { ...signed, id: did2 }

      try {
        await verifyManifest(tampered)
        expect.fail('Should have thrown')
      } catch (error) {
        expect(error).toBeInstanceOf(AuthError)
        const authError = error as AuthError
        expect(
          authError.code === AuthErrorCode.AUTH_DID_MISMATCH ||
            authError.code === AuthErrorCode.AUTH_INVALID_MANIFEST_SIGNATURE
        ).toBe(true)
      }
    })

    it('should reject expired manifest', async () => {
      const keyPair = generateKeyPair()
      const did = publicKeyToDidKey(keyPair.publicKey)
      const verificationMethod = createVerificationMethod(did)

      // Create manifest that expired 1 hour ago
      const now = new Date()
      const expired = new Date(now.getTime() - 60 * 60 * 1000)

      const unsignedManifest: UnsignedManifest = {
        ...createTestManifest(did),
        valid_until: expired.toISOString(),
      }

      const signed = await signManifest(
        unsignedManifest,
        keyPair.privateKey,
        verificationMethod
      )

      try {
        await verifyManifest(signed, { clockSkewSeconds: 0 })
        expect.fail('Should have thrown')
      } catch (error) {
        expect(error).toBeInstanceOf(AuthError)
        expect((error as AuthError).code).toBe(
          AuthErrorCode.AUTH_MANIFEST_EXPIRED
        )
      }
    })

    it('should accept recently expired manifest with clock skew', async () => {
      const keyPair = generateKeyPair()
      const did = publicKeyToDidKey(keyPair.publicKey)
      const verificationMethod = createVerificationMethod(did)

      // Create manifest that expired 30 seconds ago
      const now = new Date()
      const recentlyExpired = new Date(now.getTime() - 30 * 1000)

      const unsignedManifest: UnsignedManifest = {
        ...createTestManifest(did),
        valid_until: recentlyExpired.toISOString(),
      }

      const signed = await signManifest(
        unsignedManifest,
        keyPair.privateKey,
        verificationMethod
      )

      // Should pass with 60s clock skew
      const isValid = await verifyManifest(signed, { clockSkewSeconds: 60 })
      expect(isValid).toBe(true)
    })

    it('should reject manifest with valid_until too far in future', async () => {
      const keyPair = generateKeyPair()
      const did = publicKeyToDidKey(keyPair.publicKey)
      const verificationMethod = createVerificationMethod(did)

      // Create manifest valid for 400 days (exceeds 365 day limit)
      const now = new Date()
      const farFuture = new Date(now.getTime() + 400 * 24 * 60 * 60 * 1000)

      const unsignedManifest: UnsignedManifest = {
        ...createTestManifest(did),
        valid_until: farFuture.toISOString(),
      }

      const signed = await signManifest(
        unsignedManifest,
        keyPair.privateKey,
        verificationMethod
      )

      try {
        await verifyManifest(signed)
        expect.fail('Should have thrown')
      } catch (error) {
        expect(error).toBeInstanceOf(AuthError)
        expect((error as AuthError).code).toBe(
          AuthErrorCode.AUTH_INVALID_REQUEST
        )
      }
    })

    it('should reject manifest with missing proof', async () => {
      const keyPair = generateKeyPair()
      const did = publicKeyToDidKey(keyPair.publicKey)
      const unsignedManifest = createTestManifest(did)

      try {
        await verifyManifest(unsignedManifest as any)
        expect.fail('Should have thrown')
      } catch (error) {
        expect(error).toBeInstanceOf(AuthError)
        expect((error as AuthError).code).toBe(
          AuthErrorCode.AUTH_INVALID_MANIFEST_SIGNATURE
        )
      }
    })

    it('should reject manifest with wrong proof type', async () => {
      const keyPair = generateKeyPair()
      const did = publicKeyToDidKey(keyPair.publicKey)
      const unsignedManifest = createTestManifest(did)
      const verificationMethod = createVerificationMethod(did)

      const signed = await signManifest(
        unsignedManifest,
        keyPair.privateKey,
        verificationMethod
      )

      const tampered: any = { ...signed }
      tampered.proof.type = 'RSASignature2018'

      try {
        await verifyManifest(tampered)
        expect.fail('Should have thrown')
      } catch (error) {
        expect(error).toBeInstanceOf(AuthError)
        expect((error as AuthError).code).toBe(
          AuthErrorCode.AUTH_INVALID_MANIFEST_SIGNATURE
        )
      }
    })
  })

  describe('Round-trip', () => {
    it('should sign and verify successfully', async () => {
      const keyPair = generateKeyPair()
      const did = publicKeyToDidKey(keyPair.publicKey)
      const unsignedManifest = createTestManifest(did)
      const verificationMethod = createVerificationMethod(did)

      const signed = await signManifest(
        unsignedManifest,
        keyPair.privateKey,
        verificationMethod
      )

      const isValid = await verifyManifest(signed)
      expect(isValid).toBe(true)
    })

    it('should work with multiple agents', async () => {
      const agents = Array.from({ length: 5 }, () => generateKeyPair())

      for (const keyPair of agents) {
        const did = publicKeyToDidKey(keyPair.publicKey)
        const unsignedManifest = createTestManifest(did)
        const verificationMethod = createVerificationMethod(did)

        const signed = await signManifest(
          unsignedManifest,
          keyPair.privateKey,
          verificationMethod
        )

        const isValid = await verifyManifest(signed)
        expect(isValid).toBe(true)
      }
    })
  })
})

describe('createVerificationMethod', () => {
  it('should create verification method for did:key', () => {
    const did = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
    const vm = createVerificationMethod(did)

    expect(vm).toBe(`${did}#${did}`)
  })

  it('should create verification method for did:web', () => {
    const did = 'did:web:agent.example.com'
    const vm = createVerificationMethod(did)

    expect(vm).toBe(`${did}#key-1`)
  })

  it('should accept custom key ID for did:web', () => {
    const did = 'did:web:agent.example.com'
    const vm = createVerificationMethod(did, 'signing-key')

    expect(vm).toBe(`${did}#signing-key`)
  })
})

describe('validateManifestSequence', () => {
  it('should allow higher sequence number', () => {
    expect(() => validateManifestSequence(5, 3)).not.toThrow()
  })

  it('should allow equal sequence number', () => {
    expect(() => validateManifestSequence(3, 3)).not.toThrow()
  })

  it('should reject lower sequence number', () => {
    try {
      validateManifestSequence(2, 5)
      expect.fail('Should have thrown')
    } catch (error) {
      expect(error).toBeInstanceOf(AuthError)
      expect((error as AuthError).code).toBe(
        AuthErrorCode.AUTH_MANIFEST_ROLLBACK
      )
    }
  })

  it('should allow first manifest (sequence 1, stored 0)', () => {
    expect(() => validateManifestSequence(1, 0)).not.toThrow()
  })
})
