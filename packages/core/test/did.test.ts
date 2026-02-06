import { describe, it, expect } from 'vitest'
import {
  parseDID,
  publicKeyToDidKey,
  didKeyToPublicKey,
  resolveDID,
} from '../src/did'
import { generateKeyPair } from '../src/crypto'
import { AuthError, AuthErrorCode } from '../src/errors'

describe('DID Parsing', () => {
  describe('parseDID', () => {
    it('should parse valid did:key', () => {
      const did = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
      const parsed = parseDID(did)

      expect(parsed.did).toBe(did)
      expect(parsed.method).toBe('key')
      expect(parsed.identifier).toBe(
        'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
      )
    })

    it('should parse valid did:web', () => {
      const did = 'did:web:agent.example.com'
      const parsed = parseDID(did)

      expect(parsed.did).toBe(did)
      expect(parsed.method).toBe('web')
      expect(parsed.identifier).toBe('agent.example.com')
    })

    it('should parse did:web with path', () => {
      const did = 'did:web:example.com:users:alice'
      const parsed = parseDID(did)

      expect(parsed.method).toBe('web')
      expect(parsed.identifier).toBe('example.com:users:alice')
    })

    it('should reject non-DID strings', () => {
      expect(() => parseDID('not-a-did')).toThrow(AuthError)
      expect(() => parseDID('http://example.com')).toThrow(AuthError)
    })

    it('should reject unsupported DID methods', () => {
      try {
        parseDID('did:pkh:eth:0x1234')
        expect.fail('Should have thrown')
      } catch (error) {
        expect(error).toBeInstanceOf(AuthError)
        expect((error as AuthError).code).toBe(
          AuthErrorCode.AUTH_UNSUPPORTED_DID_METHOD
        )
      }
    })

    it('should reject malformed DIDs', () => {
      expect(() => parseDID('did:')).toThrow(AuthError)
      expect(() => parseDID('did:key')).toThrow(AuthError)
    })
  })
})

describe('did:key Encoding/Decoding', () => {
  describe('publicKeyToDidKey', () => {
    it('should convert public key to did:key', () => {
      const keyPair = generateKeyPair()
      const didKey = publicKeyToDidKey(keyPair.publicKey)

      expect(didKey).toMatch(/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/)
    })

    it('should be deterministic', () => {
      const keyPair = generateKeyPair()
      const didKey1 = publicKeyToDidKey(keyPair.publicKey)
      const didKey2 = publicKeyToDidKey(keyPair.publicKey)

      expect(didKey1).toBe(didKey2)
    })

    it('should produce different DIDs for different keys', () => {
      const keyPair1 = generateKeyPair()
      const keyPair2 = generateKeyPair()

      const didKey1 = publicKeyToDidKey(keyPair1.publicKey)
      const didKey2 = publicKeyToDidKey(keyPair2.publicKey)

      expect(didKey1).not.toBe(didKey2)
    })

    it('should reject invalid key length', () => {
      const invalidKey = new Uint8Array(16) // Wrong length
      expect(() => publicKeyToDidKey(invalidKey)).toThrow(
        'Ed25519 public key must be 32 bytes'
      )
    })
  })

  describe('didKeyToPublicKey', () => {
    it('should extract public key from did:key', () => {
      const keyPair = generateKeyPair()
      const didKey = publicKeyToDidKey(keyPair.publicKey)
      const extracted = didKeyToPublicKey(didKey)

      expect(extracted).toEqual(keyPair.publicKey)
    })

    it('should round-trip successfully', () => {
      const keyPair = generateKeyPair()
      const didKey = publicKeyToDidKey(keyPair.publicKey)
      const extracted = didKeyToPublicKey(didKey)

      expect(extracted).toEqual(keyPair.publicKey)
      expect(extracted.length).toBe(32)
    })

    it('should reject non-did:key', () => {
      try {
        didKeyToPublicKey('did:web:example.com')
        expect.fail('Should have thrown')
      } catch (error) {
        expect(error).toBeInstanceOf(AuthError)
        expect((error as AuthError).code).toBe(
          AuthErrorCode.AUTH_INVALID_REQUEST
        )
      }
    })

    it('should reject malformed did:key', () => {
      try {
        didKeyToPublicKey('did:key:invalid')
        expect.fail('Should have thrown')
      } catch (error) {
        expect(error).toBeInstanceOf(AuthError)
        expect((error as AuthError).code).toBe(
          AuthErrorCode.AUTH_DID_RESOLUTION_FAILED
        )
      }
    })
  })

  describe('Round-trip multiple keys', () => {
    it('should round-trip 10 different keys successfully', () => {
      for (let i = 0; i < 10; i++) {
        const keyPair = generateKeyPair()
        const didKey = publicKeyToDidKey(keyPair.publicKey)
        const extracted = didKeyToPublicKey(didKey)

        expect(extracted).toEqual(keyPair.publicKey)
      }
    })
  })
})

describe('resolveDID', () => {
  it('should resolve did:key', async () => {
    const keyPair = generateKeyPair()
    const didKey = publicKeyToDidKey(keyPair.publicKey)

    const publicKey = await resolveDID(didKey)

    expect(publicKey).toEqual(keyPair.publicKey)
  })

  it('should reject unsupported DID method', async () => {
    try {
      await resolveDID('did:pkh:eth:0x1234')
      expect.fail('Should have thrown')
    } catch (error) {
      expect(error).toBeInstanceOf(AuthError)
      expect((error as AuthError).code).toBe(
        AuthErrorCode.AUTH_UNSUPPORTED_DID_METHOD
      )
    }
  })
})

describe('did:web Resolution', () => {
  // Note: Full did:web tests would require mocking fetch
  // These are basic structure tests

  it('should reject did:web without network access', async () => {
    // This will fail because we don't have a real did:web server
    try {
      await resolveDID('did:web:nonexistent.example.com', undefined, {
        timeoutMs: 100,
      })
      expect.fail('Should have thrown')
    } catch (error) {
      expect(error).toBeInstanceOf(AuthError)
      expect((error as AuthError).code).toBe(
        AuthErrorCode.AUTH_DID_RESOLUTION_FAILED
      )
    }
  })
})
