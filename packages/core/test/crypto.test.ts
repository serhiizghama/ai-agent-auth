import { describe, it, expect } from 'vitest'
import {
  generateKeyPair,
  signBytes,
  verifySignature,
  signChallenge,
  verifyChallengeSignature,
  generateChallenge,
  hashSHA256,
  hexToBytes,
  bytesToHex,
} from '../src/crypto'

describe('Key Generation', () => {
  it('should generate a key pair', () => {
    const keyPair = generateKeyPair()

    expect(keyPair.privateKey).toBeInstanceOf(Uint8Array)
    expect(keyPair.publicKey).toBeInstanceOf(Uint8Array)
    expect(keyPair.privateKey.length).toBe(32)
    expect(keyPair.publicKey.length).toBe(32)
  })

  it('should generate different keys on each call', () => {
    const keyPair1 = generateKeyPair()
    const keyPair2 = generateKeyPair()

    expect(keyPair1.privateKey).not.toEqual(keyPair2.privateKey)
    expect(keyPair1.publicKey).not.toEqual(keyPair2.publicKey)
  })

  it('should generate keys with proper entropy', () => {
    const keyPair = generateKeyPair()

    // Check that not all bytes are the same (very basic entropy check)
    const uniqueBytes = new Set(keyPair.privateKey)
    expect(uniqueBytes.size).toBeGreaterThan(1)
  })
})

describe('Signing and Verification', () => {
  describe('signBytes / verifySignature', () => {
    it('should sign and verify data', async () => {
      const keyPair = generateKeyPair()
      const data = new TextEncoder().encode('Hello, World!')

      const signature = await signBytes(data, keyPair.privateKey)
      expect(signature).toBeInstanceOf(Uint8Array)
      expect(signature.length).toBe(64)

      const isValid = await verifySignature(
        signature,
        data,
        keyPair.publicKey
      )
      expect(isValid).toBe(true)
    })

    it('should reject signature with wrong data', async () => {
      const keyPair = generateKeyPair()
      const data = new TextEncoder().encode('Hello, World!')
      const wrongData = new TextEncoder().encode('Hello, World!!')

      const signature = await signBytes(data, keyPair.privateKey)
      const isValid = await verifySignature(
        signature,
        wrongData,
        keyPair.publicKey
      )

      expect(isValid).toBe(false)
    })

    it('should reject signature with wrong public key', async () => {
      const keyPair1 = generateKeyPair()
      const keyPair2 = generateKeyPair()
      const data = new TextEncoder().encode('Hello, World!')

      const signature = await signBytes(data, keyPair1.privateKey)
      const isValid = await verifySignature(
        signature,
        data,
        keyPair2.publicKey
      )

      expect(isValid).toBe(false)
    })

    it('should reject tampered signature', async () => {
      const keyPair = generateKeyPair()
      const data = new TextEncoder().encode('Hello, World!')

      const signature = await signBytes(data, keyPair.privateKey)

      // Tamper with signature
      signature[0] ^= 0xff

      const isValid = await verifySignature(
        signature,
        data,
        keyPair.publicKey
      )

      expect(isValid).toBe(false)
    })

    it('should throw on invalid private key length', async () => {
      const invalidKey = new Uint8Array(16) // Wrong length

      await expect(
        signBytes(new Uint8Array(), invalidKey)
      ).rejects.toThrow('Private key must be 32 bytes')
    })

    it('should throw on invalid public key length', async () => {
      const invalidKey = new Uint8Array(16) // Wrong length

      await expect(
        verifySignature(new Uint8Array(64), new Uint8Array(), invalidKey)
      ).rejects.toThrow('Public key must be 32 bytes')
    })

    it('should throw on invalid signature length', async () => {
      const keyPair = generateKeyPair()
      const invalidSignature = new Uint8Array(32) // Wrong length

      await expect(
        verifySignature(invalidSignature, new Uint8Array(), keyPair.publicKey)
      ).rejects.toThrow('Signature must be 64 bytes')
    })
  })

  describe('Challenge Signing', () => {
    it('should sign and verify challenge', async () => {
      const keyPair = generateKeyPair()
      const challenge = 'a'.repeat(64)
      const did = 'did:web:agent.example.com'
      const expiresAt = '2026-02-06T12:05:00Z'

      const signature = await signChallenge(
        challenge,
        did,
        expiresAt,
        keyPair.privateKey
      )

      expect(signature).toMatch(/^z[1-9A-HJ-NP-Za-km-z]+$/)

      const isValid = await verifyChallengeSignature(
        challenge,
        did,
        expiresAt,
        signature,
        keyPair.publicKey
      )

      expect(isValid).toBe(true)
    })

    it('should produce deterministic signature for same input', async () => {
      const keyPair = generateKeyPair()
      const challenge = 'a'.repeat(64)
      const did = 'did:web:agent.example.com'
      const expiresAt = '2026-02-06T12:05:00Z'

      const sig1 = await signChallenge(
        challenge,
        did,
        expiresAt,
        keyPair.privateKey
      )
      const sig2 = await signChallenge(
        challenge,
        did,
        expiresAt,
        keyPair.privateKey
      )

      expect(sig1).toBe(sig2)
    })

    it('should reject signature with wrong challenge', async () => {
      const keyPair = generateKeyPair()
      const challenge = 'a'.repeat(64)
      const wrongChallenge = 'b'.repeat(64)
      const did = 'did:web:agent.example.com'
      const expiresAt = '2026-02-06T12:05:00Z'

      const signature = await signChallenge(
        challenge,
        did,
        expiresAt,
        keyPair.privateKey
      )

      const isValid = await verifyChallengeSignature(
        wrongChallenge,
        did,
        expiresAt,
        signature,
        keyPair.publicKey
      )

      expect(isValid).toBe(false)
    })

    it('should reject signature with wrong DID', async () => {
      const keyPair = generateKeyPair()
      const challenge = 'a'.repeat(64)
      const did = 'did:web:agent.example.com'
      const wrongDid = 'did:web:attacker.example.com'
      const expiresAt = '2026-02-06T12:05:00Z'

      const signature = await signChallenge(
        challenge,
        did,
        expiresAt,
        keyPair.privateKey
      )

      const isValid = await verifyChallengeSignature(
        challenge,
        wrongDid,
        expiresAt,
        signature,
        keyPair.publicKey
      )

      expect(isValid).toBe(false)
    })

    it('should reject signature with wrong expiresAt', async () => {
      const keyPair = generateKeyPair()
      const challenge = 'a'.repeat(64)
      const did = 'did:web:agent.example.com'
      const expiresAt = '2026-02-06T12:05:00Z'
      const wrongExpiresAt = '2026-02-06T12:06:00Z'

      const signature = await signChallenge(
        challenge,
        did,
        expiresAt,
        keyPair.privateKey
      )

      const isValid = await verifyChallengeSignature(
        challenge,
        did,
        wrongExpiresAt,
        signature,
        keyPair.publicKey
      )

      expect(isValid).toBe(false)
    })

    it('should handle malformed signature gracefully', async () => {
      const keyPair = generateKeyPair()
      const challenge = 'a'.repeat(64)
      const did = 'did:web:agent.example.com'
      const expiresAt = '2026-02-06T12:05:00Z'

      const isValid = await verifyChallengeSignature(
        challenge,
        did,
        expiresAt,
        'z123invalid',
        keyPair.publicKey
      )

      expect(isValid).toBe(false)
    })
  })
})

describe('Challenge Generation', () => {
  it('should generate 64-char hex challenge', () => {
    const challenge = generateChallenge()

    expect(challenge).toMatch(/^[0-9a-f]{64}$/)
    expect(challenge.length).toBe(64)
  })

  it('should generate different challenges', () => {
    const challenge1 = generateChallenge()
    const challenge2 = generateChallenge()

    expect(challenge1).not.toBe(challenge2)
  })

  it('should generate challenges with proper entropy', () => {
    const challenge = generateChallenge()

    // Check that not all characters are the same
    const uniqueChars = new Set(challenge)
    expect(uniqueChars.size).toBeGreaterThan(1)
  })
})

describe('Hashing', () => {
  it('should hash data with SHA-256', () => {
    const data = new TextEncoder().encode('Hello, World!')
    const hash = hashSHA256(data)

    expect(hash).toBeInstanceOf(Uint8Array)
    expect(hash.length).toBe(32)
  })

  it('should produce deterministic hashes', () => {
    const data = new TextEncoder().encode('Hello, World!')
    const hash1 = hashSHA256(data)
    const hash2 = hashSHA256(data)

    expect(hash1).toEqual(hash2)
  })

  it('should produce different hashes for different data', () => {
    const data1 = new TextEncoder().encode('Hello, World!')
    const data2 = new TextEncoder().encode('Hello, World!!')

    const hash1 = hashSHA256(data1)
    const hash2 = hashSHA256(data2)

    expect(hash1).not.toEqual(hash2)
  })

  it('should match known SHA-256 test vector', () => {
    // SHA-256 of empty string
    const data = new Uint8Array()
    const hash = hashSHA256(data)
    const hashHex = bytesToHex(hash)

    expect(hashHex).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    )
  })
})

describe('Hex Utilities', () => {
  describe('hexToBytes', () => {
    it('should convert hex string to bytes', () => {
      const hex = '0102030a0b0c'
      const bytes = hexToBytes(hex)

      expect(bytes).toEqual(new Uint8Array([1, 2, 3, 10, 11, 12]))
    })

    it('should handle empty string', () => {
      const bytes = hexToBytes('')
      expect(bytes).toEqual(new Uint8Array())
    })

    it('should throw on odd-length hex string', () => {
      expect(() => hexToBytes('abc')).toThrow('even length')
    })
  })

  describe('bytesToHex', () => {
    it('should convert bytes to hex string', () => {
      const bytes = new Uint8Array([1, 2, 3, 10, 11, 12])
      const hex = bytesToHex(bytes)

      expect(hex).toBe('0102030a0b0c')
    })

    it('should handle empty array', () => {
      const hex = bytesToHex(new Uint8Array())
      expect(hex).toBe('')
    })

    it('should pad with leading zeros', () => {
      const bytes = new Uint8Array([0, 1, 15, 255])
      const hex = bytesToHex(bytes)

      expect(hex).toBe('00010fff')
    })
  })

  describe('Round-trip', () => {
    it('should successfully round-trip hex conversion', () => {
      const original = 'deadbeef0123456789abcdef'
      const bytes = hexToBytes(original)
      const hex = bytesToHex(bytes)

      expect(hex).toBe(original)
    })

    it('should successfully round-trip byte conversion', () => {
      const original = new Uint8Array([0, 1, 2, 3, 255, 254, 253])
      const hex = bytesToHex(original)
      const bytes = hexToBytes(hex)

      expect(bytes).toEqual(original)
    })
  })
})
