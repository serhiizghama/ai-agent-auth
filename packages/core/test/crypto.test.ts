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

describe('Ed25519 RFC 8032 Test Vectors', () => {
  /**
   * Official test vectors from RFC 8032 Section 7.1
   * https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1
   *
   * These tests verify that our Ed25519 implementation is compatible
   * with the official specification.
   */

  it('should pass RFC 8032 Test Vector 1 (empty message)', async () => {
    // TEST 1: Empty message
    const secretKey = hexToBytes(
      '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
    )
    const publicKey = hexToBytes(
      'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
    )
    const message = new Uint8Array([]) // Empty message
    const expectedSignature = hexToBytes(
      'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'
    )

    // Sign the message
    const signature = await signBytes(message, secretKey)

    // Verify signature matches expected
    expect(bytesToHex(signature)).toBe(bytesToHex(expectedSignature))

    // Verify signature with public key
    const isValid = await verifySignature(signature, message, publicKey)
    expect(isValid).toBe(true)
  })

  it('should pass RFC 8032 Test Vector 2 (1-byte message)', async () => {
    // TEST 2: Single byte message (0x72)
    const secretKey = hexToBytes(
      '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb'
    )
    const publicKey = hexToBytes(
      '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c'
    )
    const message = hexToBytes('72')
    const expectedSignature = hexToBytes(
      '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00'
    )

    // Sign the message
    const signature = await signBytes(message, secretKey)

    // Verify signature matches expected
    expect(bytesToHex(signature)).toBe(bytesToHex(expectedSignature))

    // Verify signature with public key
    const isValid = await verifySignature(signature, message, publicKey)
    expect(isValid).toBe(true)
  })

  it('should pass RFC 8032 Test Vector 3 (2-byte message)', async () => {
    // TEST 3: Two-byte message (0xaf82)
    const secretKey = hexToBytes(
      'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7'
    )
    const publicKey = hexToBytes(
      'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025'
    )
    const message = hexToBytes('af82')
    const expectedSignature = hexToBytes(
      '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a'
    )

    // Sign the message
    const signature = await signBytes(message, secretKey)

    // Verify signature matches expected
    expect(bytesToHex(signature)).toBe(bytesToHex(expectedSignature))

    // Verify signature with public key
    const isValid = await verifySignature(signature, message, publicKey)
    expect(isValid).toBe(true)
  })

  it('should reject invalid signature (tampered)', async () => {
    // Use Test Vector 1 but tamper with signature
    const publicKey = hexToBytes(
      'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
    )
    const message = new Uint8Array([])
    const validSignature = hexToBytes(
      'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'
    )

    // Tamper with signature (flip one bit)
    const tamperedSignature = new Uint8Array(validSignature)
    tamperedSignature[0] ^= 0x01

    // Verification should fail
    const isValid = await verifySignature(tamperedSignature, message, publicKey)
    expect(isValid).toBe(false)
  })

  it('should reject signature with wrong message', async () => {
    // Use Test Vector 1 but verify with different message
    const publicKey = hexToBytes(
      'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
    )
    const correctMessage = new Uint8Array([])
    const wrongMessage = new Uint8Array([0x01])
    const signature = hexToBytes(
      'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'
    )

    // Verification should fail with wrong message
    const isValid = await verifySignature(signature, wrongMessage, publicKey)
    expect(isValid).toBe(false)

    // But succeed with correct message
    const isValidCorrect = await verifySignature(
      signature,
      correctMessage,
      publicKey
    )
    expect(isValidCorrect).toBe(true)
  })
})
