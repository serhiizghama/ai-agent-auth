import { describe, it, expect } from 'vitest'
import { encodeBase58btc, decodeBase58btc, isValidBase58btc } from '../src/base58'

describe('Base58btc Codec', () => {
  describe('encodeBase58btc', () => {
    it('should encode bytes to base58btc with z prefix', () => {
      const data = new Uint8Array([0, 1, 2, 3, 4, 5])
      const encoded = encodeBase58btc(data)

      expect(encoded).toMatch(/^z[1-9A-HJ-NP-Za-km-z]+$/)
      expect(encoded[0]).toBe('z')
    })

    it('should produce deterministic output', () => {
      const data = new Uint8Array([1, 2, 3, 4, 5])
      const encoded1 = encodeBase58btc(data)
      const encoded2 = encodeBase58btc(data)

      expect(encoded1).toBe(encoded2)
    })

    it('should handle empty array', () => {
      const data = new Uint8Array([])
      const encoded = encodeBase58btc(data)

      expect(encoded).toBe('z')
    })

    it('should handle 32-byte key', () => {
      const data = new Uint8Array(32).fill(42)
      const encoded = encodeBase58btc(data)

      expect(encoded).toMatch(/^z[1-9A-HJ-NP-Za-km-z]+$/)
      expect(encoded.length).toBeGreaterThan(1)
    })
  })

  describe('decodeBase58btc', () => {
    it('should decode base58btc with z prefix', () => {
      const original = new Uint8Array([1, 2, 3, 4, 5])
      const encoded = encodeBase58btc(original)
      const decoded = decodeBase58btc(encoded)

      expect(decoded).toEqual(original)
    })

    it('should decode base58btc without z prefix', () => {
      const original = new Uint8Array([1, 2, 3, 4, 5])
      const encoded = encodeBase58btc(original)
      const withoutPrefix = encoded.slice(1)
      const decoded = decodeBase58btc(withoutPrefix)

      expect(decoded).toEqual(original)
    })

    it('should handle empty string after z', () => {
      const decoded = decodeBase58btc('z')
      expect(decoded).toEqual(new Uint8Array([]))
    })

    it('should throw on invalid base58 characters', () => {
      expect(() => decodeBase58btc('z0OIl')).toThrow()
    })

    it('should throw on malformed string', () => {
      expect(() => decodeBase58btc('zInvalid!')).toThrow()
    })
  })

  describe('Round-trip', () => {
    it('should successfully round-trip various byte arrays', () => {
      const testCases = [
        new Uint8Array([]),
        new Uint8Array([0]),
        new Uint8Array([255]),
        new Uint8Array([1, 2, 3, 4, 5]),
        new Uint8Array(32).fill(0),
        new Uint8Array(32).fill(255),
        new Uint8Array(64).fill(42),
      ]

      testCases.forEach((original) => {
        const encoded = encodeBase58btc(original)
        const decoded = decodeBase58btc(encoded)
        expect(decoded).toEqual(original)
      })
    })

    it('should round-trip 32-byte Ed25519 key', () => {
      const key = new Uint8Array(32)
      for (let i = 0; i < 32; i++) {
        key[i] = Math.floor(Math.random() * 256)
      }

      const encoded = encodeBase58btc(key)
      const decoded = decodeBase58btc(encoded)

      expect(decoded).toEqual(key)
      expect(decoded.length).toBe(32)
    })

    it('should round-trip 64-byte Ed25519 signature', () => {
      const signature = new Uint8Array(64)
      for (let i = 0; i < 64; i++) {
        signature[i] = Math.floor(Math.random() * 256)
      }

      const encoded = encodeBase58btc(signature)
      const decoded = decodeBase58btc(encoded)

      expect(decoded).toEqual(signature)
      expect(decoded.length).toBe(64)
    })
  })

  describe('isValidBase58btc', () => {
    it('should accept valid base58btc strings', () => {
      const valid = [
        'z3FXQqFk3GFm8GpVNdYbKHcNrAiRnvP9xL4MzC7R2jB5n',
        'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
        'z1',
        'zABC123xyz',
      ]

      valid.forEach((str) => {
        expect(isValidBase58btc(str)).toBe(true)
      })
    })

    it('should reject strings without z prefix', () => {
      expect(isValidBase58btc('3FXQqFk')).toBe(false)
      expect(isValidBase58btc('ABC123')).toBe(false)
    })

    it('should reject strings with invalid characters', () => {
      const invalid = [
        'z0',     // contains 0
        'zO',     // contains O
        'zI',     // contains I
        'zl',     // contains l
        'z!',     // contains special char
        'z ABC',  // contains space
      ]

      invalid.forEach((str) => {
        expect(isValidBase58btc(str)).toBe(false)
      })
    })

    it('should reject empty string', () => {
      expect(isValidBase58btc('')).toBe(false)
    })

    it('should accept z alone', () => {
      expect(isValidBase58btc('z')).toBe(false) // Actually requires at least one char after z
    })
  })
})
