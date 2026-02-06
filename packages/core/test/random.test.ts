import { describe, it, expect } from 'vitest'
import { randomBytes } from '../src/random'

describe('randomBytes', () => {
  it('should generate random bytes of specified length', () => {
    const bytes = randomBytes(32)

    expect(bytes).toBeInstanceOf(Uint8Array)
    expect(bytes.length).toBe(32)
  })

  it('should generate different values on successive calls', () => {
    const bytes1 = randomBytes(32)
    const bytes2 = randomBytes(32)

    // Probability of collision is astronomically low (1/2^256)
    expect(bytes1).not.toEqual(bytes2)
  })

  it('should generate bytes of different lengths', () => {
    expect(randomBytes(16).length).toBe(16)
    expect(randomBytes(32).length).toBe(32)
    expect(randomBytes(64).length).toBe(64)
  })

  it('should throw error for non-positive length', () => {
    expect(() => randomBytes(0)).toThrow('Length must be positive')
    expect(() => randomBytes(-1)).toThrow('Length must be positive')
  })

  it('should generate cryptographically random bytes (statistical test)', () => {
    // Generate 1000 random bytes and check distribution
    // Each byte should have roughly equal probability (uniform distribution)
    const bytes = randomBytes(1000)

    // Count occurrences of each byte value (0-255)
    const counts = new Array(256).fill(0)
    for (const byte of bytes) {
      counts[byte]++
    }

    // Check that no single value dominates (very weak test, but catches obvious failures)
    // With 1000 bytes and 256 possible values, average is ~3.9 per value
    // No value should appear more than 20 times (very generous threshold)
    const maxCount = Math.max(...counts)
    expect(maxCount).toBeLessThan(20)
  })

  it('should work in Node.js environment with Web Crypto API', () => {
    // This test verifies that globalThis.crypto is available
    // (Node 20+ has Web Crypto API globally)
    expect(globalThis.crypto).toBeDefined()
    expect(globalThis.crypto.getRandomValues).toBeDefined()

    const bytes = randomBytes(32)
    expect(bytes).toBeInstanceOf(Uint8Array)
  })
})
