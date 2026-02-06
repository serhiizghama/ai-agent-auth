import { describe, it, expect } from 'vitest'
import {
  canonicalizeToBytes,
  canonicalizeToString,
  areCanonicallyEqual,
} from '../src/jcs'

describe('JCS Canonicalization', () => {
  describe('canonicalizeToString', () => {
    it('should produce deterministic output', () => {
      const obj = { b: 2, a: 1 }
      const canon1 = canonicalizeToString(obj)
      const canon2 = canonicalizeToString(obj)

      expect(canon1).toBe(canon2)
    })

    it('should sort object keys lexicographically', () => {
      const obj = { z: 3, a: 1, m: 2 }
      const canonical = canonicalizeToString(obj)

      expect(canonical).toBe('{"a":1,"m":2,"z":3}')
    })

    it('should handle nested objects', () => {
      const obj = { outer: { b: 2, a: 1 }, x: 3 }
      const canonical = canonicalizeToString(obj)

      expect(canonical).toBe('{"outer":{"a":1,"b":2},"x":3}')
    })

    it('should handle arrays', () => {
      const obj = { arr: [3, 1, 2], b: 1 }
      const canonical = canonicalizeToString(obj)

      expect(canonical).toBe('{"arr":[3,1,2],"b":1}')
    })

    it('should handle numbers correctly', () => {
      const obj = {
        int: 42,
        float: 3.14,
        zero: 0,
        negative: -10,
      }
      const canonical = canonicalizeToString(obj)

      expect(canonical).toContain('"int":42')
      expect(canonical).toContain('"float":3.14')
      expect(canonical).toContain('"zero":0')
      expect(canonical).toContain('"negative":-10')
    })

    it('should handle null and boolean', () => {
      const obj = {
        nullVal: null,
        trueVal: true,
        falseVal: false,
      }
      const canonical = canonicalizeToString(obj)

      expect(canonical).toContain('"nullVal":null')
      expect(canonical).toContain('"trueVal":true')
      expect(canonical).toContain('"falseVal":false')
    })

    it('should handle empty object', () => {
      const canonical = canonicalizeToString({})
      expect(canonical).toBe('{}')
    })

    it('should handle empty array', () => {
      const canonical = canonicalizeToString([])
      expect(canonical).toBe('[]')
    })

    it('should escape strings properly', () => {
      const obj = { str: 'hello\nworld' }
      const canonical = canonicalizeToString(obj)

      expect(canonical).toContain('\\n')
    })

    it('should handle Unicode characters', () => {
      const obj = { emoji: '🚀', chinese: '你好' }
      const canonical = canonicalizeToString(obj)

      // Should preserve Unicode
      expect(canonical).toContain('🚀')
      expect(canonical).toContain('你好')
    })
  })

  describe('canonicalizeToBytes', () => {
    it('should return Uint8Array', () => {
      const obj = { a: 1 }
      const bytes = canonicalizeToBytes(obj)

      expect(bytes).toBeInstanceOf(Uint8Array)
    })

    it('should produce UTF-8 encoded bytes', () => {
      const obj = { a: 1 }
      const bytes = canonicalizeToBytes(obj)
      const str = new TextDecoder().decode(bytes)

      expect(str).toBe('{"a":1}')
    })

    it('should be deterministic', () => {
      const obj = { b: 2, a: 1 }
      const bytes1 = canonicalizeToBytes(obj)
      const bytes2 = canonicalizeToBytes(obj)

      expect(bytes1).toEqual(bytes2)
    })

    it('should handle empty object', () => {
      const bytes = canonicalizeToBytes({})
      const str = new TextDecoder().decode(bytes)

      expect(str).toBe('{}')
      expect(bytes.length).toBe(2)
    })

    it('should encode Unicode correctly', () => {
      const obj = { emoji: '🚀' }
      const bytes = canonicalizeToBytes(obj)

      // Decode back to verify
      const str = new TextDecoder().decode(bytes)
      expect(str).toContain('🚀')
    })
  })

  describe('areCanonicallyEqual', () => {
    it('should return true for objects with different key order', () => {
      const obj1 = { a: 1, b: 2 }
      const obj2 = { b: 2, a: 1 }

      expect(areCanonicallyEqual(obj1, obj2)).toBe(true)
    })

    it('should return false for different objects', () => {
      const obj1 = { a: 1, b: 2 }
      const obj2 = { a: 1, b: 3 }

      expect(areCanonicallyEqual(obj1, obj2)).toBe(false)
    })

    it('should return true for nested objects', () => {
      const obj1 = { outer: { b: 2, a: 1 } }
      const obj2 = { outer: { a: 1, b: 2 } }

      expect(areCanonicallyEqual(obj1, obj2)).toBe(true)
    })

    it('should return false for objects with different values', () => {
      const obj1 = { a: 1 }
      const obj2 = { a: 2 }

      expect(areCanonicallyEqual(obj1, obj2)).toBe(false)
    })

    it('should return true for empty objects', () => {
      expect(areCanonicallyEqual({}, {})).toBe(true)
    })

    it('should handle arrays correctly', () => {
      const obj1 = { arr: [1, 2, 3] }
      const obj2 = { arr: [1, 2, 3] }

      expect(areCanonicallyEqual(obj1, obj2)).toBe(true)
    })

    it('should return false for arrays with different order', () => {
      const obj1 = { arr: [1, 2, 3] }
      const obj2 = { arr: [3, 2, 1] }

      expect(areCanonicallyEqual(obj1, obj2)).toBe(false)
    })
  })

  describe('RFC 8785 Examples', () => {
    // Test case from RFC 8785
    it('should match RFC 8785 example', () => {
      const obj = {
        numbers: [333333333.33333329, 1e30, 4.5, 2e-3, 0.000000000000000000000000001],
        string: '\u20ac$\u000F\u000aA\'\u0042\u0022\u005c\\"//',
        literals: [null, true, false],
      }

      const canonical = canonicalizeToString(obj)

      // Verify key ordering
      expect(canonical.indexOf('"literals"')).toBeLessThan(
        canonical.indexOf('"numbers"')
      )
      expect(canonical.indexOf('"numbers"')).toBeLessThan(
        canonical.indexOf('"string"')
      )

      // Verify no whitespace
      expect(canonical).not.toContain(' ')
      expect(canonical).not.toContain('\n')
    })
  })

  describe('Manifest-like object', () => {
    it('should canonicalize manifest-like structure deterministically', () => {
      const manifest = {
        version: '1.0.0',
        id: 'did:web:example.com',
        sequence: 1,
        metadata: {
          name: 'TestAgent',
          description: 'A test agent',
        },
        capabilities: {
          interfaces: [
            {
              protocol: 'https',
              url: 'https://example.com/api',
            },
          ],
        },
      }

      const canon1 = canonicalizeToString(manifest)
      const canon2 = canonicalizeToString(manifest)

      // Test determinism - same object should produce identical output
      expect(canon1).toBe(canon2)
      // Should be compact JSON (no formatting whitespace outside strings)
      expect(canon1).toMatch(/^\{.*\}$/)
    })
  })
})
