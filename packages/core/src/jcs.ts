/**
 * JSON Canonicalization Scheme (JCS) wrapper
 * Based on AAA-SPEC.md Section 5.3
 * Implements RFC 8785 for deterministic JSON serialization
 */

import canonicalize from 'canonicalize'

/**
 * Canonicalize a JavaScript object to deterministic UTF-8 byte string
 * using JCS (RFC 8785)
 *
 * JCS produces:
 * - Object keys sorted lexicographically by Unicode code point
 * - No whitespace
 * - Numbers in shortest representation
 * - Strings escaped per RFC 8785 §3.2.2.2
 *
 * @param obj - Object to canonicalize
 * @returns UTF-8 encoded canonical byte string
 * @throws Error if canonicalization fails
 */
export function canonicalizeToBytes(obj: unknown): Uint8Array {
  const canonical = canonicalize(obj)

  if (typeof canonical !== 'string') {
    throw new Error('Canonicalization failed: result is not a string')
  }

  // Convert to UTF-8 bytes
  return new TextEncoder().encode(canonical)
}

/**
 * Canonicalize a JavaScript object to deterministic JSON string
 *
 * @param obj - Object to canonicalize
 * @returns Canonical JSON string
 * @throws Error if canonicalization fails
 */
export function canonicalizeToString(obj: unknown): string {
  const canonical = canonicalize(obj)

  if (typeof canonical !== 'string') {
    throw new Error('Canonicalization failed: result is not a string')
  }

  return canonical
}

/**
 * Verify that two objects produce the same canonical form
 *
 * @param obj1 - First object
 * @param obj2 - Second object
 * @returns true if canonical forms are identical
 */
export function areCanonicallyEqual(obj1: unknown, obj2: unknown): boolean {
  try {
    const canon1 = canonicalizeToString(obj1)
    const canon2 = canonicalizeToString(obj2)
    return canon1 === canon2
  } catch {
    return false
  }
}
