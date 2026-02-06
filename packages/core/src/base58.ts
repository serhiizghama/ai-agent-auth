/**
 * Base58btc encoding/decoding utilities
 * Based on AAA-SPEC.md Section 5
 * Uses multibase 'z' prefix for base58btc
 */

import { base58 } from '@scure/base'

/**
 * Encode bytes to base58btc with 'z' prefix (multibase)
 * @param data - Bytes to encode
 * @returns Base58btc string with 'z' prefix
 */
export function encodeBase58btc(data: Uint8Array): string {
  const encoded = base58.encode(data)
  return 'z' + encoded
}

/**
 * Decode base58btc string (with or without 'z' prefix)
 * @param encoded - Base58btc string
 * @returns Decoded bytes
 * @throws Error if decoding fails or invalid format
 */
export function decodeBase58btc(encoded: string): Uint8Array {
  // Strip 'z' prefix if present
  const toDecode = encoded.startsWith('z') ? encoded.slice(1) : encoded

  try {
    return base58.decode(toDecode)
  } catch (error) {
    throw new Error(
      `Failed to decode base58btc string: ${error instanceof Error ? error.message : String(error)}`
    )
  }
}

/**
 * Validate base58btc string format
 * @param str - String to validate
 * @returns true if valid base58btc with 'z' prefix
 */
export function isValidBase58btc(str: string): boolean {
  if (!str.startsWith('z')) {
    return false
  }

  // Base58 alphabet: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
  // Excludes: 0, O, I, l
  const base58Regex = /^z[1-9A-HJ-NP-Za-km-z]+$/
  return base58Regex.test(str)
}
