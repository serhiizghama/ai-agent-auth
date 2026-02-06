/**
 * Cryptographic primitives for ai-agent-auth
 * Based on AAA-SPEC.md Section 5
 * Uses Ed25519 via @noble/ed25519
 */

import * as ed from '@noble/ed25519'
import { sha256 } from '@noble/hashes/sha256'
import { sha512 } from '@noble/hashes/sha512'
import { randomBytes as cryptoRandomBytes } from 'node:crypto'
import type { KeyPair } from './types'
import { encodeBase58btc, decodeBase58btc } from './base58'

// Set up SHA-512 for @noble/ed25519
// This is required by the library for security reasons
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m))
ed.etc.sha512Async = (...m) => Promise.resolve(ed.etc.sha512Sync(...m))

/**
 * Generate a new Ed25519 key pair
 * Private key: 32 bytes (256 bits), generated via CSPRNG
 * Public key: 32 bytes, derived from private key via Ed25519
 *
 * @returns KeyPair with privateKey and publicKey (both 32 bytes)
 */
export function generateKeyPair(): KeyPair {
  const privateKey = cryptoRandomBytes(32)
  const publicKey = ed.getPublicKey(privateKey)

  return {
    privateKey,
    publicKey,
  }
}

/**
 * Sign arbitrary bytes with Ed25519 private key
 *
 * @param data - Data to sign
 * @param privateKey - 32-byte Ed25519 private key
 * @returns 64-byte Ed25519 signature
 */
export async function signBytes(
  data: Uint8Array,
  privateKey: Uint8Array
): Promise<Uint8Array> {
  if (privateKey.length !== 32) {
    throw new Error('Private key must be 32 bytes')
  }

  return await ed.signAsync(data, privateKey)
}

/**
 * Verify Ed25519 signature
 *
 * @param signature - 64-byte signature
 * @param data - Original data that was signed
 * @param publicKey - 32-byte Ed25519 public key
 * @returns true if signature is valid
 */
export async function verifySignature(
  signature: Uint8Array,
  data: Uint8Array,
  publicKey: Uint8Array
): Promise<boolean> {
  if (publicKey.length !== 32) {
    throw new Error('Public key must be 32 bytes')
  }

  if (signature.length !== 64) {
    throw new Error('Signature must be 64 bytes')
  }

  try {
    return await ed.verifyAsync(signature, data, publicKey)
  } catch {
    return false
  }
}

/**
 * Sign a challenge string as per SPEC §5.5
 *
 * Procedure (byte-precise):
 * 1. Construct payload: challenge + "." + did + "." + expires_at
 * 2. Encode to UTF-8 bytes
 * 3. Hash with SHA-256
 * 4. Sign hash with Ed25519
 * 5. Encode signature as base58btc with 'z' prefix
 *
 * @param challenge - 64-char hex string
 * @param did - Agent's DID
 * @param expiresAt - ISO 8601 timestamp
 * @param privateKey - 32-byte Ed25519 private key
 * @returns Base58btc-encoded signature with 'z' prefix
 */
export async function signChallenge(
  challenge: string,
  did: string,
  expiresAt: string,
  privateKey: Uint8Array
): Promise<string> {
  // Step 1: Construct payload
  const payloadString = `${challenge}.${did}.${expiresAt}`

  // Step 2: Encode to UTF-8 bytes
  const payloadBytes = new TextEncoder().encode(payloadString)

  // Step 3: Hash with SHA-256
  const hash = sha256(payloadBytes)

  // Step 4: Sign hash with Ed25519
  const signatureBytes = await signBytes(hash, privateKey)

  // Step 5: Encode as base58btc with 'z' prefix
  return encodeBase58btc(signatureBytes)
}

/**
 * Verify a challenge signature as per SPEC §5.6
 *
 * @param challenge - 64-char hex string
 * @param did - Agent's DID
 * @param expiresAt - ISO 8601 timestamp
 * @param signature - Base58btc-encoded signature with 'z' prefix
 * @param publicKey - 32-byte Ed25519 public key
 * @returns true if signature is valid
 */
export async function verifyChallengeSignature(
  challenge: string,
  did: string,
  expiresAt: string,
  signature: string,
  publicKey: Uint8Array
): Promise<boolean> {
  try {
    // Step 1: Reconstruct payload
    const payloadString = `${challenge}.${did}.${expiresAt}`
    const payloadBytes = new TextEncoder().encode(payloadString)

    // Step 2: Hash with SHA-256
    const hash = sha256(payloadBytes)

    // Step 3: Decode signature from base58btc
    const signatureBytes = decodeBase58btc(signature)

    if (signatureBytes.length !== 64) {
      return false
    }

    // Step 4: Verify signature
    return await verifySignature(signatureBytes, hash, publicKey)
  } catch {
    return false
  }
}

/**
 * Generate a cryptographically secure random challenge
 * Returns a 256-bit random value as a 64-character hex string
 *
 * @returns 64-char hex string (256 bits of randomness)
 */
export function generateChallenge(): string {
  const bytes = cryptoRandomBytes(32) // 256 bits
  return Buffer.from(bytes).toString('hex')
}

/**
 * Hash data with SHA-256
 *
 * @param data - Data to hash
 * @returns 32-byte SHA-256 hash
 */
export function hashSHA256(data: Uint8Array): Uint8Array {
  return sha256(data)
}

/**
 * Convert hex string to Uint8Array
 *
 * @param hex - Hex string
 * @returns Byte array
 */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('Hex string must have even length')
  }

  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16)
  }

  return bytes
}

/**
 * Convert Uint8Array to hex string
 *
 * @param bytes - Byte array
 * @returns Hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}
