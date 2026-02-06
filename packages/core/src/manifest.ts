/**
 * Agent Manifest signing and verification
 * Based on AAA-SPEC.md Section 5.3 and 5.4
 */

import type { AgentManifest, UnsignedManifest } from './types'
import { canonicalizeToBytes } from './jcs'
import { hashSHA256 } from './crypto'
import { signBytes, verifySignature } from './crypto'
import { encodeBase58btc, decodeBase58btc } from './base58'
import { resolveDID } from './did'
import { AuthError, AuthErrorCode } from './errors'

/**
 * Sign an unsigned manifest
 *
 * Procedure (SPEC §5.3):
 * 1. CANONICALIZE: canonical_bytes = JCS(unsigned_manifest)
 * 2. HASH: hash = SHA-256(canonical_bytes)
 * 3. SIGN: signature_bytes = Ed25519.sign(private_key, hash)
 * 4. ENCODE: proof_value = "z" + base58btc_encode(signature_bytes)
 * 5. ASSEMBLE PROOF
 * 6. ATTACH: signed_manifest = { ...unsigned_manifest, proof }
 *
 * @param unsignedManifest - Manifest without proof
 * @param privateKey - 32-byte Ed25519 private key
 * @param verificationMethod - DID URL for the signing key
 * @returns Signed manifest with proof attached
 */
export async function signManifest(
  unsignedManifest: UnsignedManifest,
  privateKey: Uint8Array,
  verificationMethod: string
): Promise<AgentManifest> {
  // Step 1: Canonicalize
  const canonicalBytes = canonicalizeToBytes(unsignedManifest)

  // Step 2: Hash
  const hash = hashSHA256(canonicalBytes)

  // Step 3: Sign
  const signatureBytes = await signBytes(hash, privateKey)

  // Step 4: Encode
  const proofValue = encodeBase58btc(signatureBytes)

  // Step 5: Assemble proof
  const proof = {
    type: 'Ed25519Signature2020' as const,
    created: new Date().toISOString(),
    verification_method: verificationMethod,
    proof_purpose: 'assertionMethod' as const,
    proof_value: proofValue,
  }

  // Step 6: Attach
  return {
    ...unsignedManifest,
    proof,
  }
}

/**
 * Verify a signed manifest
 *
 * Procedure (SPEC §5.4):
 * 1. EXTRACT PROOF
 * 2. VALIDATE PROOF STRUCTURE
 * 3. RESOLVE PUBLIC KEY
 * 4. VALIDATE DID MATCH
 * 5. CANONICALIZE (without proof)
 * 6. HASH
 * 7. DECODE SIGNATURE
 * 8. VERIFY
 * 9. VALIDATE TIMESTAMPS
 *
 * @param manifest - Signed manifest
 * @param options - Verification options (for did:web resolution)
 * @returns true if manifest signature is valid
 * @throws AuthError if verification fails
 */
export async function verifyManifest(
  manifest: AgentManifest,
  options: {
    clockSkewSeconds?: number
    fetchFn?: typeof globalThis.fetch
    timeoutMs?: number
    maxBytes?: number
  } = {}
): Promise<boolean> {
  const { clockSkewSeconds = 60, fetchFn, timeoutMs, maxBytes } = options

  try {
    // Step 1: Extract proof
    const { proof, ...unsignedManifest } = manifest

    if (!proof) {
      throw new AuthError(
        AuthErrorCode.AUTH_INVALID_MANIFEST_SIGNATURE,
        'Manifest is missing proof'
      )
    }

    // Step 2: Validate proof structure
    if (proof.type !== 'Ed25519Signature2020') {
      throw new AuthError(
        AuthErrorCode.AUTH_INVALID_MANIFEST_SIGNATURE,
        `Invalid proof type: ${proof.type}`
      )
    }

    if (proof.proof_purpose !== 'assertionMethod') {
      throw new AuthError(
        AuthErrorCode.AUTH_INVALID_MANIFEST_SIGNATURE,
        `Invalid proof purpose: ${proof.proof_purpose}`
      )
    }

    if (!proof.proof_value.startsWith('z')) {
      throw new AuthError(
        AuthErrorCode.AUTH_INVALID_MANIFEST_SIGNATURE,
        'Proof value must start with z'
      )
    }

    // Step 3: Resolve public key
    const publicKey = await resolveDID(manifest.id, proof.verification_method, {
      fetchFn,
      timeoutMs,
      maxBytes,
    })

    // Step 4: Validate DID match
    if (!proof.verification_method.startsWith(manifest.id)) {
      throw new AuthError(
        AuthErrorCode.AUTH_DID_MISMATCH,
        'Verification method does not match manifest DID'
      )
    }

    // Step 5: Canonicalize
    const canonicalBytes = canonicalizeToBytes(unsignedManifest)

    // Step 6: Hash
    const hash = hashSHA256(canonicalBytes)

    // Step 7: Decode signature
    const signatureBytes = decodeBase58btc(proof.proof_value)

    if (signatureBytes.length !== 64) {
      throw new AuthError(
        AuthErrorCode.AUTH_INVALID_MANIFEST_SIGNATURE,
        'Signature must be 64 bytes'
      )
    }

    // Step 8: Verify
    const isValid = await verifySignature(signatureBytes, hash, publicKey)

    if (!isValid) {
      throw new AuthError(
        AuthErrorCode.AUTH_INVALID_MANIFEST_SIGNATURE,
        'Signature verification failed'
      )
    }

    // Step 9: Validate timestamps
    const now = Date.now()
    const validUntil = new Date(manifest.valid_until).getTime()

    // Apply clock skew leeway (past direction only)
    const validUntilWithSkew = validUntil + clockSkewSeconds * 1000

    if (now > validUntilWithSkew) {
      throw new AuthError(
        AuthErrorCode.AUTH_MANIFEST_EXPIRED,
        `Manifest expired at ${manifest.valid_until}`
      )
    }

    // Sanity bound: valid_until must not be more than 365 days in the future
    const maxValidUntil = now + 365 * 24 * 60 * 60 * 1000
    if (validUntil > maxValidUntil) {
      throw new AuthError(
        AuthErrorCode.AUTH_INVALID_REQUEST,
        'Manifest valid_until is too far in the future (max: 365 days)'
      )
    }

    return true
  } catch (error) {
    if (error instanceof AuthError) {
      throw error
    }

    throw new AuthError(
      AuthErrorCode.AUTH_INVALID_MANIFEST_SIGNATURE,
      `Manifest verification failed: ${error instanceof Error ? error.message : String(error)}`
    )
  }
}

/**
 * Create a verification method DID URL for a given DID
 *
 * @param did - Agent's DID
 * @param keyId - Optional key identifier (default: "key-1")
 * @returns Verification method DID URL
 */
export function createVerificationMethod(
  did: string,
  keyId: string = 'key-1'
): string {
  if (did.startsWith('did:key:')) {
    // For did:key, verification method is self-referencing
    return `${did}#${did}`
  } else {
    // For did:web, use conventional key-1 fragment
    return `${did}#${keyId}`
  }
}

/**
 * Validate manifest sequence number to prevent rollback attacks
 *
 * @param newSequence - Sequence from incoming manifest
 * @param storedSequence - Highest sequence previously seen (0 if first time)
 * @throws AuthError if rollback detected
 */
export function validateManifestSequence(
  newSequence: number,
  storedSequence: number
): void {
  if (newSequence < storedSequence) {
    throw new AuthError(
      AuthErrorCode.AUTH_MANIFEST_ROLLBACK,
      `Manifest sequence ${newSequence} is lower than previously seen ${storedSequence}`
    )
  }
}
