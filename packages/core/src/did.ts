/**
 * DID (Decentralized Identifier) utilities
 * Based on AAA-SPEC.md Section 5.2
 * Supports did:key and did:web methods
 */

import type { ParsedDID } from './types'
import { encodeBase58btc, decodeBase58btc } from './base58'
import { AuthError, AuthErrorCode } from './errors'

// Ed25519 multicodec prefix: 0xed01
const ED25519_MULTICODEC = new Uint8Array([0xed, 0x01])

/**
 * Parse a DID string into its components
 *
 * @param did - DID string (did:key:... or did:web:...)
 * @returns Parsed DID components
 * @throws AuthError if DID format is invalid
 */
export function parseDID(did: string): ParsedDID {
  if (!did.startsWith('did:')) {
    throw new AuthError(
      AuthErrorCode.AUTH_INVALID_REQUEST,
      'DID must start with "did:"'
    )
  }

  const parts = did.split(':')

  if (parts.length < 3) {
    throw new AuthError(
      AuthErrorCode.AUTH_INVALID_REQUEST,
      'Invalid DID format'
    )
  }

  const method = parts[1]
  const identifier = parts.slice(2).join(':')

  if (method !== 'key' && method !== 'web') {
    throw new AuthError(
      AuthErrorCode.AUTH_UNSUPPORTED_DID_METHOD,
      `Unsupported DID method: ${method}. Only did:key and did:web are supported.`
    )
  }

  return {
    did,
    method: method as 'key' | 'web',
    identifier,
  }
}

/**
 * Convert Ed25519 public key to did:key identifier
 *
 * Procedure (SPEC §5.2.1):
 * 1. Prepend multicodec prefix 0xed01
 * 2. Encode as base58btc
 * 3. Format as "did:key:z{base58btc}"
 *
 * @param publicKey - 32-byte Ed25519 public key
 * @returns did:key identifier
 * @throws Error if public key is invalid
 */
export function publicKeyToDidKey(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) {
    throw new Error('Ed25519 public key must be 32 bytes')
  }

  // Step 1: Prepend multicodec prefix
  const payload = new Uint8Array(34)
  payload.set(ED25519_MULTICODEC, 0)
  payload.set(publicKey, 2)

  // Step 2: Encode as base58btc (with 'z' prefix)
  const encoded = encodeBase58btc(payload)

  // Step 3: Format as did:key
  return `did:key:${encoded}`
}

/**
 * Extract Ed25519 public key from did:key identifier
 *
 * Procedure (SPEC §5.2.2):
 * 1. Strip "did:key:z" prefix
 * 2. Decode base58btc
 * 3. Verify first 2 bytes == 0xed01 (Ed25519 multicodec)
 * 4. Extract bytes [2..34] (32-byte public key)
 *
 * @param didKey - did:key identifier
 * @returns 32-byte Ed25519 public key
 * @throws AuthError if did:key format is invalid
 */
export function didKeyToPublicKey(didKey: string): Uint8Array {
  const parsed = parseDID(didKey)

  if (parsed.method !== 'key') {
    throw new AuthError(
      AuthErrorCode.AUTH_INVALID_REQUEST,
      'DID is not a did:key'
    )
  }

  try {
    // identifier should be the base58btc part with 'z' prefix
    const encoded = parsed.identifier

    if (!encoded.startsWith('z')) {
      throw new Error('did:key identifier must start with z')
    }

    // Decode base58btc
    const payload = decodeBase58btc(encoded)

    if (payload.length !== 34) {
      throw new Error(
        `Invalid did:key payload length: expected 34 bytes, got ${payload.length}`
      )
    }

    // Verify multicodec prefix
    if (payload[0] !== 0xed || payload[1] !== 0x01) {
      throw new Error(
        `Invalid multicodec prefix: expected [0xed, 0x01], got [0x${payload[0].toString(16)}, 0x${payload[1].toString(16)}]`
      )
    }

    // Extract public key (bytes [2..34])
    return payload.slice(2, 34)
  } catch (error) {
    throw new AuthError(
      AuthErrorCode.AUTH_DID_RESOLUTION_FAILED,
      `Failed to extract public key from did:key: ${error instanceof Error ? error.message : String(error)}`
    )
  }
}

/**
 * Resolve did:web to retrieve the DID document and extract public key
 *
 * Procedure (SPEC §5.2.3):
 * 1. Parse DID string
 * 2. Replace ':' with '/' in identifier
 * 3. URL-decode percent-encoded characters
 * 4. Construct URL: https://{domain}/.well-known/did.json
 * 5. Fetch with timeout (2s), size limit (100KB), max redirects (3)
 * 6. Parse JSON → extract verificationMethod
 * 7. Find key matching verification_method from proof
 * 8. Decode publicKeyMultibase → return public key
 *
 * @param did - did:web identifier
 * @param verificationMethod - Optional DID URL to look up specific key (e.g., "did:web:example.com#key-1")
 * @param options - Fetch options (timeout, maxBytes, maxRedirects, fetch function)
 * @returns 32-byte Ed25519 public key
 * @throws AuthError if resolution fails
 */
export async function resolveDidWeb(
  did: string,
  verificationMethod?: string,
  options: {
    timeoutMs?: number
    maxBytes?: number
    maxRedirects?: number
    fetchFn?: typeof globalThis.fetch
  } = {}
): Promise<Uint8Array> {
  const {
    timeoutMs = 2000,
    maxBytes = 102400, // 100 KB
    maxRedirects = 3,
    fetchFn = globalThis.fetch,
  } = options

  const parsed = parseDID(did)

  if (parsed.method !== 'web') {
    throw new AuthError(
      AuthErrorCode.AUTH_INVALID_REQUEST,
      'DID is not a did:web'
    )
  }

  try {
    // Step 2-3: Replace ':' with '/', URL-decode
    const domain = parsed.identifier.replace(/:/g, '/')
    const decoded = decodeURIComponent(domain)

    // Step 4: Construct URL
    const url = `https://${decoded}/.well-known/did.json`

    // Step 5: Fetch with safety limits
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeoutMs)

    let response: Response
    try {
      response = await fetchFn(url, {
        signal: controller.signal,
        redirect: 'follow',
        headers: { Accept: 'application/json' },
      })
    } finally {
      clearTimeout(timer)
    }

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`)
    }

    if (!response.body) {
      throw new Error('Response body is empty')
    }

    // Read body with size limit
    const chunks: Uint8Array[] = []
    let totalBytes = 0
    const reader = response.body.getReader()

    try {
      while (true) {
        const { done, value } = await reader.read()
        if (done) break

        totalBytes += value.byteLength
        if (totalBytes > maxBytes) {
          throw new Error(`Response exceeded ${maxBytes} bytes`)
        }

        chunks.push(value)
      }
    } finally {
      reader.releaseLock()
    }

    // Concatenate chunks
    const bodyBytes = new Uint8Array(totalBytes)
    let offset = 0
    for (const chunk of chunks) {
      bodyBytes.set(chunk, offset)
      offset += chunk.length
    }

    // Step 6: Parse JSON
    const bodyText = new TextDecoder().decode(bodyBytes)
    const didDocument = JSON.parse(bodyText)

    // Step 7: Extract verificationMethod array
    if (!Array.isArray(didDocument.verificationMethod)) {
      throw new Error('DID document missing verificationMethod array')
    }

    // Find the key
    let keyObject
    if (verificationMethod) {
      // Look for specific verification method
      keyObject = didDocument.verificationMethod.find(
        (vm: any) => vm.id === verificationMethod
      )
      if (!keyObject) {
        throw new Error(
          `Verification method ${verificationMethod} not found in DID document`
        )
      }
    } else {
      // Use first assertionMethod or first verificationMethod
      if (Array.isArray(didDocument.assertionMethod)) {
        const assertionMethodId =
          typeof didDocument.assertionMethod[0] === 'string'
            ? didDocument.assertionMethod[0]
            : didDocument.assertionMethod[0]?.id

        keyObject = didDocument.verificationMethod.find(
          (vm: any) => vm.id === assertionMethodId
        )
      }

      if (!keyObject) {
        keyObject = didDocument.verificationMethod[0]
      }
    }

    if (!keyObject) {
      throw new Error('No verification method found in DID document')
    }

    // Step 8: Decode publicKeyMultibase
    if (!keyObject.publicKeyMultibase) {
      throw new Error('Verification method missing publicKeyMultibase')
    }

    const publicKeyMultibase = keyObject.publicKeyMultibase as string

    // Decode similar to did:key
    if (!publicKeyMultibase.startsWith('z')) {
      throw new Error('publicKeyMultibase must start with z')
    }

    const payload = decodeBase58btc(publicKeyMultibase)

    if (payload.length !== 34) {
      throw new Error('Invalid public key payload length')
    }

    if (payload[0] !== 0xed || payload[1] !== 0x01) {
      throw new Error('Invalid Ed25519 multicodec prefix')
    }

    return payload.slice(2, 34)
  } catch (error) {
    throw new AuthError(
      AuthErrorCode.AUTH_DID_RESOLUTION_FAILED,
      `Failed to resolve did:web: ${error instanceof Error ? error.message : String(error)}`
    )
  }
}

/**
 * Resolve a DID to a public key (works for both did:key and did:web)
 *
 * @param did - DID string
 * @param verificationMethod - Optional verification method for did:web
 * @param options - Options for did:web resolution
 * @returns 32-byte Ed25519 public key
 * @throws AuthError if resolution fails
 */
export async function resolveDID(
  did: string,
  verificationMethod?: string,
  options?: {
    timeoutMs?: number
    maxBytes?: number
    maxRedirects?: number
    fetchFn?: typeof globalThis.fetch
  }
): Promise<Uint8Array> {
  const parsed = parseDID(did)

  if (parsed.method === 'key') {
    return didKeyToPublicKey(did)
  } else {
    // did:web
    return await resolveDidWeb(did, verificationMethod, options)
  }
}
