/**
 * Cross-platform cryptographically secure random byte generation
 * Works in Node.js 20+, browsers, Deno, Cloudflare Workers, Bun
 */

/**
 * Generate cryptographically secure random bytes
 * Uses Web Crypto API (crypto.getRandomValues) which is available in:
 * - Node.js 20+ (global crypto object)
 * - Browsers (window.crypto)
 * - Deno (global crypto)
 * - Cloudflare Workers (global crypto)
 * - Bun (global crypto)
 *
 * @param length - Number of random bytes to generate
 * @returns Uint8Array of random bytes
 */
export function randomBytes(length: number): Uint8Array {
  if (length <= 0) {
    throw new Error('Length must be positive')
  }

  // Use Web Crypto API (available in all modern runtimes)
  const cryptoObj = globalThis.crypto

  if (!cryptoObj || !cryptoObj.getRandomValues) {
    throw new Error(
      'Web Crypto API not available. Requires Node.js 20+, modern browser, Deno, CF Workers, or Bun.'
    )
  }

  const bytes = new Uint8Array(length)
  cryptoObj.getRandomValues(bytes)

  return bytes
}
