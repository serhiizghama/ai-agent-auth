/**
 * AgentIdentity — Cryptographic identity management for AI agents.
 *
 * Manages Ed25519 key pairs and DID identifiers. Provides methods for
 * key generation, challenge signing, and key import/export.
 *
 * @packageDocumentation
 */

import {
  generateKeyPair,
  signChallenge,
  signBytes,
  publicKeyToDidKey,
  parseDID,
  hexToBytes,
  bytesToHex,
  type KeyPair,
  type ParsedDID,
} from '@ai-agent-auth/core';

/**
 * AgentIdentity represents an agent's cryptographic identity.
 *
 * Use `AgentIdentity.generate()` to create a new identity, or
 * `AgentIdentity.fromPrivateKey()` to restore from an existing key.
 *
 * @example
 * ```typescript
 * // Generate a new identity
 * const identity = AgentIdentity.generate();
 * console.log(identity.did); // "did:key:z6Mk..."
 *
 * // Restore from existing private key
 * const restored = AgentIdentity.fromPrivateKeyHex(hexString, did);
 * ```
 */
export class AgentIdentity {
  private readonly privateKey: Uint8Array;
  public readonly publicKey: Uint8Array;
  public readonly did: string;
  public readonly parsedDID: ParsedDID;
  public readonly verificationMethod: string;

  /**
   * Private constructor. Use static factory methods to create instances.
   */
  private constructor(keyPair: KeyPair, did?: string) {
    this.privateKey = keyPair.privateKey;
    this.publicKey = keyPair.publicKey;

    // If DID not provided, derive did:key from public key
    if (!did) {
      this.did = publicKeyToDidKey(this.publicKey);
    } else {
      this.did = did;
    }

    this.parsedDID = parseDID(this.did);

    // Set verification method based on DID method
    if (this.parsedDID.method === 'key') {
      // For did:key, the verification method is self-referencing
      this.verificationMethod = `${this.did}#${this.did}`;
    } else if (this.parsedDID.method === 'web') {
      // For did:web, use conventional fragment identifier
      this.verificationMethod = `${this.did}#key-1`;
    } else {
      // Fallback (should not happen if parseDID validates correctly)
      this.verificationMethod = `${this.did}#key-1`;
    }
  }

  /**
   * Generate a new Ed25519 identity with a random key pair.
   * The DID is derived as `did:key` from the public key.
   *
   * @returns A new AgentIdentity instance
   *
   * @example
   * ```typescript
   * const identity = AgentIdentity.generate();
   * console.log(identity.did); // "did:key:z6Mk..."
   * ```
   */
  public static generate(): AgentIdentity {
    const keyPair = generateKeyPair();
    return new AgentIdentity(keyPair);
  }

  /**
   * Restore an identity from an existing Ed25519 private key.
   *
   * @param privateKey - 32-byte Ed25519 private key
   * @param did - Optional DID string. If omitted, derived as did:key from public key.
   * @returns An AgentIdentity instance
   *
   * @throws {Error} If private key is not 32 bytes
   *
   * @example
   * ```typescript
   * const privateKey = new Uint8Array(32); // ... your key
   * const identity = await AgentIdentity.fromPrivateKey(privateKey);
   * ```
   */
  public static async fromPrivateKey(privateKey: Uint8Array, did?: string): Promise<AgentIdentity> {
    if (privateKey.length !== 32) {
      throw new Error('Private key must be exactly 32 bytes');
    }

    // Derive public key from private key
    // Import @noble/ed25519 dynamically to avoid bundling issues
    const ed = await import('@noble/ed25519');
    const publicKey = await ed.getPublicKey(privateKey);

    return new AgentIdentity({ privateKey, publicKey }, did);
  }

  /**
   * Restore an identity from a hex-encoded private key string.
   *
   * @param hex - Hex-encoded 32-byte private key (64 hex characters)
   * @param did - Optional DID string. If omitted, derived as did:key from public key.
   * @returns An AgentIdentity instance
   *
   * @throws {Error} If hex string is invalid or not 64 characters
   *
   * @example
   * ```typescript
   * const identity = await AgentIdentity.fromPrivateKeyHex(
   *   'a1b2c3d4...',
   *   'did:web:agent.example.com'
   * );
   * ```
   */
  public static async fromPrivateKeyHex(hex: string, did?: string): Promise<AgentIdentity> {
    if (hex.length !== 64) {
      throw new Error('Hex string must be exactly 64 characters (32 bytes)');
    }

    const privateKey = hexToBytes(hex);
    return AgentIdentity.fromPrivateKey(privateKey, did);
  }

  /**
   * Sign arbitrary bytes with the agent's private key.
   *
   * @param data - Data to sign
   * @returns 64-byte Ed25519 signature
   *
   * @example
   * ```typescript
   * const data = new TextEncoder().encode('Hello, world!');
   * const signature = await identity.sign(data);
   * ```
   */
  public async sign(data: Uint8Array): Promise<Uint8Array> {
    // signBytes expects (data, privateKey) signature
    return signBytes(data, this.privateKey);
  }

  /**
   * Sign a challenge string as per protocol specification §5.5.
   *
   * Constructs the payload as `challenge + "." + did + "." + expiresAt`,
   * hashes it with SHA-256, signs with Ed25519, and encodes as base58btc with 'z' prefix.
   *
   * @param challenge - 64-character hex challenge string
   * @param did - Agent's DID (must match this identity's DID)
   * @param expiresAt - ISO 8601 expiry timestamp
   * @returns Base58btc-encoded signature with 'z' prefix
   *
   * @throws {Error} If DID does not match this identity's DID
   *
   * @example
   * ```typescript
   * const signature = await identity.signChallenge(
   *   'a1b2c3...',
   *   identity.did,
   *   '2026-02-06T12:05:00Z'
   * );
   * ```
   */
  public async signChallenge(
    challenge: string,
    did: string,
    expiresAt: string,
  ): Promise<string> {
    if (did !== this.did) {
      throw new Error(
        `DID mismatch: expected ${this.did}, got ${did}`,
      );
    }

    return signChallenge(challenge, did, expiresAt, this.privateKey);
  }

  /**
   * Get the raw private key bytes.
   *
   * ⚠️ **INTERNAL USE**: This method is intended for use by ManifestBuilder
   * and other internal components. Handle with extreme care.
   *
   * @returns 32-byte private key
   * @internal
   */
  public getPrivateKey(): Uint8Array {
    return this.privateKey;
  }

  /**
   * Export the private key as a hex string.
   *
   * ⚠️ **WARNING**: This exposes the raw private key. Handle with care.
   * Never log, transmit over insecure channels, or store unencrypted.
   *
   * @returns Hex-encoded private key (64 characters)
   *
   * @example
   * ```typescript
   * const hex = identity.exportPrivateKeyHex();
   * // Store securely (e.g., encrypted environment variable)
   * ```
   */
  public exportPrivateKeyHex(): string {
    return bytesToHex(this.privateKey);
  }

  /**
   * Export the public key as a hex string.
   *
   * @returns Hex-encoded public key (64 characters)
   *
   * @example
   * ```typescript
   * const pubKeyHex = identity.exportPublicKeyHex();
   * ```
   */
  public exportPublicKeyHex(): string {
    return bytesToHex(this.publicKey);
  }
}
