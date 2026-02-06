/**
 * ManifestBuilder — Fluent API for constructing and signing agent manifests.
 *
 * Provides a builder pattern for creating validated `AgentManifest` objects.
 * All fields are validated against Zod schemas before signing.
 *
 * @packageDocumentation
 */

import {
  signManifest,
  createVerificationMethod,
  UnsignedManifestSchema,
  type AgentManifest,
  type UnsignedManifest,
  type ManifestMetadata,
  type ManifestCapabilities,
  type RevocationConfig,
} from '@ai-agent-auth/core';
import type { AgentIdentity } from './agent-identity';

/**
 * Fluent builder for constructing and signing agent manifests.
 *
 * All fields with defaults can be omitted, but metadata and capabilities
 * are required. The builder validates the manifest structure before signing.
 *
 * @example
 * ```typescript
 * const manifest = await new ManifestBuilder(identity)
 *   .setVersion('1.0.0')
 *   .setSequence(1)
 *   .setValidUntil(new Date(Date.now() + 365 * 24 * 60 * 60 * 1000))
 *   .setMetadata({
 *     name: 'MyAgent',
 *     description: 'A helpful agent',
 *     agent_version: '1.0.0',
 *   })
 *   .setCapabilities({
 *     interfaces: [{
 *       protocol: 'https',
 *       url: 'https://api.example.com',
 *       api_standard: 'openai-v1-chat',
 *     }],
 *   })
 *   .build();
 * ```
 */
export class ManifestBuilder {
  private identity: AgentIdentity;
  private version: string = '1.0.0';
  private sequence?: number;
  private createdAt?: string;
  private updatedAt?: string;
  private validUntil?: string;
  private revocation?: RevocationConfig;
  private metadata?: ManifestMetadata;
  private capabilities?: ManifestCapabilities;

  /**
   * Create a new ManifestBuilder.
   *
   * @param identity - The agent identity that will sign the manifest
   */
  constructor(identity: AgentIdentity) {
    this.identity = identity;
  }

  /**
   * Set the protocol version.
   *
   * @param version - SemVer version string (default: "1.0.0")
   * @returns This builder for chaining
   */
  public setVersion(version: string): this {
    this.version = version;
    return this;
  }

  /**
   * Set the manifest sequence number.
   *
   * The sequence must be ≥ 1 and should be monotonically increasing
   * when updating an existing manifest.
   *
   * @param sequence - Sequence number (≥ 1)
   * @returns This builder for chaining
   * @throws {Error} If sequence is less than 1
   */
  public setSequence(sequence: number): this {
    if (sequence < 1) {
      throw new Error('Sequence must be >= 1');
    }
    this.sequence = sequence;
    return this;
  }

  /**
   * Set the manifest validity period.
   *
   * The server will reject manifests with `valid_until` in the past
   * or more than 365 days in the future (per spec §5.4 Step 9).
   *
   * @param validUntil - Date or ISO 8601 string
   * @returns This builder for chaining
   */
  public setValidUntil(validUntil: Date | string): this {
    if (validUntil instanceof Date) {
      this.validUntil = validUntil.toISOString();
    } else {
      this.validUntil = validUntil;
    }
    return this;
  }

  /**
   * Set the created_at timestamp.
   * If not set, defaults to current time at build().
   *
   * @param createdAt - Date or ISO 8601 string
   * @returns This builder for chaining
   */
  public setCreatedAt(createdAt: Date | string): this {
    if (createdAt instanceof Date) {
      this.createdAt = createdAt.toISOString();
    } else {
      this.createdAt = createdAt;
    }
    return this;
  }

  /**
   * Set the updated_at timestamp.
   * If not set, defaults to current time at build().
   *
   * @param updatedAt - Date or ISO 8601 string
   * @returns This builder for chaining
   */
  public setUpdatedAt(updatedAt: Date | string): this {
    if (updatedAt instanceof Date) {
      this.updatedAt = updatedAt.toISOString();
    } else {
      this.updatedAt = updatedAt;
    }
    return this;
  }

  /**
   * Set the revocation configuration.
   *
   * @param endpoint - HTTPS URL of the revocation status endpoint
   * @param checkInterval - Optional check interval in seconds (min 60, default 3600)
   * @returns This builder for chaining
   */
  public setRevocation(endpoint: string, checkInterval?: number): this {
    this.revocation = {
      endpoint,
      ...(checkInterval !== undefined && { check_interval: checkInterval }),
    };
    return this;
  }

  /**
   * Set the manifest metadata block.
   *
   * Required fields: name, description, agent_version.
   *
   * @param metadata - Manifest metadata
   * @returns This builder for chaining
   */
  public setMetadata(metadata: ManifestMetadata): this {
    this.metadata = metadata;
    return this;
  }

  /**
   * Set the manifest capabilities block.
   *
   * Required field: interfaces (array with at least one entry).
   *
   * @param capabilities - Manifest capabilities
   * @returns This builder for chaining
   */
  public setCapabilities(capabilities: ManifestCapabilities): this {
    this.capabilities = capabilities;
    return this;
  }

  /**
   * Build and sign the manifest.
   *
   * This method:
   * 1. Validates all required fields are present
   * 2. Applies defaults for timestamps
   * 3. Validates the unsigned manifest structure via Zod
   * 4. Signs the manifest with the identity's private key
   * 5. Returns the complete signed AgentManifest
   *
   * @returns The signed AgentManifest
   * @throws {Error} If required fields are missing or validation fails
   */
  public async build(): Promise<AgentManifest> {
    // Validate required fields
    if (!this.sequence) {
      throw new Error('Sequence is required. Call setSequence() before build().');
    }
    if (!this.validUntil) {
      throw new Error('ValidUntil is required. Call setValidUntil() before build().');
    }
    if (!this.metadata) {
      throw new Error('Metadata is required. Call setMetadata() before build().');
    }
    if (!this.capabilities) {
      throw new Error('Capabilities is required. Call setCapabilities() before build().');
    }

    // Apply timestamp defaults
    const now = new Date().toISOString();
    const createdAt = this.createdAt ?? now;
    const updatedAt = this.updatedAt ?? now;

    // Construct unsigned manifest
    const unsigned: UnsignedManifest = {
      $schema: 'https://schema.agentauth.org/v1/manifest.json',
      version: this.version,
      id: this.identity.did,
      sequence: this.sequence,
      created_at: createdAt,
      updated_at: updatedAt,
      valid_until: this.validUntil,
      ...(this.revocation && { revocation: this.revocation }),
      metadata: this.metadata,
      capabilities: this.capabilities,
    };

    // Validate structure
    const validation = UnsignedManifestSchema.safeParse(unsigned);
    if (!validation.success) {
      const errors = validation.error.errors.map(e => `${e.path.join('.')}: ${e.message}`).join('; ');
      throw new Error(`Manifest validation failed: ${errors}`);
    }

    // Sign the manifest
    const verificationMethod = createVerificationMethod(this.identity.did, this.identity.parsedDID.method);
    const signed = await signManifest(unsigned, this.identity.getPrivateKey(), verificationMethod);

    return signed;
  }
}
