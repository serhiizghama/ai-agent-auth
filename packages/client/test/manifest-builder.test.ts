/**
 * Tests for ManifestBuilder
 */

import { describe, it, expect } from 'vitest';
import { ManifestBuilder } from '../src/manifest-builder';
import { AgentIdentity } from '../src/agent-identity';
import { verifyManifest } from '@ai-agent-auth/core';

describe('ManifestBuilder', () => {
  const createTestIdentity = () => AgentIdentity.generate();

  const createMinimalManifest = async (identity: AgentIdentity) => {
    return new ManifestBuilder(identity)
      .setSequence(1)
      .setValidUntil(new Date(Date.now() + 365 * 24 * 60 * 60 * 1000))
      .setMetadata({
        name: 'TestAgent',
        description: 'A test agent',
        agent_version: '1.0.0',
      })
      .setCapabilities({
        interfaces: [
          {
            protocol: 'https',
            url: 'https://api.example.com',
          },
        ],
      })
      .build();
  };

  describe('constructor', () => {
    it('should create builder with identity', () => {
      const identity = createTestIdentity();
      const builder = new ManifestBuilder(identity);
      expect(builder).toBeInstanceOf(ManifestBuilder);
    });
  });

  describe('fluent API', () => {
    it('should support method chaining', async () => {
      const identity = createTestIdentity();
      const manifest = await new ManifestBuilder(identity)
        .setVersion('1.0.0')
        .setSequence(1)
        .setValidUntil(new Date(Date.now() + 1000))
        .setMetadata({
          name: 'TestAgent',
          description: 'Test',
          agent_version: '1.0.0',
        })
        .setCapabilities({
          interfaces: [{ protocol: 'https', url: 'https://api.example.com' }],
        })
        .build();

      expect(manifest).toBeDefined();
      expect(manifest.id).toBe(identity.did);
    });
  });

  describe('setVersion()', () => {
    it('should set custom version', async () => {
      const identity = createTestIdentity();
      const manifest = await new ManifestBuilder(identity)
        .setVersion('2.0.0')
        .setSequence(1)
        .setValidUntil(new Date(Date.now() + 1000))
        .setMetadata({
          name: 'TestAgent',
          description: 'Test',
          agent_version: '1.0.0',
        })
        .setCapabilities({
          interfaces: [{ protocol: 'https', url: 'https://api.example.com' }],
        })
        .build();

      expect(manifest.version).toBe('2.0.0');
    });
  });

  describe('setSequence()', () => {
    it('should set sequence number', async () => {
      const identity = createTestIdentity();
      const manifest = await createMinimalManifest(identity);
      expect(manifest.sequence).toBe(1);
    });

    it('should throw if sequence < 1', () => {
      const identity = createTestIdentity();
      const builder = new ManifestBuilder(identity);
      expect(() => builder.setSequence(0)).toThrow('Sequence must be >= 1');
    });
  });

  describe('setValidUntil()', () => {
    it('should accept Date object', async () => {
      const identity = createTestIdentity();
      const validUntil = new Date(Date.now() + 60 * 60 * 1000);
      const manifest = await new ManifestBuilder(identity)
        .setSequence(1)
        .setValidUntil(validUntil)
        .setMetadata({
          name: 'TestAgent',
          description: 'Test',
          agent_version: '1.0.0',
        })
        .setCapabilities({
          interfaces: [{ protocol: 'https', url: 'https://api.example.com' }],
        })
        .build();

      expect(manifest.valid_until).toBe(validUntil.toISOString());
    });

    it('should accept ISO 8601 string', async () => {
      const identity = createTestIdentity();
      const validUntil = '2026-12-31T23:59:59Z';
      const manifest = await new ManifestBuilder(identity)
        .setSequence(1)
        .setValidUntil(validUntil)
        .setMetadata({
          name: 'TestAgent',
          description: 'Test',
          agent_version: '1.0.0',
        })
        .setCapabilities({
          interfaces: [{ protocol: 'https', url: 'https://api.example.com' }],
        })
        .build();

      expect(manifest.valid_until).toBe(validUntil);
    });
  });

  describe('setRevocation()', () => {
    it('should set revocation endpoint', async () => {
      const identity = createTestIdentity();
      const manifest = await new ManifestBuilder(identity)
        .setSequence(1)
        .setValidUntil(new Date(Date.now() + 1000))
        .setRevocation('https://revocation.example.com/status')
        .setMetadata({
          name: 'TestAgent',
          description: 'Test',
          agent_version: '1.0.0',
        })
        .setCapabilities({
          interfaces: [{ protocol: 'https', url: 'https://api.example.com' }],
        })
        .build();

      expect(manifest.revocation).toEqual({
        endpoint: 'https://revocation.example.com/status',
      });
    });

    it('should set revocation with check_interval', async () => {
      const identity = createTestIdentity();
      const manifest = await new ManifestBuilder(identity)
        .setSequence(1)
        .setValidUntil(new Date(Date.now() + 1000))
        .setRevocation('https://revocation.example.com/status', 7200)
        .setMetadata({
          name: 'TestAgent',
          description: 'Test',
          agent_version: '1.0.0',
        })
        .setCapabilities({
          interfaces: [{ protocol: 'https', url: 'https://api.example.com' }],
        })
        .build();

      expect(manifest.revocation?.check_interval).toBe(7200);
    });
  });

  describe('setMetadata()', () => {
    it('should set required metadata fields', async () => {
      const identity = createTestIdentity();
      const metadata = {
        name: 'MyAgent',
        description: 'A sophisticated AI agent',
        agent_version: '2.1.0',
      };

      const manifest = await new ManifestBuilder(identity)
        .setSequence(1)
        .setValidUntil(new Date(Date.now() + 1000))
        .setMetadata(metadata)
        .setCapabilities({
          interfaces: [{ protocol: 'https', url: 'https://api.example.com' }],
        })
        .build();

      expect(manifest.metadata.name).toBe(metadata.name);
      expect(manifest.metadata.description).toBe(metadata.description);
      expect(manifest.metadata.agent_version).toBe(metadata.agent_version);
    });

    it('should set optional metadata fields', async () => {
      const identity = createTestIdentity();
      const metadata = {
        name: 'MyAgent',
        description: 'Test',
        agent_version: '1.0.0',
        tags: ['research', 'testing'],
        homepage: 'https://example.com',
        logo: 'https://example.com/logo.png',
        operator: {
          name: 'Acme Corp',
          url: 'https://acme.example.com',
          contact: 'support@acme.example.com',
        },
      };

      const manifest = await new ManifestBuilder(identity)
        .setSequence(1)
        .setValidUntil(new Date(Date.now() + 1000))
        .setMetadata(metadata)
        .setCapabilities({
          interfaces: [{ protocol: 'https', url: 'https://api.example.com' }],
        })
        .build();

      expect(manifest.metadata.tags).toEqual(metadata.tags);
      expect(manifest.metadata.homepage).toBe(metadata.homepage);
      expect(manifest.metadata.operator?.name).toBe(metadata.operator.name);
    });
  });

  describe('setCapabilities()', () => {
    it('should set interfaces', async () => {
      const identity = createTestIdentity();
      const capabilities = {
        interfaces: [
          {
            protocol: 'https' as const,
            url: 'https://api.example.com',
            api_standard: 'openai-v1-chat' as const,
            methods: ['chat', 'completion'],
          },
        ],
      };

      const manifest = await new ManifestBuilder(identity)
        .setSequence(1)
        .setValidUntil(new Date(Date.now() + 1000))
        .setMetadata({
          name: 'TestAgent',
          description: 'Test',
          agent_version: '1.0.0',
        })
        .setCapabilities(capabilities)
        .build();

      expect(manifest.capabilities.interfaces).toHaveLength(1);
      expect(manifest.capabilities.interfaces[0].api_standard).toBe('openai-v1-chat');
      expect(manifest.capabilities.interfaces[0].methods).toEqual(['chat', 'completion']);
    });

    it('should set categories', async () => {
      const identity = createTestIdentity();
      const manifest = await new ManifestBuilder(identity)
        .setSequence(1)
        .setValidUntil(new Date(Date.now() + 1000))
        .setMetadata({
          name: 'TestAgent',
          description: 'Test',
          agent_version: '1.0.0',
        })
        .setCapabilities({
          interfaces: [{ protocol: 'https', url: 'https://api.example.com' }],
          categories: ['research.summarization', 'productivity'],
        })
        .build();

      expect(manifest.capabilities.categories).toEqual(['research.summarization', 'productivity']);
    });
  });

  describe('build()', () => {
    it('should create a valid signed manifest', async () => {
      const identity = createTestIdentity();
      const manifest = await createMinimalManifest(identity);

      expect(manifest.id).toBe(identity.did);
      expect(manifest.sequence).toBe(1);
      expect(manifest.proof).toBeDefined();
      expect(manifest.proof.type).toBe('Ed25519Signature2020');
      expect(manifest.proof.proof_value).toMatch(/^z[1-9A-HJ-NP-Za-km-z]+$/);
    });

    it('should set timestamps automatically', async () => {
      const identity = createTestIdentity();
      const beforeBuild = Date.now();
      const manifest = await createMinimalManifest(identity);
      const afterBuild = Date.now();

      const createdAt = new Date(manifest.created_at).getTime();
      expect(createdAt).toBeGreaterThanOrEqual(beforeBuild);
      expect(createdAt).toBeLessThanOrEqual(afterBuild);

      const updatedAt = new Date(manifest.updated_at).getTime();
      expect(updatedAt).toBeGreaterThanOrEqual(beforeBuild);
      expect(updatedAt).toBeLessThanOrEqual(afterBuild);
    });

    it('should create verifiable manifest', async () => {
      const identity = createTestIdentity();
      const manifest = await createMinimalManifest(identity);

      // Verify the manifest signature
      const isValid = await verifyManifest(manifest);
      expect(isValid).toBe(true);
    });

    it('should throw if sequence not set', async () => {
      const identity = createTestIdentity();
      await expect(
        new ManifestBuilder(identity)
          .setValidUntil(new Date(Date.now() + 1000))
          .setMetadata({
            name: 'TestAgent',
            description: 'Test',
            agent_version: '1.0.0',
          })
          .setCapabilities({
            interfaces: [{ protocol: 'https', url: 'https://api.example.com' }],
          })
          .build()
      ).rejects.toThrow('Sequence is required');
    });

    it('should throw if validUntil not set', async () => {
      const identity = createTestIdentity();
      await expect(
        new ManifestBuilder(identity)
          .setSequence(1)
          .setMetadata({
            name: 'TestAgent',
            description: 'Test',
            agent_version: '1.0.0',
          })
          .setCapabilities({
            interfaces: [{ protocol: 'https', url: 'https://api.example.com' }],
          })
          .build()
      ).rejects.toThrow('ValidUntil is required');
    });

    it('should throw if metadata not set', async () => {
      const identity = createTestIdentity();
      await expect(
        new ManifestBuilder(identity)
          .setSequence(1)
          .setValidUntil(new Date(Date.now() + 1000))
          .setCapabilities({
            interfaces: [{ protocol: 'https', url: 'https://api.example.com' }],
          })
          .build()
      ).rejects.toThrow('Metadata is required');
    });

    it('should throw if capabilities not set', async () => {
      const identity = createTestIdentity();
      await expect(
        new ManifestBuilder(identity)
          .setSequence(1)
          .setValidUntil(new Date(Date.now() + 1000))
          .setMetadata({
            name: 'TestAgent',
            description: 'Test',
            agent_version: '1.0.0',
          })
          .build()
      ).rejects.toThrow('Capabilities is required');
    });
  });
});
