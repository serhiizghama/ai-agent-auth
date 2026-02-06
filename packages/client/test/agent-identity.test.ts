/**
 * Tests for AgentIdentity
 */

import { describe, it, expect } from 'vitest';
import { AgentIdentity } from '../src/agent-identity';
import { hexToBytes, bytesToHex, parseDID } from '@ai-agent-auth/core';

describe('AgentIdentity', () => {
  describe('generate()', () => {
    it('should generate a new identity with did:key', () => {
      const identity = AgentIdentity.generate();

      expect(identity.did).toMatch(/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/);
      expect(identity.publicKey).toHaveLength(32);
      expect(identity.parsedDID.method).toBe('key');
      expect(identity.verificationMethod).toBe(`${identity.did}#${identity.did}`);
    });

    it('should generate unique identities', () => {
      const id1 = AgentIdentity.generate();
      const id2 = AgentIdentity.generate();

      expect(id1.did).not.toBe(id2.did);
      expect(id1.exportPrivateKeyHex()).not.toBe(id2.exportPrivateKeyHex());
    });
  });

  describe('fromPrivateKey()', () => {
    it('should restore identity from 32-byte private key', async () => {
      const original = AgentIdentity.generate();
      const privateKey = hexToBytes(original.exportPrivateKeyHex());

      const restored = await AgentIdentity.fromPrivateKey(privateKey);

      expect(restored.did).toBe(original.did);
      expect(restored.exportPublicKeyHex()).toBe(original.exportPublicKeyHex());
    });

    it('should allow specifying a custom DID', async () => {
      const original = AgentIdentity.generate();
      const privateKey = hexToBytes(original.exportPrivateKeyHex());
      const customDid = 'did:web:agent.example.com';

      const restored = await AgentIdentity.fromPrivateKey(privateKey, customDid);

      expect(restored.did).toBe(customDid);
      expect(restored.parsedDID.method).toBe('web');
      expect(restored.verificationMethod).toBe('did:web:agent.example.com#key-1');
    });

    it('should throw if private key is not 32 bytes', async () => {
      await expect(
        AgentIdentity.fromPrivateKey(new Uint8Array(16))
      ).rejects.toThrow('Private key must be exactly 32 bytes');
    });
  });

  describe('fromPrivateKeyHex()', () => {
    it('should restore identity from hex string', async () => {
      const original = AgentIdentity.generate();
      const hex = original.exportPrivateKeyHex();

      const restored = await AgentIdentity.fromPrivateKeyHex(hex);

      expect(restored.did).toBe(original.did);
      expect(restored.exportPublicKeyHex()).toBe(original.exportPublicKeyHex());
    });

    it('should throw if hex string is not 64 characters', async () => {
      await expect(
        AgentIdentity.fromPrivateKeyHex('abc123')
      ).rejects.toThrow('Hex string must be exactly 64 characters');
    });
  });

  describe('sign()', () => {
    it('should sign data with Ed25519', async () => {
      const identity = AgentIdentity.generate();
      const data = new TextEncoder().encode('Hello, world!');

      const signature = await identity.sign(data);

      expect(signature).toHaveLength(64);
    });

    it('should produce consistent signatures for same data', async () => {
      const identity = AgentIdentity.generate();
      const data = new TextEncoder().encode('Test message');

      const sig1 = await identity.sign(data);
      const sig2 = await identity.sign(data);

      expect(bytesToHex(sig1)).toBe(bytesToHex(sig2));
    });
  });

  describe('signChallenge()', () => {
    it('should sign challenge with correct format', async () => {
      const identity = AgentIdentity.generate();
      const challenge = 'a'.repeat(64);
      const expiresAt = new Date().toISOString();

      const signature = await identity.signChallenge(challenge, identity.did, expiresAt);

      expect(signature).toMatch(/^z[1-9A-HJ-NP-Za-km-z]+$/);
    });

    it('should throw if DID does not match', async () => {
      const identity = AgentIdentity.generate();
      const challenge = 'a'.repeat(64);
      const expiresAt = new Date().toISOString();

      await expect(
        identity.signChallenge(challenge, 'did:key:z6MkOtherDID', expiresAt)
      ).rejects.toThrow('DID mismatch');
    });
  });

  describe('exportPrivateKeyHex()', () => {
    it('should export 64-character hex string', () => {
      const identity = AgentIdentity.generate();
      const hex = identity.exportPrivateKeyHex();

      expect(hex).toHaveLength(64);
      expect(hex).toMatch(/^[0-9a-f]{64}$/);
    });

    it('should round-trip through hex export/import', async () => {
      const original = AgentIdentity.generate();
      const hex = original.exportPrivateKeyHex();
      const restored = await AgentIdentity.fromPrivateKeyHex(hex);

      expect(restored.did).toBe(original.did);
      expect(restored.exportPrivateKeyHex()).toBe(hex);
    });
  });

  describe('exportPublicKeyHex()', () => {
    it('should export 64-character hex string', () => {
      const identity = AgentIdentity.generate();
      const hex = identity.exportPublicKeyHex();

      expect(hex).toHaveLength(64);
      expect(hex).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  describe('verification method', () => {
    it('should use self-referencing format for did:key', () => {
      const identity = AgentIdentity.generate();
      expect(identity.verificationMethod).toBe(`${identity.did}#${identity.did}`);
    });

    it('should use #key-1 fragment for did:web', async () => {
      const identity = AgentIdentity.generate();
      const privateKey = hexToBytes(identity.exportPrivateKeyHex());
      const webIdentity = await AgentIdentity.fromPrivateKey(
        privateKey,
        'did:web:example.com'
      );

      expect(webIdentity.verificationMethod).toBe('did:web:example.com#key-1');
    });
  });
});
