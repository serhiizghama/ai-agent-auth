/**
 * JWT token issuance and verification utilities
 */

import { SignJWT, jwtVerify, type JWTPayload } from 'jose';
import type { KeyPair, AgentTokenPayload } from '@ai-agent-auth/core';
import { AuthError, AuthErrorCode } from '@ai-agent-auth/core';
import { randomBytes } from '@ai-agent-auth/core';

/**
 * JWT signing options
 */
interface JWTSignOptions {
  /**
   * Issuer identifier (iss claim)
   */
  issuer: string;

  /**
   * Token lifetime in seconds
   */
  lifetimeSeconds: number;

  /**
   * Secret key (HMAC-SHA256) or Ed25519 key pair
   */
  secret: string | KeyPair;

  /**
   * Optional audience (aud claim). Defaults to issuer.
   */
  audience?: string;
}

/**
 * JWT verification options
 */
interface JWTVerifyOptions {
  /**
   * Issuer identifier (iss claim) to validate
   */
  issuer: string;

  /**
   * Secret key (HMAC-SHA256) or Ed25519 key pair
   */
  secret: string | KeyPair;

  /**
   * Optional audience (aud claim) to validate. Defaults to issuer.
   */
  audience?: string;

  /**
   * Clock skew tolerance in seconds (default: 60)
   */
  clockSkewSeconds?: number;
}

/**
 * Generate a random JWT ID (jti claim).
 *
 * @returns 32-character hex string
 */
function generateJti(): string {
  return Buffer.from(randomBytes(16)).toString('hex');
}

/**
 * Sign a JWT token for an authenticated agent.
 *
 * Supports both HS256 (HMAC-SHA256 with string secret) and EdDSA (Ed25519 with KeyPair).
 *
 * @param payload - Agent token payload (scope, agent_name, agent_version, manifest_sequence)
 * @param did - Agent's DID (will be set as sub claim)
 * @param options - Signing options (issuer, lifetime, secret)
 * @returns Signed JWT string
 *
 * @example
 * ```typescript
 * const token = await signJWT(
 *   { scope: 'read write', agent_name: 'MyAgent', agent_version: '1.0.0', manifest_sequence: 1 },
 *   'did:key:z6Mk...',
 *   { issuer: 'https://api.example.com', lifetimeSeconds: 3600, secret: keyPair }
 * );
 * ```
 */
export async function signJWT(
  payload: Omit<AgentTokenPayload, 'iss' | 'sub' | 'exp' | 'iat' | 'jti'>,
  did: string,
  options: JWTSignOptions,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + options.lifetimeSeconds;

  const fullPayload: AgentTokenPayload = {
    ...payload,
    iss: options.issuer,
    sub: did,
    exp,
    iat: now,
    jti: generateJti(),
  };

  const jwt = new SignJWT(fullPayload as unknown as JWTPayload);

  jwt
    .setProtectedHeader(
      typeof options.secret === 'string'
        ? { alg: 'HS256' }
        : { alg: 'EdDSA' },
    )
    .setIssuedAt(now)
    .setExpirationTime(exp)
    .setIssuer(options.issuer)
    .setSubject(did)
    .setJti(fullPayload.jti);

  // Set audience if provided
  if (options.audience) {
    jwt.setAudience(options.audience);
  }

  if (typeof options.secret === 'string') {
    // HMAC-SHA256 signing
    const secret = new TextEncoder().encode(options.secret);
    return jwt.sign(secret);
  } else {
    // EdDSA (Ed25519) signing
    // jose expects the private key as a CryptoKey or KeyLike
    // For Ed25519, we need to import the raw key
    const { importJWK } = await import('jose');

    // Convert Ed25519 private key to JWK format
    // Ed25519 private key is 32 bytes, public key is 32 bytes
    const privateKeyJwk = {
      kty: 'OKP',
      crv: 'Ed25519',
      x: Buffer.from(options.secret.publicKey).toString('base64url'),
      d: Buffer.from(options.secret.privateKey).toString('base64url'),
    };

    const privateKey = await importJWK(privateKeyJwk, 'EdDSA');
    return jwt.sign(privateKey);
  }
}

/**
 * Verify a JWT token and extract the payload.
 *
 * Validates signature, expiration, issuer, and audience.
 * Applies clock skew tolerance.
 *
 * @param token - JWT token string
 * @param options - Verification options (issuer, secret, audience, clock skew)
 * @returns Decoded and validated agent token payload
 * @throws {AuthError} if token is invalid or expired
 *
 * @example
 * ```typescript
 * try {
 *   const payload = await verifyJWT(token, {
 *     issuer: 'https://api.example.com',
 *     secret: keyPair,
 *   });
 *   console.log('Authenticated agent:', payload.sub);
 * } catch (error) {
 *   console.error('Invalid token:', error.message);
 * }
 * ```
 */
export async function verifyJWT(
  token: string,
  options: JWTVerifyOptions,
): Promise<AgentTokenPayload> {
  const clockTolerance = options.clockSkewSeconds ?? 60;

  try {
    let result;

    if (typeof options.secret === 'string') {
      // HMAC-SHA256 verification
      const secret = new TextEncoder().encode(options.secret);
      result = await jwtVerify(token, secret, {
        issuer: options.issuer,
        audience: options.audience,
        clockTolerance,
      });
    } else {
      // EdDSA (Ed25519) verification
      const { importJWK } = await import('jose');

      // Convert Ed25519 public key to JWK format
      const publicKeyJwk = {
        kty: 'OKP',
        crv: 'Ed25519',
        x: Buffer.from(options.secret.publicKey).toString('base64url'),
      };

      const publicKey = await importJWK(publicKeyJwk, 'EdDSA');
      result = await jwtVerify(token, publicKey, {
        issuer: options.issuer,
        audience: options.audience,
        clockTolerance,
      });
    }

    // Validate that required claims are present
    const payload = result.payload as unknown as AgentTokenPayload;

    if (!payload.sub || typeof payload.sub !== 'string') {
      throw new AuthError(
        AuthErrorCode.AUTH_INVALID_TOKEN,
        'Token missing required "sub" claim',
      );
    }

    if (!payload.scope || typeof payload.scope !== 'string') {
      throw new AuthError(
        AuthErrorCode.AUTH_INVALID_TOKEN,
        'Token missing required "scope" claim',
      );
    }

    return payload;
  } catch (error) {
    // Handle jose library errors
    if (error instanceof AuthError) {
      throw error;
    }

    if (error instanceof Error) {
      // Check for common jose errors
      if (error.message.includes('expired')) {
        throw new AuthError(
          AuthErrorCode.AUTH_INVALID_TOKEN,
          'Token has expired',
        );
      }

      if (
        error.message.includes('signature') ||
        error.message.includes('invalid')
      ) {
        throw new AuthError(
          AuthErrorCode.AUTH_INVALID_TOKEN,
          `Invalid token: ${error.message}`,
        );
      }

      throw new AuthError(
        AuthErrorCode.AUTH_INVALID_TOKEN,
        `Token verification failed: ${error.message}`,
      );
    }

    throw new AuthError(
      AuthErrorCode.AUTH_INVALID_TOKEN,
      'Token verification failed',
    );
  }
}
