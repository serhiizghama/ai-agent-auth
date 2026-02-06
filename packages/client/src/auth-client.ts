/**
 * AuthClient — Challenge-response authentication client for AI agents.
 *
 * Handles the full authentication flow:
 * 1. Request challenge from server
 * 2. Sign challenge with agent's private key
 * 3. Submit signature + manifest to server
 * 4. Receive JWT session token
 *
 * @packageDocumentation
 */

import {
  AuthError,
  AuthErrorCode,
  ChallengeRequestSchema,
  ChallengeResponseSchema,
  VerifyResponseSchema,
  RegisterResponseSchema,
  type ChallengeResponse,
  type VerifyResponse,
  type RegisterResponse,
  type AgentManifest,
} from '@ai-agent-auth/core';
import type { AgentIdentity } from './agent-identity';
import { Session } from './session';

/**
 * Configuration options for AuthClient.
 */
export interface AuthClientOptions {
  /**
   * Base URL of the authentication server.
   * Example: "https://api.example.com"
   */
  serverUrl: string;

  /**
   * Agent identity for signing challenges.
   */
  identity: AgentIdentity;

  /**
   * Pre-signed agent manifest.
   */
  manifest: AgentManifest;

  /**
   * Optional custom fetch implementation.
   * Defaults to globalThis.fetch.
   */
  fetch?: typeof globalThis.fetch;

  /**
   * Request timeout in milliseconds.
   * Default: 10000 (10 seconds).
   */
  timeoutMs?: number;

  /**
   * Path prefix for auth endpoints.
   * Default: "/auth"
   */
  pathPrefix?: string;
}

/**
 * AuthClient handles the challenge-response authentication flow.
 *
 * @example
 * ```typescript
 * const client = new AuthClient({
 *   serverUrl: 'https://api.example.com',
 *   identity: myIdentity,
 *   manifest: myManifest,
 * });
 *
 * try {
 *   const session = await client.authenticate();
 *   console.log('Authenticated! Token:', session.token);
 * } catch (error) {
 *   console.error('Auth failed:', error);
 * }
 * ```
 */
export class AuthClient {
  private serverUrl: string;
  private identity: AgentIdentity;
  private manifest: AgentManifest;
  private fetchFn: typeof globalThis.fetch;
  private timeoutMs: number;
  private pathPrefix: string;

  constructor(options: AuthClientOptions) {
    this.serverUrl = options.serverUrl.replace(/\/$/, ''); // Remove trailing slash
    this.identity = options.identity;
    this.manifest = options.manifest;
    this.fetchFn = options.fetch ?? globalThis.fetch;
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.pathPrefix = options.pathPrefix ?? '/auth';
  }

  /**
   * Execute the full challenge-response authentication flow.
   *
   * Steps:
   * 1. POST /auth/challenge → receive challenge
   * 2. Sign challenge with agent's private key
   * 3. POST /auth/verify → receive JWT
   *
   * @returns Session object with JWT and metadata
   * @throws {AuthError} with specific error code on failure
   *
   * @example
   * ```typescript
   * const session = await client.authenticate();
   * console.log('Token expires at:', session.expiresAt);
   * ```
   */
  public async authenticate(): Promise<Session> {
    // Step 1: Request challenge
    const challengeResponse = await this.requestChallenge();

    // Step 2: Sign challenge
    const signature = await this.identity.signChallenge(
      challengeResponse.challenge,
      this.identity.did,
      challengeResponse.expires_at,
    );

    // Step 3: Submit verification
    const verifyResponse = await this.submitVerification(
      challengeResponse.challenge,
      signature,
      challengeResponse.expires_at,
    );

    // Step 4: Create session
    return new Session(
      verifyResponse.token,
      new Date(verifyResponse.expires_at),
      verifyResponse.agent,
    );
  }

  /**
   * Request a challenge from the server.
   *
   * POST /auth/challenge with the agent's DID.
   *
   * @returns Challenge response with 64-char hex challenge and expiry
   * @throws {AuthError} if request fails or DID is not authorized
   *
   * @example
   * ```typescript
   * const { challenge, expires_at } = await client.requestChallenge();
   * ```
   */
  public async requestChallenge(): Promise<ChallengeResponse> {
    const url = `${this.serverUrl}${this.pathPrefix}/challenge`;

    const response = await this.fetchWithTimeout(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ did: this.identity.did }),
    });

    if (!response.ok) {
      await this.handleErrorResponse(response);
    }

    const data: unknown = await response.json();

    // Handle 202 Accepted (pending approval)
    if (response.status === 202) {
      const pendingData = data as { message?: string; retry_after?: number };
      throw new AuthError(
        AuthErrorCode.AUTH_DID_PENDING,
        pendingData.message ?? 'DID registration is pending approval',
        { retry_after: pendingData.retry_after },
      );
    }

    // Validate response schema
    const validation = ChallengeResponseSchema.safeParse(data);
    if (!validation.success) {
      throw new AuthError(
        AuthErrorCode.AUTH_INVALID_REQUEST,
        'Invalid challenge response format',
        { zodErrors: validation.error.errors },
      );
    }

    return validation.data;
  }

  /**
   * Submit a signed verification request to the server.
   *
   * POST /auth/verify with challenge, signature, and manifest.
   *
   * @param challenge - The challenge string from requestChallenge()
   * @param signature - Base58btc-encoded Ed25519 signature with 'z' prefix
   * @param expiresAt - ISO 8601 expiry timestamp from challenge response
   * @returns Verification response with JWT token
   * @throws {AuthError} if verification fails
   *
   * @example
   * ```typescript
   * const verifyResponse = await client.submitVerification(
   *   challenge,
   *   signature,
   *   expiresAt
   * );
   * ```
   */
  public async submitVerification(
    challenge: string,
    signature: string,
    expiresAt: string,
  ): Promise<VerifyResponse> {
    const url = `${this.serverUrl}${this.pathPrefix}/verify`;

    const response = await this.fetchWithTimeout(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        did: this.identity.did,
        challenge,
        signature,
        manifest: this.manifest,
      }),
    });

    if (!response.ok) {
      await this.handleErrorResponse(response);
    }

    const data = await response.json();

    // Validate response schema
    const validation = VerifyResponseSchema.safeParse(data);
    if (!validation.success) {
      throw new AuthError(
        AuthErrorCode.AUTH_INVALID_REQUEST,
        'Invalid verify response format',
        { zodErrors: validation.error.errors },
      );
    }

    return validation.data;
  }

  /**
   * Register the agent with the server.
   *
   * POST /auth/register with the agent's manifest and optional reason.
   *
   * @param reason - Human-readable reason for requesting access
   * @returns Registration response with status
   * @throws {AuthError} if registration fails
   *
   * @example
   * ```typescript
   * const response = await client.register('Need access for research project');
   * console.log('Status:', response.status);
   * ```
   */
  public async register(reason?: string): Promise<RegisterResponse> {
    const url = `${this.serverUrl}${this.pathPrefix}/register`;

    const response = await this.fetchWithTimeout(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        manifest: this.manifest,
        ...(reason && { reason }),
      }),
    });

    if (!response.ok && response.status !== 201) {
      await this.handleErrorResponse(response);
    }

    const data = await response.json();

    // Validate response schema
    const validation = RegisterResponseSchema.safeParse(data);
    if (!validation.success) {
      throw new AuthError(
        AuthErrorCode.AUTH_INVALID_REQUEST,
        'Invalid register response format',
        { zodErrors: validation.error.errors },
      );
    }

    return validation.data;
  }

  /**
   * Fetch with timeout support.
   */
  private async fetchWithTimeout(
    url: string,
    options: RequestInit,
  ): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await this.fetchFn(url, {
        ...options,
        signal: controller.signal,
      });
      return response;
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        throw new AuthError(
          AuthErrorCode.AUTH_INTERNAL_ERROR,
          `Request timeout after ${this.timeoutMs}ms`,
        );
      }
      throw new AuthError(
        AuthErrorCode.AUTH_INTERNAL_ERROR,
        `Network error: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Handle error responses from the server.
   */
  private async handleErrorResponse(response: Response): Promise<never> {
    let errorData: unknown;

    try {
      errorData = await response.json();
    } catch {
      // If response is not JSON, throw generic error
      throw new AuthError(
        AuthErrorCode.AUTH_INTERNAL_ERROR,
        `Server returned ${response.status}: ${response.statusText}`,
      );
    }

    // Check if it's a standard error response
    if (
      errorData &&
      typeof errorData === 'object' &&
      'error' in errorData &&
      errorData.error &&
      typeof errorData.error === 'object' &&
      'code' in errorData.error &&
      'message' in errorData.error
    ) {
      throw new AuthError(
        errorData.error.code as AuthErrorCode,
        errorData.error.message as string,
        'details' in errorData.error ? (errorData.error.details as Record<string, unknown>) : undefined,
      );
    }

    // Fallback for non-standard error responses
    const message =
      errorData &&
      typeof errorData === 'object' &&
      'message' in errorData &&
      typeof errorData.message === 'string'
        ? errorData.message
        : `Server error: ${response.status}`;

    throw new AuthError(
      AuthErrorCode.AUTH_INTERNAL_ERROR,
      message,
      errorData as Record<string, unknown> | undefined,
    );
  }
}
