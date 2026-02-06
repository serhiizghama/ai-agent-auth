/**
 * Session — JWT session token management for authenticated agents.
 *
 * Manages the lifecycle of authenticated sessions, providing methods
 * to check token expiry and format authorization headers.
 *
 * @packageDocumentation
 */

import type { VerifyResponse } from '@ai-agent-auth/core';

/**
 * Session represents an authenticated agent session.
 *
 * Created by `AuthClient.authenticate()` after successful verification.
 * Provides utilities for checking token expiry and formatting auth headers.
 *
 * @example
 * ```typescript
 * const session = await client.authenticate();
 *
 * // Check if token is still valid
 * if (!session.isExpired) {
 *   // Use the token
 *   const headers = {
 *     Authorization: session.toAuthorizationHeader(),
 *   };
 * }
 *
 * // Proactive re-authentication before expiry
 * if (session.willExpireIn(300)) { // 5 minutes
 *   console.log('Token will expire soon, re-authenticating...');
 *   const newSession = await client.authenticate();
 * }
 * ```
 */
export class Session {
  /**
   * The JWT token string.
   */
  public readonly token: string;

  /**
   * When the token expires (UTC).
   */
  public readonly expiresAt: Date;

  /**
   * Agent metadata returned by the server.
   */
  public readonly agent: VerifyResponse['agent'];

  /**
   * Create a new Session instance.
   *
   * Typically created by AuthClient, not instantiated directly by users.
   *
   * @param token - JWT token string
   * @param expiresAt - Token expiration date
   * @param agentInfo - Agent metadata from verification response
   */
  constructor(
    token: string,
    expiresAt: Date,
    agentInfo: VerifyResponse['agent'],
  ) {
    this.token = token;
    this.expiresAt = expiresAt;
    this.agent = agentInfo;
  }

  /**
   * Check if the token has expired.
   *
   * Applies a 60-second grace period to account for clock skew.
   * Returns true if token expired more than 60 seconds ago.
   *
   * @returns true if the token has expired (beyond grace period)
   *
   * @example
   * ```typescript
   * if (session.isExpired) {
   *   console.log('Session expired, need to re-authenticate');
   * }
   * ```
   */
  public get isExpired(): boolean {
    const now = Date.now();
    const expiryWithGrace = this.expiresAt.getTime() + 60_000; // 60s grace period after expiry
    return now > expiryWithGrace;
  }

  /**
   * Check if the token will expire within the given number of seconds.
   *
   * Useful for proactive re-authentication before the token expires.
   *
   * @param seconds - Number of seconds to check ahead
   * @returns true if token will expire within the specified time
   *
   * @example
   * ```typescript
   * // Re-authenticate if token expires in less than 5 minutes
   * if (session.willExpireIn(300)) {
   *   await client.authenticate();
   * }
   * ```
   */
  public willExpireIn(seconds: number): boolean {
    const now = Date.now();
    const threshold = this.expiresAt.getTime() - (seconds * 1000);
    return now > threshold;
  }

  /**
   * Get the value for the HTTP Authorization header.
   *
   * @returns "Bearer {token}"
   *
   * @example
   * ```typescript
   * const response = await fetch('https://api.example.com/protected', {
   *   headers: {
   *     Authorization: session.toAuthorizationHeader(),
   *   },
   * });
   * ```
   */
  public toAuthorizationHeader(): string {
    return `Bearer ${this.token}`;
  }

  /**
   * Get a plain object representation of the session.
   *
   * Useful for serialization or logging (token is included, handle carefully).
   *
   * @returns Plain object with token, expiresAt (ISO string), and agent info
   *
   * @example
   * ```typescript
   * const sessionData = session.toJSON();
   * localStorage.setItem('session', JSON.stringify(sessionData));
   * ```
   */
  public toJSON(): {
    token: string;
    expiresAt: string;
    agent: VerifyResponse['agent'];
  } {
    return {
      token: this.token,
      expiresAt: this.expiresAt.toISOString(),
      agent: this.agent,
    };
  }

  /**
   * Restore a Session from a plain object (e.g., from localStorage).
   *
   * @param data - Plain object with token, expiresAt, and agent info
   * @returns Session instance
   *
   * @example
   * ```typescript
   * const sessionData = JSON.parse(localStorage.getItem('session')!);
   * const session = Session.fromJSON(sessionData);
   *
   * if (!session.isExpired) {
   *   // Use the restored session
   * }
   * ```
   */
  public static fromJSON(data: {
    token: string;
    expiresAt: string;
    agent: VerifyResponse['agent'];
  }): Session {
    return new Session(
      data.token,
      new Date(data.expiresAt),
      data.agent,
    );
  }
}
