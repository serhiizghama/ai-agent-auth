/**
 * Error handling for ai-agent-auth
 * Based on AAA-SPEC.md Section 9
 */

import type { AuthErrorBody } from './types'

/**
 * Error codes from SPEC Section 9.1
 */
export enum AuthErrorCode {
  // Request validation errors (400)
  AUTH_INVALID_REQUEST = 'AUTH_INVALID_REQUEST',
  AUTH_INVALID_SIGNATURE = 'AUTH_INVALID_SIGNATURE',
  AUTH_INVALID_MANIFEST_SIGNATURE = 'AUTH_INVALID_MANIFEST_SIGNATURE',
  AUTH_EXPIRED_CHALLENGE = 'AUTH_EXPIRED_CHALLENGE',
  AUTH_CHALLENGE_NOT_FOUND = 'AUTH_CHALLENGE_NOT_FOUND',
  AUTH_CHALLENGE_ALREADY_USED = 'AUTH_CHALLENGE_ALREADY_USED',
  AUTH_DID_MISMATCH = 'AUTH_DID_MISMATCH',
  AUTH_MANIFEST_EXPIRED = 'AUTH_MANIFEST_EXPIRED',
  AUTH_MANIFEST_ROLLBACK = 'AUTH_MANIFEST_ROLLBACK',
  AUTH_MANIFEST_REVOKED = 'AUTH_MANIFEST_REVOKED',
  AUTH_UNSUPPORTED_DID_METHOD = 'AUTH_UNSUPPORTED_DID_METHOD',
  AUTH_DID_RESOLUTION_FAILED = 'AUTH_DID_RESOLUTION_FAILED',

  // Authorization errors (403)
  AUTH_DID_NOT_FOUND = 'AUTH_DID_NOT_FOUND',
  AUTH_DID_REJECTED = 'AUTH_DID_REJECTED',
  AUTH_DID_BANNED = 'AUTH_DID_BANNED',

  // Pending status (202)
  AUTH_DID_PENDING = 'AUTH_DID_PENDING',

  // Token errors (401)
  AUTH_INVALID_TOKEN = 'AUTH_INVALID_TOKEN',

  // Rate limiting (429)
  AUTH_RATE_LIMITED = 'AUTH_RATE_LIMITED',

  // Internal errors (500)
  AUTH_INTERNAL_ERROR = 'AUTH_INTERNAL_ERROR',
}

/**
 * HTTP status code mapping for error codes
 */
export const ERROR_STATUS_MAP: Record<AuthErrorCode, number> = {
  [AuthErrorCode.AUTH_INVALID_REQUEST]: 400,
  [AuthErrorCode.AUTH_INVALID_SIGNATURE]: 400,
  [AuthErrorCode.AUTH_INVALID_MANIFEST_SIGNATURE]: 400,
  [AuthErrorCode.AUTH_EXPIRED_CHALLENGE]: 400,
  [AuthErrorCode.AUTH_CHALLENGE_NOT_FOUND]: 400,
  [AuthErrorCode.AUTH_CHALLENGE_ALREADY_USED]: 400,
  [AuthErrorCode.AUTH_DID_MISMATCH]: 400,
  [AuthErrorCode.AUTH_MANIFEST_EXPIRED]: 400,
  [AuthErrorCode.AUTH_MANIFEST_ROLLBACK]: 400,
  [AuthErrorCode.AUTH_MANIFEST_REVOKED]: 403,
  [AuthErrorCode.AUTH_UNSUPPORTED_DID_METHOD]: 400,
  [AuthErrorCode.AUTH_DID_RESOLUTION_FAILED]: 400,
  [AuthErrorCode.AUTH_DID_NOT_FOUND]: 403,
  [AuthErrorCode.AUTH_DID_REJECTED]: 403,
  [AuthErrorCode.AUTH_DID_BANNED]: 403,
  [AuthErrorCode.AUTH_DID_PENDING]: 202,
  [AuthErrorCode.AUTH_INVALID_TOKEN]: 401,
  [AuthErrorCode.AUTH_RATE_LIMITED]: 429,
  [AuthErrorCode.AUTH_INTERNAL_ERROR]: 500,
}

/**
 * Default error messages
 */
export const ERROR_MESSAGES: Record<AuthErrorCode, string> = {
  [AuthErrorCode.AUTH_INVALID_REQUEST]:
    'Request body failed schema validation.',
  [AuthErrorCode.AUTH_INVALID_SIGNATURE]:
    'Challenge signature verification failed.',
  [AuthErrorCode.AUTH_INVALID_MANIFEST_SIGNATURE]:
    'Manifest signature verification failed.',
  [AuthErrorCode.AUTH_EXPIRED_CHALLENGE]: 'Challenge has expired.',
  [AuthErrorCode.AUTH_CHALLENGE_NOT_FOUND]:
    'Challenge not found in the challenge store.',
  [AuthErrorCode.AUTH_CHALLENGE_ALREADY_USED]:
    'Challenge has already been consumed.',
  [AuthErrorCode.AUTH_DID_MISMATCH]:
    'DID in request does not match manifest or proof.',
  [AuthErrorCode.AUTH_MANIFEST_EXPIRED]: 'Manifest has expired.',
  [AuthErrorCode.AUTH_MANIFEST_ROLLBACK]:
    'Manifest sequence is lower than previously seen.',
  [AuthErrorCode.AUTH_MANIFEST_REVOKED]: 'Manifest has been revoked.',
  [AuthErrorCode.AUTH_UNSUPPORTED_DID_METHOD]:
    'DID method is not supported. Only did:key and did:web are allowed.',
  [AuthErrorCode.AUTH_DID_RESOLUTION_FAILED]:
    'Failed to resolve DID (network error or invalid DID document).',
  [AuthErrorCode.AUTH_DID_NOT_FOUND]:
    'DID is not registered in the access control list.',
  [AuthErrorCode.AUTH_DID_REJECTED]: 'DID registration was rejected.',
  [AuthErrorCode.AUTH_DID_BANNED]: 'DID has been banned.',
  [AuthErrorCode.AUTH_DID_PENDING]:
    'DID registration is pending admin approval.',
  [AuthErrorCode.AUTH_INVALID_TOKEN]:
    'JWT is invalid, expired, or malformed.',
  [AuthErrorCode.AUTH_RATE_LIMITED]: 'Too many requests. Please retry later.',
  [AuthErrorCode.AUTH_INTERNAL_ERROR]:
    'An internal server error occurred. Please try again later.',
}

/**
 * Custom error class for ai-agent-auth
 */
export class AuthError extends Error {
  public readonly code: AuthErrorCode
  public readonly statusCode: number
  public readonly details?: Record<string, unknown>

  constructor(
    code: AuthErrorCode,
    message?: string,
    details?: Record<string, unknown>
  ) {
    super(message || ERROR_MESSAGES[code])
    this.name = 'AuthError'
    this.code = code
    this.statusCode = ERROR_STATUS_MAP[code]
    this.details = details

    // Maintain proper stack trace in V8
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, AuthError)
    }
  }

  /**
   * Convert error to AuthErrorBody format for API responses
   */
  toJSON(): AuthErrorBody {
    return {
      error: {
        code: this.code,
        message: this.message,
        ...(this.details && { details: this.details }),
      },
    }
  }

  /**
   * Get HTTP status code for this error
   */
  getStatusCode(): number {
    return this.statusCode
  }

  /**
   * Check if error is a specific code
   */
  is(code: AuthErrorCode): boolean {
    return this.code === code
  }

  /**
   * Create AuthError from unknown error
   */
  static from(error: unknown): AuthError {
    if (error instanceof AuthError) {
      return error
    }

    if (error instanceof Error) {
      return new AuthError(
        AuthErrorCode.AUTH_INTERNAL_ERROR,
        error.message,
        { originalError: error.name }
      )
    }

    return new AuthError(
      AuthErrorCode.AUTH_INTERNAL_ERROR,
      'An unknown error occurred',
      { error: String(error) }
    )
  }
}
