import { describe, it, expect } from 'vitest'
import { AuthError, AuthErrorCode, ERROR_STATUS_MAP } from '../src/errors'

describe('AuthError', () => {
  it('should create error with code and default message', () => {
    const error = new AuthError(AuthErrorCode.AUTH_INVALID_SIGNATURE)

    expect(error.code).toBe(AuthErrorCode.AUTH_INVALID_SIGNATURE)
    expect(error.message).toBe('Challenge signature verification failed.')
    expect(error.statusCode).toBe(400)
    expect(error.name).toBe('AuthError')
  })

  it('should create error with custom message', () => {
    const error = new AuthError(
      AuthErrorCode.AUTH_INVALID_SIGNATURE,
      'Custom error message'
    )

    expect(error.message).toBe('Custom error message')
  })

  it('should create error with details', () => {
    const details = { field: 'signature', reason: 'invalid format' }
    const error = new AuthError(
      AuthErrorCode.AUTH_INVALID_SIGNATURE,
      undefined,
      details
    )

    expect(error.details).toEqual(details)
  })

  it('should serialize to AuthErrorBody format', () => {
    const error = new AuthError(
      AuthErrorCode.AUTH_INVALID_SIGNATURE,
      'Signature is invalid',
      { field: 'signature' }
    )

    const json = error.toJSON()

    expect(json).toEqual({
      error: {
        code: 'AUTH_INVALID_SIGNATURE',
        message: 'Signature is invalid',
        details: { field: 'signature' },
      },
    })
  })

  it('should serialize without details if not provided', () => {
    const error = new AuthError(AuthErrorCode.AUTH_INVALID_SIGNATURE)
    const json = error.toJSON()

    expect(json.error.details).toBeUndefined()
  })

  it('should return correct status code', () => {
    const error = new AuthError(AuthErrorCode.AUTH_INVALID_SIGNATURE)
    expect(error.getStatusCode()).toBe(400)
  })

  it('should check error code with is() method', () => {
    const error = new AuthError(AuthErrorCode.AUTH_INVALID_SIGNATURE)

    expect(error.is(AuthErrorCode.AUTH_INVALID_SIGNATURE)).toBe(true)
    expect(error.is(AuthErrorCode.AUTH_INVALID_TOKEN)).toBe(false)
  })

  describe('from()', () => {
    it('should return AuthError as-is', () => {
      const original = new AuthError(AuthErrorCode.AUTH_INVALID_SIGNATURE)
      const converted = AuthError.from(original)

      expect(converted).toBe(original)
    })

    it('should convert regular Error to AuthError', () => {
      const original = new Error('Something went wrong')
      const converted = AuthError.from(original)

      expect(converted).toBeInstanceOf(AuthError)
      expect(converted.code).toBe(AuthErrorCode.AUTH_INTERNAL_ERROR)
      expect(converted.message).toBe('Something went wrong')
      expect(converted.details).toEqual({ originalError: 'Error' })
    })

    it('should convert unknown error to AuthError', () => {
      const converted = AuthError.from('string error')

      expect(converted).toBeInstanceOf(AuthError)
      expect(converted.code).toBe(AuthErrorCode.AUTH_INTERNAL_ERROR)
      expect(converted.message).toBe('An unknown error occurred')
      expect(converted.details).toEqual({ error: 'string error' })
    })
  })

  describe('ERROR_STATUS_MAP', () => {
    it('should map all error codes to status codes', () => {
      // Verify all error codes have status mappings
      const codes = Object.values(AuthErrorCode)

      codes.forEach((code) => {
        expect(ERROR_STATUS_MAP[code]).toBeDefined()
        expect(typeof ERROR_STATUS_MAP[code]).toBe('number')
      })
    })

    it('should use correct status codes', () => {
      expect(ERROR_STATUS_MAP[AuthErrorCode.AUTH_INVALID_REQUEST]).toBe(400)
      expect(ERROR_STATUS_MAP[AuthErrorCode.AUTH_DID_NOT_FOUND]).toBe(403)
      expect(ERROR_STATUS_MAP[AuthErrorCode.AUTH_INVALID_TOKEN]).toBe(401)
      expect(ERROR_STATUS_MAP[AuthErrorCode.AUTH_RATE_LIMITED]).toBe(429)
      expect(ERROR_STATUS_MAP[AuthErrorCode.AUTH_INTERNAL_ERROR]).toBe(500)
      expect(ERROR_STATUS_MAP[AuthErrorCode.AUTH_DID_PENDING]).toBe(202)
    })
  })
})
