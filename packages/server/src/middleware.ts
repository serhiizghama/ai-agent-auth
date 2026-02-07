/**
 * Express middleware for AI agent authentication
 */

import type { Request, Response, NextFunction, Router } from 'express';
import { AgentAuthHandler } from './auth-handler';
import type { ServerConfig, AuthenticatedRequest } from './config';
import { AuthError, AuthErrorCode } from '@ai-agent-auth/core';

/**
 * Create Express middleware for AI agent authentication.
 *
 * Returns an object with:
 * - `router` — Express router with auth endpoints (/challenge, /verify, /register)
 * - `guard` — Middleware for protecting routes (validates JWT)
 * - `handler` — Underlying AgentAuthHandler instance
 *
 * @param config - Server configuration
 * @returns Middleware bundle { router, guard, handler }
 *
 * @example
 * ```typescript
 * import express from 'express';
 * import { agentAuthMiddleware } from '@ai-agent-auth/server';
 *
 * const app = express();
 * const auth = agentAuthMiddleware({
 *   issuer: 'https://api.example.com',
 *   jwtSecret: keyPair,
 * });
 *
 * // Mount auth endpoints
 * app.use(auth.router);
 *
 * // Protect routes
 * app.get('/protected', auth.guard, (req: AuthenticatedRequest, res) => {
 *   res.json({ message: `Hello ${req.agent.sub}` });
 * });
 *
 * // Clean up on shutdown
 * process.on('SIGTERM', () => auth.handler.destroy());
 * ```
 */
export function agentAuthMiddleware(config: ServerConfig): {
  router: Router;
  guard: (req: Request, res: Response, next: NextFunction) => Promise<void>;
  handler: AgentAuthHandler;
} {
  const handler = new AgentAuthHandler(config);
  const pathPrefix = config.pathPrefix ?? '/auth';

  // Lazy-load express to avoid bundling it
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const express = require('express') as typeof import('express');
  const router = express.Router();

  // Body parser for JSON
  router.use(express.json());

  /**
   * POST /auth/challenge
   *
   * Request a challenge for a DID.
   */
  router.post(`${pathPrefix}/challenge`, async (req, res) => {
    try {
      const response = await handler.handleChallenge(req.body);
      res.status(200).json(response);
    } catch (error) {
      handleErrorResponse(error, res);
    }
  });

  /**
   * POST /auth/verify
   *
   * Submit signed challenge + manifest for verification.
   */
  router.post(`${pathPrefix}/verify`, async (req, res) => {
    try {
      const response = await handler.handleVerify(req.body);
      res.status(200).json(response);
    } catch (error) {
      handleErrorResponse(error, res);
    }
  });

  /**
   * POST /auth/register
   *
   * Register a new agent (if registration is enabled).
   */
  router.post(`${pathPrefix}/register`, async (req, res) => {
    try {
      const response = await handler.handleRegister(req.body);
      res.status(201).json(response);
    } catch (error) {
      handleErrorResponse(error, res);
    }
  });

  /**
   * Guard middleware for protecting routes.
   *
   * Validates JWT token from Authorization header.
   * Sets `req.agent` with decoded token payload.
   */
  const guard = async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Extract token from Authorization header
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        throw new AuthError(
          AuthErrorCode.AUTH_INVALID_TOKEN,
          'Missing Authorization header',
        );
      }

      if (!authHeader.startsWith('Bearer ')) {
        throw new AuthError(
          AuthErrorCode.AUTH_INVALID_TOKEN,
          'Authorization header must use Bearer scheme',
        );
      }

      const token = authHeader.substring(7); // Remove "Bearer " prefix

      // Validate token
      const payload = await handler.validateToken(token);

      // Set agent on request
      (req as AuthenticatedRequest).agent = payload;

      next();
    } catch (error) {
      handleErrorResponse(error, res);
    }
  };

  return { router, guard, handler };
}

/**
 * Handle error responses with proper status codes.
 */
function handleErrorResponse(error: unknown, res: Response): void {
  if (error instanceof AuthError) {
    // Get HTTP status code from error code
    const statusCode = getStatusCodeForError(error.code);

    // Special handling for pending approval (202)
    if (error.code === AuthErrorCode.AUTH_DID_PENDING) {
      res.status(202).json({
        status: 'pending_approval',
        message: error.message,
        retry_after: error.details?.retry_after ?? 3600,
      });
      return;
    }

    // Standard error response
    res.status(statusCode).json({
      error: {
        code: error.code,
        message: error.message,
        ...(error.details && { details: error.details }),
      },
    });
  } else {
    // Unknown error - return 500
    const message = error instanceof Error ? error.message : 'Internal server error';
    res.status(500).json({
      error: {
        code: AuthErrorCode.AUTH_INTERNAL_ERROR,
        message,
      },
    });
  }
}

/**
 * Map error codes to HTTP status codes.
 */
function getStatusCodeForError(code: AuthErrorCode): number {
  switch (code) {
    // 400 Bad Request
    case AuthErrorCode.AUTH_INVALID_REQUEST:
    case AuthErrorCode.AUTH_INVALID_SIGNATURE:
    case AuthErrorCode.AUTH_INVALID_MANIFEST_SIGNATURE:
    case AuthErrorCode.AUTH_EXPIRED_CHALLENGE:
    case AuthErrorCode.AUTH_CHALLENGE_NOT_FOUND:
    case AuthErrorCode.AUTH_CHALLENGE_ALREADY_USED:
    case AuthErrorCode.AUTH_DID_MISMATCH:
    case AuthErrorCode.AUTH_MANIFEST_EXPIRED:
    case AuthErrorCode.AUTH_MANIFEST_ROLLBACK:
    case AuthErrorCode.AUTH_UNSUPPORTED_DID_METHOD:
    case AuthErrorCode.AUTH_DID_RESOLUTION_FAILED:
      return 400;

    // 401 Unauthorized
    case AuthErrorCode.AUTH_INVALID_TOKEN:
      return 401;

    // 403 Forbidden
    case AuthErrorCode.AUTH_DID_NOT_FOUND:
    case AuthErrorCode.AUTH_DID_REJECTED:
    case AuthErrorCode.AUTH_DID_BANNED:
      return 403;

    // 429 Too Many Requests
    case AuthErrorCode.AUTH_RATE_LIMITED:
      return 429;

    // 202 Accepted (pending)
    case AuthErrorCode.AUTH_DID_PENDING:
      return 202;

    // 500 Internal Server Error
    case AuthErrorCode.AUTH_INTERNAL_ERROR:
    default:
      return 500;
  }
}
