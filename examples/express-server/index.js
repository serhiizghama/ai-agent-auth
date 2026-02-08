#!/usr/bin/env node
/**
 * Express Server Example with AI Agent Authentication
 *
 * This example demonstrates how to set up an Express server that authenticates
 * AI agents using the @ai-agent-auth/server middleware.
 *
 * Features:
 * - Challenge-response authentication endpoints
 * - JWT token issuance
 * - Protected routes with token validation
 * - Agent registration workflow
 * - ACL management
 */

import express from 'express'
import {
  AgentAuthHandler,
  agentAuthMiddleware,
  InMemoryACL,
  InMemoryChallengeStore,
  InMemoryManifestCache
} from '@ai-agent-auth/server'

const PORT = process.env.PORT || 3000
const JWT_SECRET = process.env.JWT_SECRET || 'demo-secret-change-in-production'

async function main() {
  const app = express()

  // Parse JSON bodies
  app.use(express.json())

  // Logging middleware
  app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} ${req.method} ${req.path}`)
    next()
  })

  console.log('🚀 Setting up AI Agent Authentication Server')
  console.log('=' .repeat(50))

  // Step 1: Create storage instances
  console.log('📦 Initializing storage...')
  const acl = new InMemoryACL()
  const challengeStore = new InMemoryChallengeStore()
  const manifestCache = new InMemoryManifestCache()
  console.log('   ✅ Storage initialized')

  // Step 2: Set up authentication handler
  console.log('🔐 Configuring authentication handler...')
  const authHandler = new AgentAuthHandler({
    acl,
    challengeStore,
    manifestCache,
    jwtSecret: JWT_SECRET,
    jwtExpiresIn: '1h',
    autoApproveNewAgents: true // For demo purposes
  })
  console.log('   ✅ Auth handler ready')
  console.log(`   ⚠️  Auto-approve enabled (disable in production)`)

  // Step 3: Mount authentication endpoints
  console.log('🛣️  Mounting authentication routes...')
  const { router, guard } = agentAuthMiddleware(authHandler)
  app.use('/auth', router)
  console.log('   ✅ POST /auth/challenge - Request authentication challenge')
  console.log('   ✅ POST /auth/verify - Submit challenge response')
  console.log('   ✅ POST /auth/register - Request agent registration')

  // Step 4: Public routes
  app.get('/', (req, res) => {
    res.json({
      message: 'AI Agent Authentication Server',
      version: '1.0.0',
      endpoints: {
        challenge: 'POST /auth/challenge',
        verify: 'POST /auth/verify',
        register: 'POST /auth/register',
        protected: 'GET /api/protected (requires auth)',
        info: 'GET /api/info (requires auth)'
      }
    })
  })

  app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() })
  })

  // Step 5: Protected routes (require authentication)
  console.log('🔒 Setting up protected routes...')

  app.get('/api/protected', guard, (req, res) => {
    // The guard middleware adds req.agent with the authenticated agent info
    res.json({
      message: 'You have accessed a protected route!',
      agent: {
        did: req.agent.did,
        name: req.agent.name,
        version: req.agent.version,
        capabilities: req.agent.capabilities
      },
      timestamp: new Date().toISOString()
    })
  })

  app.get('/api/info', guard, (req, res) => {
    res.json({
      message: 'Agent information',
      agent: req.agent,
      token: {
        issuedAt: new Date(req.agent.iat * 1000).toISOString(),
        expiresAt: new Date(req.agent.exp * 1000).toISOString()
      }
    })
  })

  app.post('/api/echo', guard, (req, res) => {
    res.json({
      echo: req.body,
      agent: { did: req.agent.did, name: req.agent.name }
    })
  })

  console.log('   ✅ GET /api/protected')
  console.log('   ✅ GET /api/info')
  console.log('   ✅ POST /api/echo')

  // Step 6: ACL management endpoints (admin only in production)
  app.get('/admin/acl', async (req, res) => {
    const agents = await acl.listAll()
    res.json({ agents })
  })

  app.post('/admin/acl/:did/approve', async (req, res) => {
    const { did } = req.params
    const decoded = decodeURIComponent(did)
    await acl.setStatus(decoded, 'approved')
    res.json({ message: 'Agent approved', did: decoded })
  })

  app.post('/admin/acl/:did/ban', async (req, res) => {
    const { did } = req.params
    const decoded = decodeURIComponent(did)
    await acl.setStatus(decoded, 'banned')
    res.json({ message: 'Agent banned', did: decoded })
  })

  console.log('   ✅ GET /admin/acl - List all agents')
  console.log('   ✅ POST /admin/acl/:did/approve')
  console.log('   ✅ POST /admin/acl/:did/ban')

  // Error handler
  app.use((err, req, res, next) => {
    console.error('Error:', err)
    res.status(err.status || 500).json({
      error: err.message || 'Internal server error',
      code: err.code || 'INTERNAL_ERROR'
    })
  })

  // Start server
  const server = app.listen(PORT, () => {
    console.log()
    console.log('=' .repeat(50))
    console.log(`✨ Server running on http://localhost:${PORT}`)
    console.log()
    console.log('Try it out:')
    console.log(`  curl http://localhost:${PORT}`)
    console.log(`  curl http://localhost:${PORT}/health`)
    console.log()
    console.log('Run the basic-agent example:')
    console.log('  cd ../basic-agent && pnpm start')
    console.log('=' .repeat(50))
  })

  // Graceful shutdown
  process.on('SIGTERM', () => {
    console.log('\n🛑 Shutting down gracefully...')
    authHandler.destroy()
    server.close(() => {
      console.log('✅ Server closed')
      process.exit(0)
    })
  })

  process.on('SIGINT', () => {
    console.log('\n🛑 Shutting down gracefully...')
    authHandler.destroy()
    server.close(() => {
      console.log('✅ Server closed')
      process.exit(0)
    })
  })
}

main().catch(error => {
  console.error('Fatal error:', error)
  process.exit(1)
})
