#!/usr/bin/env node
/**
 * Basic Agent Example
 *
 * This example demonstrates how an AI agent can authenticate with a server
 * using the @ai-agent-auth/client SDK.
 *
 * Usage:
 *   node index.js <server-url>
 *
 * Example:
 *   node index.js http://localhost:3000
 */

import { AgentIdentity, ManifestBuilder, AuthClient } from '@ai-agent-auth/client'

async function main() {
  const serverUrl = process.argv[2] || 'http://localhost:3000'

  console.log('🤖 AI Agent Authentication Example')
  console.log('=' .repeat(50))
  console.log()

  // Step 1: Generate agent identity
  console.log('📝 Step 1: Generating agent identity...')
  const identity = AgentIdentity.generate()
  console.log(`   ✅ DID: ${identity.did}`)
  console.log(`   ✅ Public Key: ${identity.exportPublicKeyHex().slice(0, 16)}...`)
  console.log()

  // Step 2: Build agent manifest
  console.log('📋 Step 2: Building agent manifest...')
  const manifest = await new ManifestBuilder(identity)
    .setSequence(1)
    .setValidUntil(new Date(Date.now() + 365 * 24 * 60 * 60 * 1000))
    .setMetadata({
      name: 'Example Basic Agent',
      description: 'A simple demonstration agent for ai-agent-auth',
      agent_version: '1.0.0',
      operator: {
        name: 'Example Operator',
        url: 'https://example.com',
        contact: 'operator@example.com'
      }
    })
    .setCapabilities({
      interfaces: [{
        protocol: 'https',
        url: 'https://api.example.com/chat'
      }],
      categories: ['text-generation']
    })
    .build()

  console.log(`   ✅ Manifest created with sequence: ${manifest.sequence}`)
  console.log(`   ✅ Valid until: ${manifest.valid_until}`)
  console.log()

  // Step 3: Authenticate with server
  console.log('🔐 Step 3: Authenticating with server...')
  console.log(`   Server: ${serverUrl}`)

  try {
    const client = new AuthClient({
      baseUrl: serverUrl,
      identity,
      manifest
    })

    const session = await client.authenticate()

    console.log('   ✅ Authentication successful!')
    console.log(`   ✅ Token: ${session.token.slice(0, 20)}...`)
    console.log(`   ✅ Expires: ${session.expiresAt.toISOString()}`)
    console.log(`   ✅ DID: ${session.did}`)
    console.log()

    // Step 4: Use the session
    console.log('🎯 Step 4: Session ready for use')
    console.log(`   Authorization header: ${session.toAuthorizationHeader().slice(0, 30)}...`)
    console.log()

    // Check expiry
    if (session.willExpireIn(3600)) {
      console.log('   ⚠️  Token will expire in less than 1 hour')
    } else {
      console.log('   ✅ Token is valid for more than 1 hour')
    }

    console.log()
    console.log('✨ Example completed successfully!')

  } catch (error) {
    console.error('   ❌ Authentication failed!')
    console.error(`   Error: ${error.message}`)

    if (error.code) {
      console.error(`   Code: ${error.code}`)
    }

    if (error.details) {
      console.error(`   Details: ${JSON.stringify(error.details, null, 2)}`)
    }

    console.log()
    console.log('💡 Troubleshooting:')
    console.log('   1. Make sure the server is running')
    console.log('   2. Check that the server URL is correct')
    console.log('   3. Verify the agent is approved in the server ACL')

    process.exit(1)
  }
}

main().catch(error => {
  console.error('Fatal error:', error)
  process.exit(1)
})
