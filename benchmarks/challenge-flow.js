#!/usr/bin/env node
/**
 * Challenge-Response Flow Benchmark
 *
 * Measures the complete authentication flow performance
 */

import { generateKeyPair, signChallenge, verifyChallengeSignature } from '@ai-agent-auth/core'
import { publicKeyToDidKey } from '@ai-agent-auth/core'

const ITERATIONS = 100
const WARMUP_ITERATIONS = 10

async function benchmark(name, fn, iterations) {
  // Warmup
  for (let i = 0; i < WARMUP_ITERATIONS; i++) {
    await fn()
  }

  // Measure
  const times = []
  for (let i = 0; i < iterations; i++) {
    const start = performance.now()
    await fn()
    const end = performance.now()
    times.push(end - start)
  }

  // Statistics
  const avg = times.reduce((a, b) => a + b, 0) / times.length
  const sorted = times.sort((a, b) => a - b)
  const p50 = sorted[Math.floor(sorted.length * 0.5)]
  const p95 = sorted[Math.floor(sorted.length * 0.95)]
  const p99 = sorted[Math.floor(sorted.length * 0.99)]
  const min = sorted[0]
  const max = sorted[sorted.length - 1]

  return { avg, p50, p95, p99, min, max }
}

async function main() {
  console.log('🔬 Challenge-Response Flow Benchmark')
  console.log('=' .repeat(60))
  console.log()

  // Setup
  const keyPair = generateKeyPair()
  const did = publicKeyToDidKey(keyPair.publicKey)
  const challenge = 'a'.repeat(64) // 256-bit challenge
  const expiresAt = new Date(Date.now() + 300000).toISOString()

  console.log(`📊 Configuration:`)
  console.log(`   Iterations: ${ITERATIONS}`)
  console.log(`   Warmup: ${WARMUP_ITERATIONS}`)
  console.log()

  // Benchmark 1: Challenge signing
  console.log('1️⃣  Challenge Signing')
  console.log('-'.repeat(60))

  const signResults = await benchmark(
    'Challenge Sign',
    async () => {
      await signChallenge(challenge, did, expiresAt, keyPair.privateKey)
    },
    ITERATIONS
  )

  console.log(`   Average:  ${signResults.avg.toFixed(3)} ms`)
  console.log(`   Median:   ${signResults.p50.toFixed(3)} ms`)
  console.log(`   P95:      ${signResults.p95.toFixed(3)} ms`)
  console.log(`   P99:      ${signResults.p99.toFixed(3)} ms`)
  console.log(`   Min:      ${signResults.min.toFixed(3)} ms`)
  console.log(`   Max:      ${signResults.max.toFixed(3)} ms`)
  console.log()

  // Benchmark 2: Challenge verification
  console.log('2️⃣  Challenge Verification')
  console.log('-'.repeat(60))

  const signature = await signChallenge(challenge, did, expiresAt, keyPair.privateKey)

  const verifyResults = await benchmark(
    'Challenge Verify',
    async () => {
      await verifyChallengeSignature(
        challenge,
        did,
        expiresAt,
        signature,
        keyPair.publicKey
      )
    },
    ITERATIONS
  )

  console.log(`   Average:  ${verifyResults.avg.toFixed(3)} ms`)
  console.log(`   Median:   ${verifyResults.p50.toFixed(3)} ms`)
  console.log(`   P95:      ${verifyResults.p95.toFixed(3)} ms`)
  console.log(`   P99:      ${verifyResults.p99.toFixed(3)} ms`)
  console.log(`   Min:      ${verifyResults.min.toFixed(3)} ms`)
  console.log(`   Max:      ${verifyResults.max.toFixed(3)} ms`)
  console.log()

  // Benchmark 3: Round-trip
  console.log('3️⃣  Round-Trip (Sign + Verify)')
  console.log('-'.repeat(60))

  const roundTripResults = await benchmark(
    'Round-Trip',
    async () => {
      const sig = await signChallenge(challenge, did, expiresAt, keyPair.privateKey)
      await verifyChallengeSignature(challenge, did, expiresAt, sig, keyPair.publicKey)
    },
    ITERATIONS
  )

  console.log(`   Average:  ${roundTripResults.avg.toFixed(3)} ms`)
  console.log(`   Median:   ${roundTripResults.p50.toFixed(3)} ms`)
  console.log(`   P95:      ${roundTripResults.p95.toFixed(3)} ms`)
  console.log(`   P99:      ${roundTripResults.p99.toFixed(3)} ms`)
  console.log(`   Min:      ${roundTripResults.min.toFixed(3)} ms`)
  console.log(`   Max:      ${roundTripResults.max.toFixed(3)} ms`)
  console.log()

  // Summary
  console.log('=' .repeat(60))
  console.log('📈 Summary')
  console.log('=' .repeat(60))
  console.log()
  console.log('Challenge-response flow performance:')
  console.log(`  Sign:       ${signResults.avg.toFixed(2)} ms avg`)
  console.log(`  Verify:     ${verifyResults.avg.toFixed(2)} ms avg`)
  console.log(`  Round-trip: ${roundTripResults.avg.toFixed(2)} ms avg`)
  console.log()
  console.log('Platform:', process.platform, process.arch)
  console.log('Node.js:', process.version)
  console.log()
}

main().catch(error => {
  console.error('Benchmark failed:', error)
  process.exit(1)
})
