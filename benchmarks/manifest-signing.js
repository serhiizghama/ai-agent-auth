#!/usr/bin/env node
/**
 * Manifest Signing & Verification Benchmark
 *
 * Target: < 10ms for sign + verify round-trip
 * SPEC: §12 Non-Functional Requirements
 */

import { AgentIdentity, ManifestBuilder } from '@ai-agent-auth/client'
import { verifyManifest } from '@ai-agent-auth/core'

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

  return { avg, p50, p95, p99, min, max, times }
}

async function main() {
  console.log('🔬 Manifest Signing & Verification Benchmark')
  console.log('=' .repeat(60))
  console.log()

  // Setup
  const identity = AgentIdentity.generate()
  const builder = new ManifestBuilder(identity)
    .setSequence(1)
    .setValidUntil(new Date(Date.now() + 365 * 24 * 60 * 60 * 1000))
    .setMetadata({
      name: 'Benchmark Agent',
      description: 'Performance testing agent',
      agent_version: '1.0.0',
      operator: {
        name: 'Benchmark Operator',
        url: 'https://example.com',
        contact: 'bench@example.com'
      }
    })
    .setCapabilities({
      interfaces: [{
        protocol: 'https',
        url: 'https://api.example.com/test'
      }]
    })

  console.log(`📊 Configuration:`)
  console.log(`   Iterations: ${ITERATIONS}`)
  console.log(`   Warmup: ${WARMUP_ITERATIONS}`)
  console.log()

  // Benchmark 1: Manifest signing
  console.log('1️⃣  Manifest Signing')
  console.log('-'.repeat(60))

  const signResults = await benchmark(
    'Manifest Sign',
    async () => {
      await builder.build()
    },
    ITERATIONS
  )

  console.log(`   Average:  ${signResults.avg.toFixed(3)} ms`)
  console.log(`   Median:   ${signResults.p50.toFixed(3)} ms`)
  console.log(`   P95:      ${signResults.p95.toFixed(3)} ms`)
  console.log(`   P99:      ${signResults.p99.toFixed(3)} ms`)
  console.log(`   Min:      ${signResults.min.toFixed(3)} ms`)
  console.log(`   Max:      ${signResults.max.toFixed(3)} ms`)

  const signTarget = 5 // Half of 10ms target for round-trip
  const signPass = signResults.avg < signTarget
  console.log(`   Target:   < ${signTarget} ms ${signPass ? '✅ PASS' : '❌ FAIL'}`)
  console.log()

  // Benchmark 2: Manifest verification
  console.log('2️⃣  Manifest Verification')
  console.log('-'.repeat(60))

  const manifest = await builder.build()

  const verifyResults = await benchmark(
    'Manifest Verify',
    async () => {
      await verifyManifest(manifest)
    },
    ITERATIONS
  )

  console.log(`   Average:  ${verifyResults.avg.toFixed(3)} ms`)
  console.log(`   Median:   ${verifyResults.p50.toFixed(3)} ms`)
  console.log(`   P95:      ${verifyResults.p95.toFixed(3)} ms`)
  console.log(`   P99:      ${verifyResults.p99.toFixed(3)} ms`)
  console.log(`   Min:      ${verifyResults.min.toFixed(3)} ms`)
  console.log(`   Max:      ${verifyResults.max.toFixed(3)} ms`)

  const verifyTarget = 5 // Half of 10ms target for round-trip
  const verifyPass = verifyResults.avg < verifyTarget
  console.log(`   Target:   < ${verifyTarget} ms ${verifyPass ? '✅ PASS' : '❌ FAIL'}`)
  console.log()

  // Benchmark 3: Round-trip (sign + verify)
  console.log('3️⃣  Round-Trip (Sign + Verify)')
  console.log('-'.repeat(60))

  const roundTripResults = await benchmark(
    'Round-Trip',
    async () => {
      const m = await builder.build()
      await verifyManifest(m)
    },
    ITERATIONS
  )

  console.log(`   Average:  ${roundTripResults.avg.toFixed(3)} ms`)
  console.log(`   Median:   ${roundTripResults.p50.toFixed(3)} ms`)
  console.log(`   P95:      ${roundTripResults.p95.toFixed(3)} ms`)
  console.log(`   P99:      ${roundTripResults.p99.toFixed(3)} ms`)
  console.log(`   Min:      ${roundTripResults.min.toFixed(3)} ms`)
  console.log(`   Max:      ${roundTripResults.max.toFixed(3)} ms`)

  const roundTripTarget = 10 // SPEC requirement
  const roundTripPass = roundTripResults.avg < roundTripTarget
  console.log(`   Target:   < ${roundTripTarget} ms ${roundTripPass ? '✅ PASS' : '❌ FAIL'}`)
  console.log()

  // Summary
  console.log('=' .repeat(60))
  console.log('📈 Summary')
  console.log('=' .repeat(60))
  console.log()

  const allPass = signPass && verifyPass && roundTripPass

  if (allPass) {
    console.log('✅ All benchmarks PASSED')
    console.log()
    console.log('Performance meets SPEC §12 requirements:')
    console.log('  ✅ Manifest sign+verify < 10ms')
  } else {
    console.log('❌ Some benchmarks FAILED')
    console.log()
    if (!signPass) console.log('  ❌ Signing too slow')
    if (!verifyPass) console.log('  ❌ Verification too slow')
    if (!roundTripPass) console.log('  ❌ Round-trip too slow')
  }

  console.log()
  console.log('Platform:', process.platform, process.arch)
  console.log('Node.js:', process.version)
  console.log()
}

main().catch(error => {
  console.error('Benchmark failed:', error)
  process.exit(1)
})
