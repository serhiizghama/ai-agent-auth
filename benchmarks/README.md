# Performance Benchmarks

Performance benchmarks for validating ai-agent-auth meets the non-functional requirements specified in SPEC §12.

## Requirements

From **SPEC.md §12 Non-Functional Requirements**:

| Requirement | Target |
|-------------|--------|
| Manifest sign+verify | < 10 ms |
| Challenge round-trip | (measured for reference) |

## Running Benchmarks

### Run all benchmarks

```bash
cd benchmarks
pnpm bench
```

### Run specific benchmarks

```bash
# Manifest signing & verification
pnpm bench:manifest

# Challenge-response flow
pnpm bench:challenge
```

## Benchmarks

### 1. Manifest Signing & Verification

**File:** `manifest-signing.js`

Measures:
- **Manifest signing** - Time to sign a manifest with Ed25519
- **Manifest verification** - Time to verify a signed manifest
- **Round-trip** - Total time for sign + verify

**Target:** < 10ms for round-trip (SPEC requirement)

### 2. Challenge-Response Flow

**File:** `challenge-flow.js`

Measures:
- **Challenge signing** - Time to sign a challenge string
- **Challenge verification** - Time to verify a challenge signature
- **Round-trip** - Total time for sign + verify

## Interpreting Results

Each benchmark reports:
- **Average** - Mean execution time
- **Median (P50)** - 50th percentile
- **P95** - 95th percentile
- **P99** - 99th percentile
- **Min/Max** - Fastest and slowest execution

### Example Output

```
🔬 Manifest Signing & Verification Benchmark
============================================================

1️⃣  Manifest Signing
------------------------------------------------------------
   Average:  3.245 ms
   Median:   3.120 ms
   P95:      4.850 ms
   P99:      5.420 ms
   Min:      2.890 ms
   Max:      6.120 ms
   Target:   < 5 ms ✅ PASS

2️⃣  Manifest Verification
------------------------------------------------------------
   Average:  2.780 ms
   Median:   2.650 ms
   P95:      3.920 ms
   P99:      4.330 ms
   Min:      2.420 ms
   Max:      5.010 ms
   Target:   < 5 ms ✅ PASS

3️⃣  Round-Trip (Sign + Verify)
------------------------------------------------------------
   Average:  6.025 ms
   Median:   5.770 ms
   P95:      8.770 ms
   P99:      9.750 ms
   Min:      5.310 ms
   Max:      11.130 ms
   Target:   < 10 ms ✅ PASS

============================================================
📈 Summary
============================================================

✅ All benchmarks PASSED

Performance meets SPEC §12 requirements:
  ✅ Manifest sign+verify < 10ms
```

## Performance Factors

Performance can vary based on:
- **CPU** - Ed25519 signing/verification is CPU-bound
- **Node.js version** - Newer versions may have optimizations
- **System load** - Background processes can affect timing
- **JIT warmup** - First few iterations may be slower (handled by warmup phase)

## Optimization Notes

The implementation uses:
- **@noble/ed25519** - Fast, pure-JS Ed25519 implementation
- **JCS (canonicalize)** - Deterministic JSON serialization
- **SHA-256** - Native crypto hash function
- **No native addons** - Pure JS for cross-platform compatibility

## Continuous Integration

Run benchmarks in CI to detect performance regressions:

```bash
# In CI pipeline
pnpm --filter benchmarks bench
```

Consider failing CI if:
- Round-trip exceeds 10ms consistently
- Performance degrades >20% from baseline

## Platform-Specific Results

Performance will vary by platform. Document baseline results for reference:

- **macOS ARM64 (M1)** - ~6ms round-trip
- **Linux x64** - ~8ms round-trip
- **Windows x64** - ~9ms round-trip

*(Update with actual measured results)*
