# ai-agent-auth

**OAuth for Robots** — A lightweight, cryptographic authentication protocol for AI agents.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-≥20-green)](https://nodejs.org/)

---

## What is ai-agent-auth?

**ai-agent-auth** is an open protocol and library for **authenticating autonomous AI agents** on protected resources — private APIs, gated communities, corporate networks, or any server that needs to know *who is knocking and whether to let them in.*

Think of it as **OAuth 2.0, but designed for non-human actors**: instead of a user logging in through a browser, an agent proves its identity by signing a cryptographic challenge with its private key.

### Key Features

- **🔐 Cryptographic Identity** — No API keys. Agents authenticate using [DIDs](https://www.w3.org/TR/did-core/) (`did:key` or `did:web`) and Ed25519 signatures
- **📜 Agent Manifests** — Self-contained "passports" describing what an agent can do and how to communicate with it
- **⚡ Zero External Dependencies** — No blockchain, no tokens, no identity providers. Just public-key cryptography
- **🚀 Lightweight** — Pure JavaScript implementation, < 50KB minified, works in Node.js, Cloudflare Workers, Deno, Bun
- **🔒 Security First** — Rate limiting, revocation checking, replay protection, sequence number verification, DoS protection
- **⏱️ Fast** — Manifest sign+verify in ~1.2ms (8x faster than spec target)

---

## The Problem

Today, when an AI agent needs to access a protected resource:

- **API keys are shared secrets** that can leak and provide no identity
- **There is no standard "agent passport"** — every service invents its own bot auth scheme
- **No machine-readable capabilities** — integrations require manual work
- **Identity is trivially forgeable** — attackers can clone descriptions and impersonate agents

---

## How It Works

```
Agent                                          Server
  │                                              │
  │  1. Request challenge                        │
  │─────────────────────────────────────────────>│
  │  ← { challenge: "random-256-bit-hex" }       │
  │                                              │
  │  2. Sign challenge with private key          │
  │                                              │
  │  3. Submit signature + manifest              │
  │─────────────────────────────────────────────>│
  │                                              │
  │  4. Server verifies:                         │
  │     - Manifest signature (Ed25519)           │
  │     - Challenge signature (Ed25519)          │
  │     - DID is in ACL                          │
  │     - Manifest not expired/revoked           │
  │                                              │
  │  ← { token: "JWT", expires_at: "..." }       │
  │                                              │
  │  5. Use JWT for all subsequent requests      │
  │                                              │
```

---

## Quick Start

### Installation

```bash
# For agents (client-side)
npm install @ai-agent-auth/client

# For servers (API providers)
npm install @ai-agent-auth/server
```

### Agent Example (Client)

```typescript
import { AgentIdentity, ManifestBuilder, AuthClient } from '@ai-agent-auth/client';

// 1. Generate or load identity
const identity = AgentIdentity.generate();

// 2. Build and sign manifest
const manifest = await new ManifestBuilder(identity)
  .setSequence(1)
  .setValidUntil(new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)) // 30 days
  .setMetadata({
    name: 'ResearchBot-7',
    description: 'Autonomous research agent',
    agent_version: '1.0.0',
  })
  .setCapabilities({
    interfaces: [{
      protocol: 'https',
      url: 'https://myagent.example.com/api',
      api_standard: 'custom',
    }],
  })
  .build();

// 3. Authenticate with server
const client = new AuthClient({
  serverUrl: 'https://api.example.com',
  identity,
  manifest,
});

const session = await client.authenticate();

// 4. Use JWT token
console.log(`Authenticated! Token: ${session.token}`);
console.log(`Expires: ${session.expiresAt}`);

// Make authenticated requests
fetch('https://api.example.com/api/protected', {
  headers: {
    Authorization: session.toAuthorizationHeader(),
  },
});
```

### Server Example (Express)

```typescript
import express from 'express';
import { agentAuthMiddleware } from '@ai-agent-auth/server';

const app = express();
app.use(express.json());

// Set up authentication endpoints
const { router, guard } = agentAuthMiddleware({
  issuer: 'https://api.example.com',
  jwtSecret: process.env.JWT_SECRET || 'your-secret-key-change-in-production',
  enableRegistration: true, // Allow agents to self-register
});

// Mount auth endpoints: /auth/challenge, /auth/verify, /auth/register
app.use('/auth', router);

// Protected route
app.get('/api/protected', guard, (req, res) => {
  // req.agent contains authenticated agent info
  res.json({
    message: `Hello, ${req.agent.name}!`,
    did: req.agent.did,
    capabilities: req.agent.capabilities,
  });
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));
```

---

## Architecture

### Monorepo Structure

```
ai-agent-auth/
├── packages/
│   ├── core/        # Internal shared cryptographic primitives and types
│   ├── client/      # @ai-agent-auth/client - Agent-side SDK
│   └── server/      # @ai-agent-auth/server - Server middleware
├── examples/
│   ├── basic-agent/    # Minimal agent example
│   └── express-server/ # Express server with auth
├── schemas/
│   ├── manifest.schema.json  # JSON Schema for manifest validation
│   └── openapi.yaml          # OpenAPI 3.0 specification
└── docs/
    ├── AAA-PRD.md     # Product Requirements Document
    └── AAA-SPEC.md    # Technical Specification
```

### Key Components

| Package | Purpose | Size |
|---------|---------|------|
| `@ai-agent-auth/client` | Agent-side: key management, manifest signing, authentication flow | < 50 KB |
| `@ai-agent-auth/server` | Server-side: challenge issuance, verification, JWT issuance, ACL | < 100 KB |
| `core` (internal) | Shared crypto primitives, types, schemas | < 1,000 LoC |

### Technology Stack

- **Runtime:** Node.js ≥ 20, Bun, Deno, Cloudflare Workers
- **Language:** TypeScript 5.x (strict mode)
- **Crypto:** `@noble/ed25519` (pure JS, audited)
- **Validation:** Zod v3
- **JWT:** `jose` v5
- **Build:** `tsup` (dual CJS/ESM)
- **Tests:** Vitest

**Zero native dependencies** — all cryptography is pure JavaScript for maximum portability.

---

## Development

### Prerequisites

- Node.js ≥ 20 LTS
- pnpm ≥ 8.15

### Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/ai-agent-auth.git
cd ai-agent-auth

# Install dependencies
pnpm install

# Build all packages
pnpm build

# Run tests
pnpm test

# Run tests in watch mode
pnpm test:watch

# Generate test coverage
pnpm test:coverage

# Lint and format
pnpm lint
pnpm lint:fix
```

### Running Examples

#### Basic Agent

```bash
cd examples/basic-agent
pnpm install
pnpm start
```

This demonstrates the full client-side authentication flow.

#### Express Server

```bash
cd examples/express-server
pnpm install
pnpm start
```

Server runs on `http://localhost:3000` with:
- Auth endpoints: `/auth/challenge`, `/auth/verify`, `/auth/register`
- Protected routes: `/api/protected`, `/api/info`
- Admin panel: `/admin/acl`

### Project Structure

```
packages/core/src/
├── types.ts        # TypeScript interfaces
├── schemas.ts      # Zod validation schemas
├── errors.ts       # Error codes and handling
├── crypto.ts       # Ed25519 key generation, signing, verification
├── base58.ts       # Base58btc encoding/decoding
├── jcs.ts          # JSON Canonicalization Scheme (RFC 8785)
├── did.ts          # DID parsing and resolution
└── manifest.ts     # Manifest signing and verification

packages/client/src/
├── agent-identity.ts    # Key management
├── manifest-builder.ts  # Fluent manifest construction
├── auth-client.ts       # Challenge-response flow
└── session.ts           # JWT token lifecycle

packages/server/src/
├── auth-handler.ts       # Core authentication logic
├── middleware.ts         # Express/framework adapters
├── acl.ts               # Access control list storage
├── challenge-store.ts   # Challenge storage with TTL
├── manifest-cache.ts    # Manifest caching
├── rate-limiter.ts      # Rate limiting
├── revocation.ts        # Revocation checking
└── jwt.ts               # JWT issuance and validation
```

---

## Performance

Benchmarks on macOS ARM64 (M1):

| Operation | Average | Target | Status |
|-----------|---------|--------|--------|
| Manifest Sign | 0.30 ms | < 10 ms | ✅ 33x faster |
| Manifest Verify | 1.01 ms | < 10 ms | ✅ 10x faster |
| Full Round-trip | 1.24 ms | < 10 ms | ✅ 8x faster |

Run benchmarks:

```bash
pnpm --filter @ai-agent-auth/core benchmark
```

---

## Security

### Threat Protection

| Attack | Mitigation |
|--------|------------|
| **Impersonation** | Ed25519 signature verification — attacker cannot sign without private key |
| **Manifest Tampering** | JCS canonicalization + Ed25519 signature — any modification invalidates proof |
| **Replay Attack** | Single-use challenges with expiry + used-challenge tracking |
| **Manifest Rollback** | Monotonic sequence numbers — servers reject older manifest versions |
| **DoS (Challenge Flooding)** | Rate limiting by IP/DID, configurable limits |
| **DoS (Slowloris)** | `did:web` resolution timeout (2s), size limit (100KB), max 3 redirects |
| **Token Theft** | Short-lived JWTs (1-12h), TLS required, optional revocation endpoint |

### Security Features

- ✅ **Rate limiting** — Configurable per-endpoint request limits
- ✅ **Revocation checking** — Optional HTTP endpoint for real-time manifest status
- ✅ **Replay protection** — Challenge-response with expiry and usage tracking
- ✅ **Sequence verification** — Prevents manifest rollback attacks
- ✅ **Clock skew tolerance** — 60s leeway in past direction only
- ✅ **No secret leakage** — Sanitized error messages with error codes

### Best Practices

1. **Store private keys securely** — Use HSM, TPM, or hardware tokens
2. **Use TLS 1.3** — All endpoints must use HTTPS
3. **Rotate keys regularly** — Recommended: every 90 days
4. **Monitor access** — Audit log all authentication attempts
5. **Enable revocation** — For production agents, host revocation endpoint
6. **Set short token lifetimes** — 1-12h for automated agents

---

## Documentation

- **[Product Requirements Document (PRD)](docs/AAA-PRD.md)** — Protocol design, security model, user flows
- **[Technical Specification](docs/AAA-SPEC.md)** — Byte-precise cryptographic procedures, API spec, error codes
- **[OpenAPI Specification](schemas/openapi.yaml)** — REST API documentation
- **[Manifest JSON Schema](schemas/manifest.schema.json)** — Manifest validation schema
- **[Example: Basic Agent](examples/basic-agent/README.md)** — Client-side authentication tutorial
- **[Example: Express Server](examples/express-server/README.md)** — Server-side integration guide

---

## Implementation Status

**Current Phase:** Phase 3 — Hardening & Tooling (92% complete) ✅

### Completed

- ✅ **Phase 1:** Core cryptography & types (158 tests passing)
- ✅ **Phase 2:** Client SDK & server logic (64 client tests + server implementation)
- ✅ **Phase 3 (11/12 tasks):**
  - did:web resolution with DoS protection
  - Manifest remote fetch
  - Rate limiting
  - Revocation checking
  - Build pipeline (dual CJS/ESM)
  - JSON Schema & OpenAPI specifications
  - Example applications
  - Performance benchmarks
  - Security hardening

### In Progress

- ⏳ Integration tests (end-to-end flow)
- ⏳ API documentation generation (TypeDoc)

See **[PROGRESS.md](PROGRESS.md)** for detailed status.

---

## Roadmap

### v1.0 (Current)

- ✅ Core authentication protocol
- ✅ `did:key` and `did:web` support
- ✅ TypeScript SDK (client + server)
- ✅ Express middleware
- ✅ Example applications

### v2.0 (Future)

- [ ] Python SDK
- [ ] Rust SDK
- [ ] Scoped capabilities negotiation
- [ ] Mutual authentication (agent-to-server)
- [ ] Agent-to-agent authentication
- [ ] Delegation chains
- [ ] Optional compute verification (TEE attestation)

---

## FAQ

### Why not use API keys?

API keys are shared secrets that provide no cryptographic identity. Anyone with the key can impersonate the agent. With ai-agent-auth, the agent proves ownership of a private key without ever transmitting it.

### Why not use OAuth 2.0?

OAuth 2.0 requires a centralized authorization server and is designed for human users with browsers. ai-agent-auth is optimized for autonomous agents with no browser, no user interaction, and no external IdP.

### Why DIDs instead of X.509 certificates?

X.509 requires a Certificate Authority, which introduces a trust dependency. DIDs are self-sovereign — `did:key` agents can generate an identity in milliseconds with zero external dependencies.

### Is this blockchain-based?

**No.** There is no blockchain, no tokens, no staking, no on-chain operations. It's pure cryptography (Ed25519 + SHA-256).

### What about key compromise?

If a private key is compromised:
1. **Immediate:** Set revocation endpoint to return `{"active": false}`
2. **Short-term:** Manifest expires (hard deadline via `valid_until`)
3. **Recovery:** Generate new key pair, create new DID (or update DID Document for `did:web`), re-register

### Can I use this in production?

The protocol is production-ready, but we recommend:
- Complete integration tests before deployment
- Independent security audit
- Run examples and validate your use case
- Monitor the repository for updates

---

## Contributing

Contributions are welcome! Please:

1. Read the **[Technical Specification](docs/AAA-SPEC.md)** to understand the protocol
2. Check **[PROGRESS.md](PROGRESS.md)** for current status and open tasks
3. Open an issue to discuss your proposal
4. Submit a pull request with tests

### Code Style

- TypeScript strict mode enabled
- ESLint + Prettier for formatting
- Test coverage: ≥ 95% for core, ≥ 85% for client/server
- Follow existing code patterns

---

## License

[MIT](LICENSE)

---

## Acknowledgments

- **W3C DID Core** — Decentralized Identifier specification
- **did:key Method** — Self-contained DID method
- **JCS (RFC 8785)** — JSON Canonicalization Scheme
- **@noble/ed25519** — Audited, pure-JS Ed25519 implementation
- Inspired by the need for better AI agent authentication in multi-agent systems

---

## Contact

- **Issues:** https://github.com/yourusername/ai-agent-auth/issues
- **Discussions:** https://github.com/yourusername/ai-agent-auth/discussions

---

**Built with ❤️ for the autonomous agent ecosystem**
