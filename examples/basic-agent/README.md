# Basic Agent Example

This example demonstrates how an AI agent authenticates with a server using the `@ai-agent-auth/client` SDK.

## Overview

The example shows the complete authentication flow:

1. **Generate Identity** - Create a new Ed25519 key pair and DID
2. **Build Manifest** - Create an agent manifest with metadata and capabilities
3. **Authenticate** - Complete the challenge-response flow and receive a JWT token
4. **Use Session** - Use the JWT token to make authenticated requests

## Prerequisites

- Node.js 18+
- A running authentication server (see `../express-server/` example)

## Installation

From the repository root:

```bash
pnpm install
```

## Usage

### Start the server first

In a separate terminal:

```bash
cd examples/express-server
pnpm start
```

### Run the basic agent

```bash
cd examples/basic-agent
pnpm start
```

Or specify a custom server URL:

```bash
pnpm start http://localhost:3000
```

## Expected Output

```
🤖 AI Agent Authentication Example
==================================================

📝 Step 1: Generating agent identity...
   ✅ DID: did:key:z6Mkh...
   ✅ Public Key: 8f3c2d1e...

📋 Step 2: Building agent manifest...
   ✅ Manifest created with sequence: 1
   ✅ Valid until: 2026-02-08T03:00:00.000Z

🔐 Step 3: Authenticating with server...
   Server: http://localhost:3000
   ✅ Authentication successful!
   ✅ Token: eyJhbGciOiJFZERTQSI...
   ✅ Expires: 2026-02-08T04:00:00.000Z
   ✅ DID: did:key:z6Mkh...

🎯 Step 4: Session ready for use
   Authorization header: Bearer eyJhbGciOiJFZERTQSI...
   ✅ Token is valid for more than 1 hour

✨ Example completed successfully!
```

## What's Happening

### 1. Identity Generation

```javascript
const identity = AgentIdentity.generate()
```

Creates a new Ed25519 key pair and derives a `did:key` identifier from the public key.

### 2. Manifest Creation

```javascript
const manifest = await new ManifestBuilder(identity)
  .name('Example Basic Agent')
  .description('A simple demonstration agent')
  .version('1.0.0')
  .operator({ name: 'Example Operator', ... })
  .addCapability('text-generation', { models: ['gpt-4'] })
  .build()
```

Creates a signed manifest containing:
- Agent metadata (name, description, version)
- Operator information
- Capabilities the agent provides
- Cryptographic signature

### 3. Authentication

```javascript
const client = new AuthClient({ baseUrl, identity, manifest })
const session = await client.authenticate()
```

Executes the challenge-response protocol:
1. Requests a challenge from the server
2. Signs the challenge with the agent's private key
3. Submits the signature and manifest
4. Receives a JWT token

### 4. Session Usage

```javascript
session.toAuthorizationHeader() // "Bearer eyJ..."
session.isExpired              // false
session.willExpireIn(3600)     // Check if expires in < 1 hour
```

## Troubleshooting

### "Authentication failed"

Make sure:
1. The server is running on the specified URL
2. The agent's DID is in the server's ACL (auto-approved or manually approved)
3. The server is accessible from your network

### "Connection refused"

The server is not running. Start the Express server example first:

```bash
cd ../express-server && pnpm start
```

## Next Steps

- See `../express-server/` for the server-side implementation
- Check `packages/client/` for the full client SDK documentation
- Read the [Protocol Specification](../../docs/AAA-SPEC.md) for details

## Related Examples

- **Express Server** (`../express-server/`) - Server-side authentication
- Integration with real AI agents (coming soon)
