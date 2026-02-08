# Express Server Example

This example demonstrates how to set up an Express server with AI agent authentication using the `@ai-agent-auth/server` middleware.

## Features

- ✅ Complete authentication endpoints (`/auth/challenge`, `/auth/verify`, `/auth/register`)
- ✅ JWT token issuance and validation
- ✅ Protected routes with authentication guard
- ✅ In-memory ACL (Access Control List)
- ✅ Automatic agent approval (configurable)
- ✅ Admin endpoints for ACL management
- ✅ Graceful shutdown handling

## Prerequisites

- Node.js 18+
- pnpm (or npm/yarn)

## Installation

From the repository root:

```bash
pnpm install
```

## Usage

### Start the server

```bash
cd examples/express-server
pnpm start
```

The server will start on `http://localhost:3000` (or the port specified in `PORT` environment variable).

### Environment Variables

```bash
PORT=3000                    # Server port (default: 3000)
JWT_SECRET=your-secret-key   # JWT signing secret (default: demo-secret-change-in-production)
```

**⚠️ Important:** Change `JWT_SECRET` in production!

## API Endpoints

### Public Endpoints

#### `GET /`
Server information and available endpoints.

```bash
curl http://localhost:3000
```

#### `GET /health`
Health check endpoint.

```bash
curl http://localhost:3000/health
```

### Authentication Endpoints

#### `POST /auth/challenge`
Request an authentication challenge.

```bash
curl -X POST http://localhost:3000/auth/challenge \
  -H "Content-Type: application/json" \
  -d '{"did": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"}'
```

Response:
```json
{
  "challenge": "c5a3f8b2...",
  "expires_at": "2026-02-08T03:10:00.000Z"
}
```

#### `POST /auth/verify`
Submit challenge response and receive JWT token.

```bash
curl -X POST http://localhost:3000/auth/verify \
  -H "Content-Type: application/json" \
  -d '{
    "did": "did:key:z6Mkh...",
    "challenge": "c5a3f8b2...",
    "signature": "zAbCd123...",
    "manifest": { ... }
  }'
```

Response:
```json
{
  "token": "eyJhbGciOiJFZERTQSI...",
  "expires_at": "2026-02-08T04:00:00.000Z"
}
```

#### `POST /auth/register`
Request agent registration (when auto-approve is disabled).

```bash
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "manifest": { ... },
    "reason": "I want to access the API"
  }'
```

### Protected Endpoints

These endpoints require a valid JWT token in the `Authorization` header.

#### `GET /api/protected`
Example protected route.

```bash
curl http://localhost:3000/api/protected \
  -H "Authorization: Bearer eyJhbGciOiJFZERTQSI..."
```

#### `GET /api/info`
Get information about the authenticated agent.

```bash
curl http://localhost:3000/api/info \
  -H "Authorization: Bearer eyJhbGciOiJFZERTQSI..."
```

#### `POST /api/echo`
Echo back the request body.

```bash
curl -X POST http://localhost:3000/api/echo \
  -H "Authorization: Bearer eyJhbGciOiJFZERTQSI..." \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello, world!"}'
```

### Admin Endpoints

⚠️ **In production, these should be protected with admin authentication!**

#### `GET /admin/acl`
List all agents in the ACL.

```bash
curl http://localhost:3000/admin/acl
```

#### `POST /admin/acl/:did/approve`
Approve an agent.

```bash
curl -X POST "http://localhost:3000/admin/acl/did%3Akey%3Az6Mkh.../approve"
```

#### `POST /admin/acl/:did/ban`
Ban an agent.

```bash
curl -X POST "http://localhost:3000/admin/acl/did%3Akey%3Az6Mkh.../ban"
```

## Configuration

### Auto-Approve Mode

By default, the server auto-approves new agents for demonstration purposes:

```javascript
const authHandler = new AgentAuthHandler({
  // ...
  autoApproveNewAgents: true  // Set to false in production
})
```

**In production:**
1. Set `autoApproveNewAgents: false`
2. Agents must use `POST /auth/register` to request access
3. Admins manually approve via `POST /admin/acl/:did/approve`

### JWT Configuration

```javascript
const authHandler = new AgentAuthHandler({
  jwtSecret: process.env.JWT_SECRET,
  jwtExpiresIn: '1h',  // Token validity period
  // ...
})
```

### Storage

The example uses in-memory storage (data is lost on restart):

```javascript
const acl = new InMemoryACL()
const challengeStore = new InMemoryChallengeStore()
const manifestCache = new InMemoryManifestCache()
```

**For production:** Implement persistent storage by creating custom classes that implement:
- `ACLStore` interface
- `ChallengeStore` interface
- `ManifestCacheStore` interface

## Testing with the Basic Agent

1. Start the server:
```bash
cd examples/express-server
pnpm start
```

2. In another terminal, run the basic agent:
```bash
cd examples/basic-agent
pnpm start
```

You should see successful authentication output from both the agent and server.

## Security Considerations

### For Production

1. **Change JWT Secret:**
   ```bash
   JWT_SECRET=$(openssl rand -hex 32) node index.js
   ```

2. **Disable Auto-Approve:**
   ```javascript
   autoApproveNewAgents: false
   ```

3. **Protect Admin Endpoints:**
   Add authentication/authorization middleware to `/admin/*` routes

4. **Use HTTPS:**
   Run behind a reverse proxy (nginx, Caddy) with TLS

5. **Rate Limiting:**
   Add rate limiting middleware to prevent abuse

6. **Persistent Storage:**
   Replace in-memory stores with database-backed implementations

7. **Monitoring:**
   Add logging, metrics, and error tracking

## Troubleshooting

### "Port already in use"

Change the port:
```bash
PORT=3001 pnpm start
```

### "JWT secret warning"

Set a proper JWT secret:
```bash
JWT_SECRET=your-secret-key pnpm start
```

### Agent authentication fails

Check:
1. Server is running
2. Agent DID is in ACL with `approved` status
3. JWT secret matches between challenge and verify requests

## Next Steps

- Integrate with your existing Express application
- Implement persistent storage
- Add rate limiting
- Set up monitoring and logging
- Deploy behind HTTPS reverse proxy

## Related Examples

- **Basic Agent** (`../basic-agent/`) - Client-side authentication
- Custom storage implementations (coming soon)
- Production deployment guide (coming soon)
