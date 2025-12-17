# Credence Registry API Specification

**Version:** 1.0.0  
**Base URL:** `https://api.credence.security/v1`

This document defines the REST API for the Credence Public Registry. Current prototype uses static JSON; this spec defines the production backend API.

## Authentication

All API requests require authentication via Bearer token:

```
Authorization: Bearer <your-api-key>
```

**Rate Limits:**
- Public endpoints: 100 requests/hour
- Authenticated: 1000 requests/hour
- Enterprise: Unlimited

## Endpoints

### Registry Queries

#### List Verified Servers

```http
GET /registry/servers
```

**Query Parameters:**
- `status` (string): Filter by status (`verified`, `flagged`, `rejected`)
- `min_trust_score` (float): Minimum trust score (0.0-1.0)
- `organization` (string): Filter by org name
- `limit` (int): Results per page (default: 20, max: 100)
- `offset` (int): Pagination offset

**Response:**
```json
{
  "total": 127,
  "servers": [
    {
      "server_id": "org/server-name",
      "version": "1.0.0",
      "verification_status": "verified",
      "trust_score": 0.95,
      "last_analyzed": "2025-12-16T23:00:00Z",
      "badge_url": "https://registry.credence.security/badge/org/server.svg"
    }
  ],
  "pagination": {
    "next": "/registry/servers?offset=20",
    "prev": null
  }
}
```

#### Get Server Details

```http
GET /registry/servers/{server_id}
```

**Path Parameters:**
- `server_id` (string): Full server identifier (e.g., `org/server-name`)

**Response:**
```json
{
  "server_id": "org/server-name",
  "version": "1.0.0",
  "verification_status": "verified",
  "trust_score": 0.95,
  "last_analyzed": "2025-12-16T23:00:00Z",
  "analysis_id": "abc123",
  
  "metadata": {
    "repository_url": "https://github.com/org/repo",
    "description": "Server description",
    "maintainer": "maintainer-name",
    "stars": 234,
    "last_commit": "2025-12-15T10:30:00Z"
  },
  
  "security_analysis": {
    "static_analysis": { /* ... */ },
    "dependency_analysis": { /* ... */ },
    "thinktank_consensus": { /* ... */ }
  },
  
  "cryptographic_attestation": {
    "signature": "MEUCIQDXvK8r...",
    "sigstore_entry": "24296fb2...",
    "signed_at": "2025-12-16T23:15:42Z"
  }
}
```

#### Search Servers

```http
GET /registry/search
```

**Query Parameters:**
- `q` (string): Search query
- `fields` (string): Comma-separated fields to search (`name`, `description`, `maintainer`)

**Response:**
```json
{
  "query": "github api",
  "results": [ /* server objects */ ],
  "total_results": 12
}
```

### Verification

#### Verify Server Signature

```http
POST /verify/signature
```

**Request Body:**
```json
{
  "server_id": "org/server-name",
  "version": "1.0.0",
  "signature": "MEUCIQDXvK8r...",
  "rekor_uuid": "24296fb2..."
}
```

**Response:**
```json
{
  "valid": true,
  "verified_at": "2025-12-16T23:30:00Z",
  "certificate_chain": [ /* ... */ ],
  "rekor_entry": {
    "uuid": "24296fb2...",
    "log_index": 142857693,
    "integrated_time": "2025-12-16T23:15:42Z"
  }
}
```

#### Get Trust Score

```http
GET /verify/trust/{server_id}
```

**Response:**
```json
{
  "server_id": "org/server-name",
  "trust_score": 0.95,
  "calculated_at": "2025-12-16T23:00:00Z",
  "components": {
    "static_analysis": 0.30,
    "dependency_health": 0.20,
    "thinktank_consensus": 0.30,
    "maintainer_reputation": 0.10,
    "community_adoption": 0.05
  }
}
```

### Submission

#### Submit Server for Analysis

```http
POST /submit
```

**Request Body:**
```json
{
  "repository_url": "https://github.com/org/repo",
  "version": "1.0.0",
  "maintainer_email": "dev@example.com",
  "callback_url": "https://example.com/webhook"
}
```

**Response:**
```json
{
  "submission_id": "sub_abc123",
  "status": "queued",
  "estimated_completion": "2025-12-17T23:00:00Z",
  "status_url": "/submissions/sub_abc123/status"
}
```

#### Check Submission Status

```http
GET /submissions/{submission_id}/status
```

**Response:**
```json
{
  "submission_id": "sub_abc123",
  "status": "analyzing" | "completed" | "failed",
  "progress": 65,
  "current_stage": "thinktank_analysis",
  "started_at": "2025-12-16T23:00:00Z",
  "completed_at": null,
  "result_url": null
}
```

### Analysis Reports

#### Get Analysis Report

```http
GET /reports/{analysis_id}
```

**Response:**
```json
{
  "analysis_id": "abc123",
  "server_id": "org/server-name",
  "analyzed_at": "2025-12-16T23:00:00Z",
  
  "summary": {
    "verdict": "APPROVED",
    "trust_score": 0.95,
    "critical_issues": 0,
    "warnings": 2
  },
  
  "static_analysis": { /* detailed results */ },
  "dependency_analysis": { /* detailed results */ },
  "thinktank_consensus": { /* detailed results */ },
  
  "recommendations": [
    {
      "priority": "high",
      "category": "dependency",
      "description": "Update requests to 2.31.0",
      "remediation": "pip install requests==2.31.0"
    }
  ]
}
```

### Badges

#### Get Badge SVG

```http
GET /badge/{server_id}.svg
```

**Query Parameters:**
- `style` (string): Badge style (`flat`, `flat-square`, `for-the-badge`)

**Response:**
```
Content-Type: image/svg+xml

<svg xmlns="http://www.w3.org/2000/svg">...</svg>
```

### Webhooks

#### Register Webhook

```http
POST /webhooks
```

**Request Body:**
```json
{
  "url": "https://example.com/webhook",
  "events": ["analysis_completed", "trust_score_changed", "server_flagged"],
  "secret": "webhook-signing-secret"
}
```

**Response:**
```json
{
  "webhook_id": "wh_abc123",
  "url": "https://example.com/webhook",
  "events": ["analysis_completed", "trust_score_changed"],
  "created_at": "2025-12-16T23:00:00Z"
}
```

#### Webhook Payload

```json
{
  "event": "analysis_completed",
  "timestamp": "2025-12-16T23:30:00Z",
  "data": {
    "submission_id": "sub_abc123",
    "server_id": "org/server-name",
    "status": "verified",
    "trust_score": 0.95,
    "report_url": "/reports/abc123"
  },
  "signature": "sha256=..."
}
```

## Error Responses

All errors follow this format:

```json
{
  "error": {
    "code": "not_found",
    "message": "Server not found in registry",
    "details": {
      "server_id": "org/invalid-server"
    }
  }
}
```

**Error Codes:**
- `invalid_request` (400): Malformed request
- `unauthorized` (401): Invalid or missing auth token
- `forbidden` (403): Insufficient permissions
- `not_found` (404): Resource not found
- `rate_limited` (429): Too many requests
- `server_error` (500): Internal server error

## WebSocket API (Future)

For real-time updates on analysis progress:

```javascript
const ws = new WebSocket('wss://api.credence.security/v1/stream');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Analysis progress:', data.progress);
};
```

## SDK Examples

### Python

```python
from credence import CredenceClient

client = CredenceClient(api_key='your-key')

# List verified servers
servers = client.registry.list_servers(status='verified')

# Submit for analysis
submission = client.submit(
    repository_url='https://github.com/org/repo',
    callback_url='https://example.com/webhook'
)

# Check status
status = client.submissions.get_status(submission.id)
```

### JavaScript

```javascript
import { CredenceClient } from '@credence/sdk';

const client = new CredenceClient({ apiKey: 'your-key' });

// Get server details
const server = await client.registry.getServer('org/server-name');

// Verify signature
const verification = await client.verify.signature({
  serverId: 'org/server-name',
  signature: 'MEUCIQDXvK8r...'
});
```

## Rate Limiting Headers

All responses include rate limit information:

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 987
X-RateLimit-Reset: 1703116800
```

## Versioning

API version is specified in URL path: `/v1/`

Breaking changes will increment the version number. Previous versions supported for 12 months after deprecation.

## Support

- **Documentation:** https://docs.credence.security
- **Status:** https://status.credence.security
- **Support:** support@credence.security

---

**This API spec defines the production backend. Current prototype uses static JSON hosted on GitHub Pages.**
