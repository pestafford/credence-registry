# Credence Registry Schema

## Server Entry Format

```json
{
  "server_id": "organization/server-name",
  "version": "1.0.0",
  "verification_status": "verified" | "flagged" | "rejected",
  "trust_score": 0.0-1.0,
  "last_analyzed": "ISO8601 timestamp",
  "analysis_id": "unique-analysis-id",
  
  "metadata": {
    "repository_url": "https://github.com/org/repo",
    "description": "Brief description",
    "maintainer": "maintainer-name",
    "stars": 123,
    "last_commit": "ISO8601 timestamp"
  },
  
  "security_analysis": {
    "static_analysis": {
      "passed": true,
      "issues_found": 0,
      "tools_used": ["semgrep", "bandit", "gitleaks"]
    },
    "dependency_analysis": {
      "passed": true,
      "vulnerabilities_found": 0,
      "sbom_generated": true
    },
    "thinktank_consensus": {
      "verdict": "APPROVED" | "FLAGGED" | "REJECTED",
      "confidence": 0.0-1.0,
      "believer_votes": 7,
      "skeptic_votes": 7,
      "neutral_votes": 5,
      "foreperson_synthesis": "Brief summary"
    }
  },
  
  "cryptographic_attestation": {
    "signature": "base64-encoded-signature",
    "sigstore_entry": "rekor-uuid",
    "signed_at": "ISO8601 timestamp",
    "certificate_chain": "base64-encoded-chain"
  },
  
  "badge_url": "https://registry.credence.security/badge/org/server-name.svg",
  "report_url": "https://registry.credence.security/reports/analysis-id.html"
}
```

## Verification Status Meanings

- **verified**: Passed all security checks, approved by ThinkTank swarm
- **flagged**: Passed basic checks but has concerns requiring review
- **rejected**: Failed security analysis, not approved for use

## Trust Score Calculation

Trust score (0.0-1.0) combines:
- Static analysis results (30%)
- Dependency health (20%)
- ThinkTank consensus confidence (30%)
- Maintainer reputation (10%)
- Community adoption (10%)

## Badge Embedding

Markdown:
```markdown
[![Credence Verified](https://registry.credence.security/badge/org/server.svg)](https://registry.credence.security/servers/org/server)
```

HTML:
```html
<a href="https://registry.credence.security/servers/org/server">
  <img src="https://registry.credence.security/badge/org/server.svg" alt="Credence Verified">
</a>
```
