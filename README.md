# Credence Public Registry Prototype

**MCPS: Secure MCP Servers - Like HTTPS for MCP**

A public registry for cryptographically verified Model Context Protocol (MCP) servers, powered by ThinkTank multi-agent security analysis.

## 🚀 Quick Start

### Deploying to GitHub Pages

1. **Fork/Clone this repository**
```bash
git clone <your-repo-url>
cd credence-registry
```

2. **Enable GitHub Pages**
   - Go to repository Settings → Pages
   - Source: Deploy from branch `main`
   - Folder: `/` (root)
   - Save

3. **Access your registry**
   - URL: `https://<username>.github.io/<repo-name>/`
   - Wait 1-2 minutes for initial deployment

### Local Development

```bash
# Serve locally
python3 -m http.server 8000

# Open browser
open http://localhost:8000
```

## 📁 Repository Structure

```
credence-registry/
├── index.html              # Main registry interface
├── submit.html             # Submission guide
├── report-example.html     # Example analysis report
├── registry.json           # Registry data (update this)
├── SCHEMA.md              # Data schema documentation
├── generate_badges.py     # Badge SVG generator
├── badge-*.svg            # Example badges
└── README.md              # This file
```

## 🔄 Adding Verified Servers

### 1. Analyze a Server with ThinkTank

Run your ThinkTank analysis pipeline:

```bash
# Example: Analyze an MCP server
thinktank analyze \
  --repo https://github.com/modelcontextprotocol/server-github \
  --config security-analysis.yaml \
  --output analysis-results.json
```

### 2. Add to Registry

Edit `registry.json`:

```json
{
  "registry_version": "1.0.0",
  "last_updated": "2024-12-16T23:00:00Z",
  "total_servers": 1,
  "verified_servers": 1,
  "servers": [
    {
      "server_id": "modelcontextprotocol/server-github",
      "version": "0.1.0",
      "verification_status": "verified",
      "trust_score": 0.95,
      "last_analyzed": "2024-12-16T23:00:00Z",
      "analysis_id": "abc123",
      
      "metadata": {
        "repository_url": "https://github.com/modelcontextprotocol/server-github",
        "description": "MCP server for GitHub API access",
        "maintainer": "Anthropic",
        "stars": 234,
        "last_commit": "2024-12-15T10:30:00Z"
      },
      
      "security_analysis": {
        "static_analysis": {
          "passed": true,
          "issues_found": 0,
          "tools_used": ["semgrep", "bandit"]
        },
        "dependency_analysis": {
          "passed": true,
          "vulnerabilities_found": 0,
          "sbom_generated": true
        },
        "thinktank_consensus": {
          "verdict": "APPROVED",
          "confidence": 0.95,
          "believer_votes": 7,
          "skeptic_votes": 7,
          "neutral_votes": 5,
          "foreperson_synthesis": "Server demonstrates strong security practices..."
        }
      },
      
      "cryptographic_attestation": {
        "signature": "MEUCIQDXvK8r...",
        "sigstore_entry": "24296fb2...",
        "signed_at": "2024-12-16T23:15:42Z",
        "certificate_chain": "base64..."
      },
      
      "badge_url": "badge-verified.svg",
      "report_url": "reports/abc123.html"
    }
  ]
}
```

### 3. Generate Badge

```bash
python3 generate_badges.py \
  --status verified \
  --score 0.95 \
  --output badges/modelcontextprotocol-server-github.svg
```

### 4. Create Analysis Report

Copy `report-example.html` and customize with your analysis results:

```bash
cp report-example.html reports/abc123.html
# Edit reports/abc123.html with your analysis data
```

### 5. Commit and Push

```bash
git add registry.json badges/ reports/
git commit -m "Add verified server: modelcontextprotocol/server-github"
git push origin main
```

GitHub Pages will automatically redeploy in 1-2 minutes.

## 🎯 First 10 Servers to Analyze

Priority targets from Smithery registry:

1. **@modelcontextprotocol/server-github** - Official GitHub integration
2. **@modelcontextprotocol/server-filesystem** - Local file access
3. **@modelcontextprotocol/server-postgres** - Database server
4. **@modelcontextprotocol/server-slack** - Slack integration
5. **@modelcontextprotocol/server-puppeteer** - Browser automation
6. **@modelcontextprotocol/server-memory** - Knowledge graph server
7. **@modelcontextprotocol/server-everything** - Multi-tool server
8. **@modelcontextprotocol/server-brave-search** - Search integration
9. **@modelcontextprotocol/server-fetch** - HTTP request server
10. **@modelcontextprotocol/server-sqlite** - SQLite database

## 📧 Collecting Badge Adoptions

### Track Badge Usage

Create GitHub issues for each server:

**Template:**
```markdown
## Badge Request: [SERVER_NAME]

Hi @maintainer,

We've analyzed your MCP server through our Credence security registry and it passed with a trust score of 95%!

**Full Report:** https://registry.credence.security/reports/[ID].html

Would you consider adding our verification badge to your README?

```markdown
[![Credence Verified](https://registry.credence.security/badge/[SERVER].svg)](https://registry.credence.security/servers/[SERVER])
```

This helps users quickly identify secure, verified MCP servers.

Thanks!
```

### Success Metrics

Track in a spreadsheet:
- Server contacted: Date
- Response received: Date
- Badge added: Date
- Stars/popularity: Number

**Goal:** 3+ servers displaying badge by end of January

## 🔐 Cryptographic Attestation (Optional)

For production deployment, integrate Sigstore:

```bash
# Sign analysis result
cosign sign-blob \
  --key cosign.key \
  analysis-results.json \
  > analysis-results.sig

# Upload to Rekor
rekor-cli upload \
  --artifact analysis-results.json \
  --signature analysis-results.sig \
  --public-key cosign.pub
```

Store Rekor UUID in registry entry.

## 📊 Analytics (Optional)

Add Google Analytics or Plausible:

```html
<!-- Add to index.html <head> -->
<script defer data-domain="yourdomain.com" src="https://plausible.io/js/script.js"></script>
```

Track:
- Page views on registry
- Report views
- Badge copy events
- Search queries

## 🚦 Status Updates

### Week 1 (Dec 16-22)
- [x] Registry interface built
- [ ] First 5 servers analyzed
- [ ] Badge generation automated
- [ ] Contact server maintainers

### Week 2 (Dec 23-29)
- [ ] 10 servers in registry
- [ ] 2 badges adopted
- [ ] Contact Anthropic/Smithery

### Week 3 (Dec 30-Jan 5)
- [ ] Approach acquirers with adoption proof
- [ ] 3+ servers displaying badge
- [ ] Public announcement

## 🎨 Customization

### Branding

Edit these in `index.html`:
- Colors: `.header { background: gradient... }`
- Logo: Add to `.header h1`
- Tagline: Update "MCPS: Secure MCP Servers"

### Badge Styles

Edit `generate_badges.py`:
- Colors in `colors` dict
- SVG dimensions
- Font sizes

### Report Template

Customize `report-example.html`:
- Layout
- Sections
- Styling

## 📝 Next Steps

1. **This Week:**
   - Deploy to GitHub Pages: `https://[username].github.io/credence-registry/`
   - Analyze first 3 servers
   - Contact maintainers

2. **Next Week:**
   - Reach 10 analyzed servers
   - Get first badge adoption
   - Refine based on feedback

3. **Week 3:**
   - Prepare acquisition pitch
   - Document adoption metrics
   - Schedule conversations

## 🤝 Contributing

This is a prototype for demonstrating MCPS concept. For production:
- API-based submission
- Automated analysis pipeline
- Database backend
- Real-time updates

## 📞 Contact

- **Registry:** [Your GitHub Pages URL]
- **Email:** verify@credence.security (configure this)
- **GitHub:** [Your GitHub org]

---

**Built with ThinkTank Multi-Agent Analysis**  
*Making MCP servers cryptographically trustworthy*
