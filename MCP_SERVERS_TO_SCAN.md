# MCP Servers to Scan - Initial 25 Targets

This document identifies the first 25 MCP (Model Context Protocol) servers selected for security scanning by the Credence Registry. The selection is organized into three tiers to ensure comprehensive coverage of the ecosystem.

## Tier 1: Top 8 Anthropic Official Servers

These are the reference implementations maintained by Anthropic in the official [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) repository.

### 1. Filesystem Server
- **Location**: `@modelcontextprotocol/server-filesystem`
- **Repository**: https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem
- **Justification**: Core server providing secure file operations with configurable access controls. Critical for understanding path traversal and access control vulnerabilities. High-risk surface area due to direct filesystem access.

### 2. GitHub Server
- **Location**: `@modelcontextprotocol/server-github`
- **Repository**: https://github.com/modelcontextprotocol/servers/tree/main/src/github
- **Justification**: Enables GitHub API integration for issue management, PRs, and repository operations. Important for understanding API token handling, permission models, and repository access controls.

### 3. PostgreSQL Server
- **Location**: `@modelcontextprotocol/server-postgres`
- **Repository**: https://github.com/modelcontextprotocol/servers/tree/main/src/postgres
- **Justification**: Provides read-only database access with schema inspection. Critical for SQL injection prevention, connection string handling, and data exposure risks.

### 4. Puppeteer Server
- **Location**: `@modelcontextprotocol/server-puppeteer`
- **Repository**: https://github.com/modelcontextprotocol/servers/tree/main/src/puppeteer
- **Justification**: Browser automation and web scraping capabilities. High-risk for SSRF, XSS, command injection, and unauthorized web access. Major attack surface.

### 5. Slack Server
- **Location**: `@modelcontextprotocol/server-slack`
- **Repository**: https://github.com/modelcontextprotocol/servers/tree/main/src/slack
- **Justification**: Channel management and messaging capabilities. Important for API token security, message injection, and unauthorized data access to corporate communications.

### 6. Google Drive Server
- **Location**: `@modelcontextprotocol/server-gdrive`
- **Repository**: https://github.com/modelcontextprotocol/servers/tree/main/src/gdrive
- **Justification**: Cloud storage integration with OAuth handling. Critical for understanding OAuth flow security, token management, and unauthorized file access.

### 7. GitLab Server
- **Location**: `@modelcontextprotocol/server-gitlab`
- **Repository**: https://github.com/modelcontextprotocol/servers/tree/main/src/gitlab
- **Justification**: Similar to GitHub but different API surface. Provides comparative analysis of git platform security patterns and API token handling.

### 8. Google Maps Server
- **Location**: `@modelcontextprotocol/server-google-maps`
- **Repository**: https://github.com/modelcontextprotocol/servers/tree/main/src/google-maps
- **Justification**: Geocoding and mapping services integration. Important for API key security, rate limiting, and data validation.

---

## Tier 2: Top 8 Downloaded by Smithery Metrics

These servers are the most actively used based on Smithery.ai usage statistics, indicating real-world deployment and impact.

### 9. Sequential Thinking
- **Location**: `@smithery-ai/server-sequential-thinking`
- **Repository**: https://smithery.ai/server/@smithery-ai/server-sequential-thinking
- **Usage**: 5,550+ uses
- **Justification**: Most popular MCP server on Smithery. Provides structured thinking/reasoning tools. Important to understand how reasoning chains could be manipulated or exploited.

### 10. wcgw (What Could Go Wrong)
- **Location**: `@kimtaeyoon83/mcp-server-wcgw`
- **Repository**: https://github.com/kimtaeyoon83/mcp-server-wcgw
- **Usage**: 4,920+ uses
- **Justification**: Second most popular server. Allows AI to execute bash commands and edit files. Extremely high-risk surface area - command injection, arbitrary file access, privilege escalation potential.

### 11. Brave Search
- **Location**: `@smithery-ai/brave-search`
- **Repository**: https://github.com/modelcontextprotocol/servers/tree/main/src/brave-search
- **Usage**: 680+ uses
- **Justification**: Web search integration. Important for API key security, search injection, and information disclosure risks.

### 12. Fetch Server
- **Location**: `@modelcontextprotocol/server-fetch`
- **Repository**: https://github.com/modelcontextprotocol/servers/tree/main/src/fetch
- **Justification**: Web content fetching and conversion. High-risk for SSRF attacks, content injection, and unauthorized network access to internal resources.

### 13. Memory Server
- **Location**: `@modelcontextprotocol/server-memory`
- **Repository**: https://github.com/modelcontextprotocol/servers/tree/main/src/memory
- **Justification**: Persistent memory/knowledge graph storage. Important for data persistence security, injection attacks, and unauthorized data access.

### 14. Everything Server
- **Location**: `@modelcontextprotocol/server-everything`
- **Repository**: https://github.com/modelcontextprotocol/servers/tree/main/src/everything
- **Justification**: Combines multiple capabilities. Useful for understanding attack surface expansion when multiple tools are combined.

### 15. Time Server
- **Location**: `@modelcontextprotocol/server-time`
- **Repository**: https://github.com/modelcontextprotocol/servers/tree/main/src/time
- **Justification**: Timezone and time conversion utilities. Lower risk but important for understanding basic server implementation patterns and input validation.

### 16. EXA Search
- **Location**: `@modelcontextprotocol/server-exa`
- **Repository**: https://github.com/modelcontextprotocol/servers/tree/main/src/exa
- **Justification**: Neural search API integration. Important for understanding API security, search manipulation, and data exposure risks.

---

## Tier 3: Top 9 Solo Creator Servers by Download/Stars

These are high-impact community servers from individual creators and organizations, ranked by GitHub stars and adoption metrics.

### 17. Microsoft Playwright MCP
- **Location**: `microsoft/playwright-mcp`
- **Repository**: https://github.com/microsoft/playwright-mcp
- **Stars**: 25,000+
- **Justification**: Official Microsoft implementation for browser automation through accessibility APIs. Enterprise-grade server with massive adoption. Critical for SSRF, browser exploitation, and web security testing.

### 18. AWS MCP Servers
- **Location**: `awslabs/mcp`
- **Repository**: https://github.com/awslabs/mcp
- **Stars**: 7,700+
- **Justification**: Official AWS integration suite. Extremely high-risk due to cloud infrastructure access. Critical for understanding credential management, IAM security, and cloud resource access controls.

### 19. Execute Automation Playwright
- **Location**: `executeautomation/mcp-playwright`
- **Repository**: https://github.com/executeautomation/mcp-playwright
- **Stars**: 5,100+
- **Justification**: Popular alternative Playwright implementation. Provides comparative analysis with Microsoft's version for identifying common browser automation vulnerabilities.

### 20. Cloudflare MCP Server
- **Location**: `cloudflare/mcp-server-cloudflare`
- **Repository**: https://github.com/cloudflare/mcp-server-cloudflare
- **Stars**: 3,200+
- **Justification**: Official Cloudflare integration for Workers, KV, R2, D1. Important for edge computing security, serverless function deployment, and storage access patterns.

### 21. Fetcher MCP (Playwright-based)
- **Location**: `jae-jae/fetcher-mcp`
- **Repository**: https://github.com/jae-jae/fetcher-mcp
- **Stars**: 940+
- **Justification**: Web scraping with JavaScript rendering. High-risk for SSRF, content injection, and browser-based attacks. Different implementation approach from official fetch server.

### 22. MongoDB Lens
- **Location**: `furey/mongodb-lens`
- **Repository**: https://github.com/furey/mongodb-lens
- **Justification**: Full-featured MongoDB database integration. Critical for NoSQL injection, connection security, and data exposure risks in document databases.

### 23. Automata Labs Playwright
- **Location**: `Automata-Labs-team/MCP-Server-Playwright`
- **Repository**: https://github.com/Automata-Labs-team/MCP-Server-Playwright
- **Stars**: 270+
- **Justification**: Third Playwright implementation providing additional comparative data for browser automation security patterns.

### 24. AWS MCP Server (Docker)
- **Location**: `alexei-led/aws-mcp-server`
- **Repository**: https://github.com/alexei-led/aws-mcp-server
- **Justification**: Docker-based AWS CLI execution. High-risk for command injection, container escape, and AWS credential exposure. Important for containerized deployment security.

### 25. LocalStack MCP Server
- **Location**: `localstack/localstack-mcp-server`
- **Repository**: https://github.com/localstack/localstack-mcp-server
- **Justification**: Local AWS environment management. Important for development environment security, infrastructure-as-code vulnerabilities, and state management risks.

---

## Selection Criteria Summary

### Tier 1 (Official Anthropic Servers)
- **Criteria**: Reference implementations that set security standards for the ecosystem
- **Risk Focus**: Foundational vulnerabilities that would affect derivative implementations
- **Impact**: High - these servers are widely forked and copied

### Tier 2 (Smithery Top Downloads)
- **Criteria**: Usage metrics from Smithery.ai indicating active real-world deployment
- **Risk Focus**: Vulnerabilities affecting the largest user base
- **Impact**: High - direct exposure in production environments

### Tier 3 (Solo Creator Popularity)
- **Criteria**: GitHub stars and community adoption metrics
- **Risk Focus**: Diverse implementation approaches and specialized use cases
- **Impact**: Medium to High - significant adoption but more specialized audiences

---

## Risk Surface Areas Covered

This selection ensures comprehensive coverage across major vulnerability categories:

1. **File System Access**: Servers 1, 6 (filesystem operations, path traversal)
2. **Database Access**: Servers 3, 22 (SQL/NoSQL injection, connection security)
3. **Browser Automation**: Servers 4, 17, 19, 23 (SSRF, XSS, browser exploitation)
4. **API Integration**: Servers 2, 5, 7, 11, 16 (token handling, OAuth, rate limiting)
5. **Network Access**: Servers 12, 21 (SSRF, content injection, internal network access)
6. **Command Execution**: Servers 10, 24 (command injection, privilege escalation)
7. **Cloud Infrastructure**: Servers 18, 20, 25 (credential management, IAM, resource access)
8. **Data Persistence**: Servers 13 (storage security, injection, data exposure)

---

## Next Steps

1. Set up automated scanning infrastructure for these 25 servers
2. Develop server-specific test cases based on functionality profiles
3. Establish baseline security metrics for each tier
4. Create comparison framework for identifying cross-server vulnerability patterns
5. Begin scanning in priority order: Tier 2 (highest real-world exposure) → Tier 1 (reference implementations) → Tier 3 (specialized implementations)

---

## References

- [Anthropic MCP Announcement](https://www.anthropic.com/news/model-context-protocol)
- [Official MCP Servers Repository](https://github.com/modelcontextprotocol/servers)
- [Smithery MCP Registry](https://smithery.ai/)
- [Popular MCP Servers (Smithery Data)](https://github.com/pedrojaques99/popular-mcp-servers)
- [Awesome MCP Servers List](https://github.com/wong2/awesome-mcp-servers)
- [MCP Specification](https://modelcontextprotocol.io/specification/2025-11-25)
