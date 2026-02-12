# Credence MCP Server

Install-time trust verification for MCP servers. Check whether an MCP server has been analyzed, verified, and attested before you install it.

## The Problem

You're about to install an MCP server. How do you know it's safe? Right now you're checking GitHub stars, README quality, and maybe skimming the source. [Those signals can be manufactured.](https://www.straiker.ai/blog/smartloader-clones-oura-ring-mcp-to-deploy-supply-chain-attack)

## What This Does

The Credence MCP server connects your AI agent (or your terminal) to the Credence Registry — a database of cryptographic attestations for MCP servers. Each attestation includes source code fingerprints, verified author identity, provenance analysis, dependency scans, and an adversarial AI review.

Three ways to use it:

1. **MCP server** — your AI agent checks Credence before connecting to unknown servers
2. **CLI tool** — you check from the terminal or CI pipeline
3. **Both at once** — the agent uses the MCP server, you verify with the CLI

---

## Install

```bash
pip install credence-mcp
```

Or from source:

```bash
git clone https://github.com/pestafford/credence-registry.git
cd credence-registry/mcp-server
pip install -e .
```

---

## Usage: CLI

### Check a server

```bash
credence check https://github.com/modelcontextprotocol/server-github

# Or use shorthand
credence check modelcontextprotocol/server-github
```

Output:

```
GitHub MCP Server
   https://github.com/modelcontextprotocol/server-github

   Trust score:  92/100
   Verdict:      APPROVED
   Identity:     verified
   Commit:       a1b2c3d4e5f6
   Source hash:  def789abcdef01...
   Attested:     2026-02-10T14:30:00Z

   ✔ SAFE TO INSTALL
```

### Verify local source matches attestation

After cloning, verify the code hasn't been tampered with:

```bash
git clone https://github.com/owner/mcp-server
credence verify owner/mcp-server --path ./mcp-server
```

Output:

```
Computing source hash for /home/dev/mcp-server...
   Local hash: abc123...
Checking Credence Registry...
   Attested:   abc123...

   ✔ HASH MATCH — code is identical to attested version
```

### List all attested servers

```bash
credence list
credence list --min-score 70
```

### Audit all your configured servers

Reads your `claude_desktop_config.json` (or Claude Code config), resolves every server to its package and repo, and checks each against the Credence Registry:

```bash
credence audit
```

Output:

```
Config: /Users/you/Library/Application Support/Claude/claude_desktop_config.json
Found 6 configured MCP server(s)
Checking Credence Registry...

MCP Server Audit
────────────────────────────────────────────────────────

  github [npx]
  npx @modelcontextprotocol/server-github
  Package: @modelcontextprotocol/server-github
  Repo:    https://github.com/modelcontextprotocol/servers
  ✔ ATTESTED — score: 92/100, verdict: APPROVED

  filesystem [npx]
  npx @modelcontextprotocol/server-filesystem /Users/you/docs
  Package: @modelcontextprotocol/server-filesystem
  Repo:    https://github.com/modelcontextprotocol/servers
  ✔ ATTESTED — score: 95/100, verdict: APPROVED

  sketchy-tool [python]
  python -m sketchy_mcp_thing
  Package: sketchy_mcp_thing
  ○ NOT ATTESTED — no Credence record found

────────────────────────────────────────────────────────

  Audit Summary
  ✔ Attested:    2/3
  ○ Unattested:  1/3

  Submit unattested servers: https://credence.securingthesingularity.com/#submit
```

The resolver handles npx packages (npm registry lookup), Python modules (PyPI lookup), uvx, docker images, node scripts, and direct binary paths. It finds the repo URL automatically when possible.

### Guard a command

Check trust before running any command. Blocks execution if the server is rejected:

```bash
# Check first, then add the server
credence guard owner/mcp-server -- claude mcp add my-server

# Allow unattested servers to proceed (with warning)
credence guard owner/mcp-server --allow-unattested -- claude mcp add my-server

# Just check, don't run anything
credence guard owner/mcp-server
```

Use this as a shell alias:

```bash
# Add to .bashrc / .zshrc
mcp-add() {
    local server="$1"
    shift
    credence guard "$server" -- claude mcp add "$@"
}
```

### Watch for config changes

Monitor your MCP client config file in real-time. Alerts when new servers are added:

```bash
credence watch
credence watch --interval 10
credence watch --config ~/custom/claude_desktop_config.json
```

Output:

```
Credence Watch
Monitoring: /Users/you/Library/Application Support/Claude/claude_desktop_config.json
Checking every 5s. Press Ctrl+C to stop.

[14:23:07] New server detected: oura-ring
  python -m oura_mcp_server
  ○ NOT ATTESTED — no Credence record

[14:25:12] New server detected: github
  npx @modelcontextprotocol/server-github
  ✔ ATTESTED — score: 92/100
```

On macOS, also sends a system notification for unattested or flagged servers. On Linux, uses `notify-send`.

### Exit codes (for CI/scripts)

| Code | Meaning |
|------|---------|
| 0 | Attested, safe to install |
| 1 | Not attested or error |
| 2 | Attested but flagged — review recommended |
| 3 | Rejected or hash mismatch — do not install |
| 4 | Audit found unattested or flagged servers |

Use in CI:

```bash
credence check owner/mcp-server || exit 1
```

---

## Usage: MCP Server

### Add to Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "credence": {
      "command": "python",
      "args": ["-m", "credence_server"],
      "env": {}
    }
  }
}
```

Once connected, Claude can use these tools:

- **`credence_check_server`** — Check if a server has an attestation and what the trust status is
- **`credence_verify_hash`** — Verify a source hash against the attested hash
- **`credence_hash_local`** — Compute the source hash of a local directory
- **`credence_list_servers`** — List all attested servers with scores and verdicts
- **`credence_audit_config`** — Audit all MCP servers in the local client config at once

### Add to Claude Code

```bash
claude mcp add credence -- python -m credence_server
```

### Add to any MCP client (stdio)

```bash
python credence_server.py
```

### Run as HTTP server

```bash
python credence_server.py --transport http --port 8400
```

---

## How the Agent Uses It

Once Credence is connected as an MCP server, an AI agent can be instructed to check trust before connecting to unknown servers. The recommended system prompt addition:

```
Before installing or connecting to any MCP server you haven't used before,
use the credence_check_server tool to verify its trust status. If the server
is not attested or has provenance flags, inform the user and ask for
confirmation before proceeding.
```

### Example agent workflow

1. User: "Install the Oura Ring MCP server"
2. Agent calls `credence_check_server` with `"owner/oura-ring-mcp"`
3. Credence returns trust score, provenance flags, verdict
4. Agent reports: "This server has a trust score of 85/100, approved by ThinkTank, no provenance flags. Safe to install."
5. — or —
6. Agent reports: "This server is NOT attested by Credence. I can't verify its safety. Want me to proceed anyway, or submit it for analysis first?"

### Example: verify before install

1. User: "Clone and install github.com/someone/cool-mcp-server"
2. Agent clones the repo
3. Agent calls `credence_hash_local` on the cloned directory
4. Agent calls `credence_verify_hash` with the computed hash
5. If match: "Source verified against Credence attestation. Installing."
6. If mismatch: "WARNING — the source code doesn't match what Credence analyzed. This code may have been modified. I recommend not installing."

---

## Integration: Pre-Install Hook

For automated environments, wrap MCP server installation with a Credence check:

```bash
#!/bin/bash
# credence-install.sh — Install MCP server only if Credence approves

REPO_URL="$1"

if [ -z "$REPO_URL" ]; then
    echo "Usage: credence-install.sh <repo-url>"
    exit 1
fi

# Check attestation
credence check "$REPO_URL"
CHECK_RESULT=$?

case $CHECK_RESULT in
    0)
        echo "Credence: APPROVED — proceeding with install"
        git clone "$REPO_URL" /tmp/mcp-install
        cd /tmp/mcp-install

        # Verify source matches attestation
        credence verify "$REPO_URL" --path .
        VERIFY_RESULT=$?

        if [ $VERIFY_RESULT -eq 0 ]; then
            echo "Source verified. Installing..."
            # Your install command here (npm install, pip install, etc.)
        else
            echo "SOURCE MISMATCH — aborting install"
            exit 3
        fi
        ;;
    1)
        echo "Credence: NOT ATTESTED — server has not been analyzed"
        echo "Submit for analysis: https://credence.securingthesingularity.com/#submit"
        read -p "Install anyway? (y/N) " confirm
        [ "$confirm" = "y" ] || exit 1
        git clone "$REPO_URL" /tmp/mcp-install
        ;;
    2)
        echo "Credence: FLAGGED — review recommended before installing"
        read -p "Install anyway? (y/N) " confirm
        [ "$confirm" = "y" ] || exit 2
        git clone "$REPO_URL" /tmp/mcp-install
        ;;
    3)
        echo "Credence: REJECTED — do not install this server"
        exit 3
        ;;
esac
```

---

## Integration: GitHub Actions

Add a Credence check to your CI pipeline:

```yaml
- name: Verify MCP server dependencies
  run: |
    pip install credence-mcp
    for server in $(cat mcp-servers.txt); do
      credence check "$server"
      if [ $? -ge 3 ]; then
        echo "BLOCKED: $server failed Credence check"
        exit 1
      fi
    done
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CREDENCE_REGISTRY_URL` | GitHub raw URL | Override registry location |
| `CREDENCE_CACHE_TTL` | `300` | Cache duration in seconds |

---

## Architecture

```
┌─────────────────┐     ┌──────────────────────┐     ┌─────────────────┐
│   AI Agent      │     │  Credence MCP Server  │     │    Credence     │
│  (Claude, etc.) │────▶│                       │────▶│    Registry     │
│                 │ MCP │  check / verify / hash │HTTP │  (GitHub JSON)  │
│                 │     │  list / audit          │     └─────────────────┘
└─────────────────┘     └──────────────────────┘

┌─────────────────┐     ┌──────────────────────┐
│   Developer     │     │  credence CLI         │
│   Terminal      │────▶│  check / verify / list│────▶ same registry
│                 │     │  audit / guard / watch │
└─────────────────┘     └──────────────────────┘

┌─────────────────┐     ┌──────────────────────┐
│   Config File   │     │  credence watch       │
│   (auto-detect) │◀───▶│  (daemon)             │────▶ alerts on new
└─────────────────┘     └──────────────────────┘      unattested servers

┌─────────────────┐     ┌──────────────────────┐
│   CI Pipeline   │────▶│  credence guard       │────▶ exit codes
│   Shell Scripts │     │  (gate + exec)        │     for automation
└─────────────────┘     └──────────────────────┘
```

The MCP server and CLI both read from the same `registry.json` hosted on GitHub. The registry is populated by the Credence scan pipeline (GitHub Actions) which runs when servers are submitted for analysis.

---

## What Credence Does NOT Do

- **Runtime monitoring** — Credence is install-time only. Use Docker MCP Catalog, ToolHive, or Solo.io Agent Mesh for runtime enforcement.
- **Guarantee safety** — An attestation means the server was analyzed and the results are published. A high trust score is strong signal, not a guarantee.
- **Replace judgment** — Credence gives you data. You (or your agent) make the decision.

---

## Links

- **Registry & landing page**: [credence.securingthesingularity.com](https://credence.securingthesingularity.com)
- **Submit a server**: [Submit form](https://credence.securingthesingularity.com/#submit)
- **Research**: [medium.com/@pe.stafford](https://medium.com/@pe.stafford)
- **Singularity Systems**: [securingthesingularity.com](https://securingthesingularity.com)

## License

MIT
