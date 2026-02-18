#!/usr/bin/env python3
"""
Credence OpenClaw Skill Analyzer — Security analysis of OpenClaw skill packages.

Detects known attack patterns in OpenClaw skills (5,700+ on ClawHub),
a markdown-as-installer format hit by coordinated malware campaigns
(Snyk, 1Password disclosures).

Analysis checks:
  Manifest analysis (SKILL.md frontmatter + claw.json):
    1. Missing permissions manifest
    2. Exec permission declared
    3. Credential access declared
    4. Broad filesystem write permissions
    5. Broad network permissions

  Content scanning (SKILL.md body, instructions.md, bundled scripts):
    6. Base64/hex-encoded payloads in shell commands
    7. curl/wget to raw IPs or unusual domains
    8. macOS quarantine bypass (xattr -d com.apple.quarantine)
    9. Hidden package installs not in manifest requirements
   10. Password-protected archives
   11. chmod +x on downloaded files

Usage:
    python -m credence_mcp.skill_analyzer /path/to/skill-repo [output.json]

Outputs: skill-analysis.json
"""

import json
import re
import sys
from pathlib import Path


# ── Manifest permission patterns ────────────────────────────────

# Patterns for detecting risky permissions in SKILL.md frontmatter YAML
EXEC_PERMISSION_RE = re.compile(r'^\s*-?\s*exec\b', re.MULTILINE | re.IGNORECASE)
CREDENTIAL_ACCESS_RE = re.compile(
    r'sensitive_data\s*[:\.]?\s*credentials\s*:\s*true',
    re.IGNORECASE,
)
BROAD_FILESYSTEM_RE = re.compile(
    r'write\s*:\s*[*]|write\s*:\s*/',
    re.IGNORECASE,
)
BROAD_NETWORK_RE = re.compile(
    r'network\s*:.*[*]',
    re.IGNORECASE,
)

# ── Content attack patterns ─────────────────────────────────────

ENCODED_PAYLOAD = re.compile(
    r'(?:echo|printf)\s+["\']?[A-Za-z0-9+/=]{40,}["\']?\s*\|\s*(?:base64|decode|bash|sh)',
    re.IGNORECASE,
)
RAW_IP_URL = re.compile(
    r'(?:curl|wget|fetch)\s+.*https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
)
QUARANTINE_BYPASS = re.compile(
    r'xattr\s+-[dr]\s+com\.apple\.quarantine',
)
HIDDEN_INSTALL = re.compile(
    r'(?:pip|pip3|npm|yarn|pnpm)\s+install\s+(?!-r\s)(?!--requirement)',
    re.IGNORECASE,
)
PASSWORD_ARCHIVE = re.compile(
    r'(?:unzip|7z|tar)\s+.*(?:-p|--password|PASSWORD)',
    re.IGNORECASE,
)
CHMOD_EXEC = re.compile(r'chmod\s+\+x')

# ── Crypto / financial attack patterns ─────────────────────────

# Hardcoded wallet addresses in assignment context (not just mentioned in comments)
CRYPTO_WALLET_ADDRESS = re.compile(
    r'(?:wallet|address|recipient|dest(?:ination)?|to_addr|account)\s*[=:]\s*["\']'
    r'(?:'
    r'[1-9A-HJ-NP-Za-km-z]{32,50}'     # Solana base58 / Bitcoin
    r'|0x[0-9a-fA-F]{40}'               # Ethereum
    r')["\']',
)

# Creating key/wallet files in home directories
CRYPTO_PRIVATE_KEY_STORAGE = re.compile(
    r'(?:~/|~\\|/home/|%USERPROFILE%|expanduser)'
    r'.*(?:\.bob-p2p|wallet\.dat|keystore|\.keys|private.?key|seed\.txt|mnemonic)',
    re.IGNORECASE,
)

# Importing crypto/blockchain SDKs
CRYPTO_SDK_IMPORT = re.compile(
    r'(?:from\s+|import\s+|require\s*\(\s*["\']|from\s+["\'])'
    r'(?:@solana/web3\.js|solders|solana|ethers|web3(?:\.py)?|brownie|hardhat|anchor|'
    r'spl-token|@project-serum|@metaplex|@coral-xyz)',
    re.IGNORECASE,
)

# Transfer/send/swap/buy token function calls, DEX interactions
CRYPTO_TRANSACTION = re.compile(
    r'(?:transfer|sendTransaction|send_transaction|swap|buy_?token|sell_?token|'
    r'signTransaction|sign_transaction|signAndSend|sign_and_send|'
    r'(?:jupiter|raydium|uniswap|pancakeswap|orca).*(?:swap|exchange|route))',
    re.IGNORECASE,
)

# Files to scan for content attack patterns
CONTENT_EXTENSIONS = {'.md', '.sh', '.py', '.js', '.ts', '.bash', '.zsh', '.ps1', '.bat', '.cmd'}
SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv'}

# Documentation files: findings are instructional, not executable
DOC_EXTENSIONS = {'.md'}

# Test directories: attack strings in test fixtures are expected test data
TEST_DIRS = {'__tests__', 'test', 'tests', 'spec', 'test_data', 'testdata', 'fixtures'}

# Severity downgrade map for documentation and test contexts
# Maps original severity -> reduced severity
_DOC_SEVERITY = {"critical": "medium", "high": "low", "medium": "info"}
_TEST_SEVERITY = {"critical": "medium", "high": "low", "medium": "info"}


def _contextual_severity(severity: str, rel_path: str) -> str:
    """Downgrade severity for findings in documentation or test files."""
    path = Path(rel_path)

    # Check if file is in a test directory
    if any(part in TEST_DIRS for part in path.parts):
        return _TEST_SEVERITY.get(severity, severity)

    # Check if file is documentation (markdown)
    if path.suffix.lower() in DOC_EXTENSIONS:
        return _DOC_SEVERITY.get(severity, severity)

    return severity


# ── Finding builder ─────────────────────────────────────────────

def _make_finding(
    finding_id: str,
    severity: str,
    title: str,
    description: str,
    file: str = "",
    line: int = 0,
    evidence: str = "",
    category: str = "skill",
) -> dict:
    """Create a finding dict in the standard Credence format."""
    return {
        "id": finding_id,
        "scanner": "skill-analyzer",
        "severity": severity,
        "category": category,
        "file": file,
        "line": line,
        "title": title,
        "description": description,
        "evidence": evidence,
    }


# ── Manifest analysis ───────────────────────────────────────────

def _parse_frontmatter(content: str) -> str | None:
    """Extract YAML frontmatter from SKILL.md (between --- delimiters)."""
    if not content.startswith('---'):
        # Check if it starts with optional whitespace then ---
        stripped = content.lstrip()
        if not stripped.startswith('---'):
            return None
        content = stripped

    parts = content.split('---', 2)
    if len(parts) < 3:
        return None
    return parts[1]


def _analyze_manifest(repo_path: Path) -> list[dict]:
    """Parse SKILL.md frontmatter and claw.json for permission analysis."""
    findings = []
    skill_md = repo_path / "SKILL.md"
    claw_json = repo_path / "claw.json"

    frontmatter = None
    skill_body = ""

    if skill_md.exists():
        try:
            content = skill_md.read_text(errors='replace')
            frontmatter = _parse_frontmatter(content)
            # Body is everything after the second ---
            parts = content.split('---', 2)
            if len(parts) >= 3:
                skill_body = parts[2]
        except Exception:
            pass

    claw_data = None
    if claw_json.exists():
        try:
            claw_data = json.loads(claw_json.read_text())
        except Exception:
            pass

    # Check: no manifest at all
    if frontmatter is None and claw_data is None:
        findings.append(_make_finding(
            "SKILL_NO_MANIFEST",
            "info",
            "No permissions manifest found",
            "Skill has no SKILL.md frontmatter or claw.json declaring permissions. "
            "Cannot verify what access the skill requires.",
            file="SKILL.md",
            category="skill-behavioral",
        ))
        return findings

    manifest_text = (frontmatter or "") + "\n" + json.dumps(claw_data or {})

    # Check: exec permission
    if EXEC_PERMISSION_RE.search(manifest_text):
        findings.append(_make_finding(
            "SKILL_EXEC_PERMISSION",
            "medium",
            "Skill declares exec permission",
            "Skill requests execution permission, allowing it to run arbitrary commands. "
            "Verify the skill's purpose justifies command execution access.",
            file="SKILL.md" if frontmatter and EXEC_PERMISSION_RE.search(frontmatter) else "claw.json",
            category="skill-behavioral",
        ))

    # Check: credential access
    if CREDENTIAL_ACCESS_RE.search(manifest_text):
        findings.append(_make_finding(
            "SKILL_CREDENTIAL_ACCESS",
            "medium",
            "Skill requests credential access",
            "Skill declares sensitive_data.credentials: true, requesting access to "
            "stored credentials.",
            file="SKILL.md" if frontmatter and CREDENTIAL_ACCESS_RE.search(frontmatter) else "claw.json",
            category="skill-behavioral",
        ))

    # Check: broad filesystem write
    if BROAD_FILESYSTEM_RE.search(manifest_text):
        findings.append(_make_finding(
            "SKILL_BROAD_FILESYSTEM",
            "high",
            "Skill requests broad filesystem write access",
            "Skill declares write:* or write:/ permission, granting write access "
            "to the entire filesystem. Legitimate skills should scope writes to "
            "specific directories.",
            file="SKILL.md" if frontmatter and BROAD_FILESYSTEM_RE.search(frontmatter) else "claw.json",
            category="skill-behavioral",
        ))

    # Check: broad network
    if BROAD_NETWORK_RE.search(manifest_text):
        findings.append(_make_finding(
            "SKILL_BROAD_NETWORK",
            "medium",
            "Skill requests unrestricted network access",
            "Skill declares wildcard network permissions, allowing connections to "
            "any host. Legitimate skills should declare specific domains.",
            file="SKILL.md" if frontmatter and BROAD_NETWORK_RE.search(frontmatter) else "claw.json",
            category="skill-behavioral",
        ))

    return findings


# ── Content scanning ─────────────────────────────────────────────

def _scan_file_content(file_path: Path, rel_path: str) -> list[dict]:
    """Scan a single file for known attack patterns."""
    findings = []
    try:
        content = file_path.read_text(errors='replace')
    except Exception:
        return findings

    lines = content.split('\n')
    for line_num, line in enumerate(lines, 1):
        # Encoded payload
        if ENCODED_PAYLOAD.search(line):
            findings.append(_make_finding(
                f"SKILL_ENCODED_PAYLOAD-{rel_path}:{line_num}",
                _contextual_severity("high", rel_path),
                "Base64/hex-encoded payload in shell command",
                "Shell command pipes encoded data through base64/decode/bash. "
                "This pattern is used by malware to hide payloads from review.",
                file=rel_path,
                line=line_num,
                evidence=line.strip()[:200],
            ))

        # Raw IP URL
        if RAW_IP_URL.search(line):
            findings.append(_make_finding(
                f"SKILL_EXTERNAL_URL-{rel_path}:{line_num}",
                _contextual_severity("high", rel_path),
                "curl/wget to raw IP address",
                "Skill fetches content from a raw IP address. Legitimate tools "
                "use domain names; raw IPs are commonly used by malware to avoid "
                "DNS-based blocking.",
                file=rel_path,
                line=line_num,
                evidence=line.strip()[:200],
            ))

        # Quarantine bypass
        if QUARANTINE_BYPASS.search(line):
            findings.append(_make_finding(
                f"SKILL_QUARANTINE_BYPASS-{rel_path}:{line_num}",
                _contextual_severity("critical", rel_path),
                "macOS quarantine bypass detected",
                "Skill removes com.apple.quarantine extended attribute, bypassing "
                "macOS Gatekeeper security. This is a key indicator of malware "
                "installation (Snyk/1Password OpenClaw campaign pattern).",
                file=rel_path,
                line=line_num,
                evidence=line.strip()[:200],
            ))

        # Hidden package install
        if HIDDEN_INSTALL.search(line):
            findings.append(_make_finding(
                f"SKILL_HIDDEN_INSTALL-{rel_path}:{line_num}",
                _contextual_severity("high", rel_path),
                "Package install in skill content",
                "Skill installs packages (pip/npm/yarn/pnpm) directly. Package "
                "installs should be declared in the manifest requirements, not "
                "embedded in instructions or scripts.",
                file=rel_path,
                line=line_num,
                evidence=line.strip()[:200],
            ))

        # Password-protected archive
        if PASSWORD_ARCHIVE.search(line):
            findings.append(_make_finding(
                f"SKILL_PASSWORD_ARCHIVE-{rel_path}:{line_num}",
                _contextual_severity("high", rel_path),
                "Password-protected archive extraction",
                "Skill extracts a password-protected archive. Password archives "
                "are used to evade antivirus scanning — contents cannot be "
                "inspected before extraction.",
                file=rel_path,
                line=line_num,
                evidence=line.strip()[:200],
            ))

        # chmod +x on downloaded files
        if CHMOD_EXEC.search(line):
            findings.append(_make_finding(
                f"SKILL_CHMOD_EXEC-{rel_path}:{line_num}",
                _contextual_severity("medium", rel_path),
                "chmod +x on file",
                "Skill makes a file executable. Combined with download commands, "
                "this pattern enables execution of untrusted binaries.",
                file=rel_path,
                line=line_num,
                evidence=line.strip()[:200],
            ))

        # Hardcoded crypto wallet address
        if CRYPTO_WALLET_ADDRESS.search(line):
            findings.append(_make_finding(
                f"SKILL_CRYPTO_WALLET-{rel_path}:{line_num}",
                _contextual_severity("high", rel_path),
                "Hardcoded crypto wallet address",
                "Skill contains a hardcoded cryptocurrency wallet address in an "
                "assignment context. Legitimate tools do not embed destination "
                "wallet addresses — this is a drain/exfiltration indicator.",
                file=rel_path,
                line=line_num,
                evidence=line.strip()[:200],
            ))

        # Private key / wallet file creation in home directories
        if CRYPTO_PRIVATE_KEY_STORAGE.search(line):
            findings.append(_make_finding(
                f"SKILL_CRYPTO_KEY_STORAGE-{rel_path}:{line_num}",
                _contextual_severity("high", rel_path),
                "Crypto key/wallet file in home directory",
                "Skill creates or accesses key/wallet files in the user's home "
                "directory. This pattern is used to store stolen keys or seed "
                "phrases for later exfiltration.",
                file=rel_path,
                line=line_num,
                evidence=line.strip()[:200],
            ))

        # Crypto SDK import
        if CRYPTO_SDK_IMPORT.search(line):
            findings.append(_make_finding(
                f"SKILL_CRYPTO_SDK-{rel_path}:{line_num}",
                _contextual_severity("medium", rel_path),
                "Crypto/blockchain SDK import",
                "Skill imports a cryptocurrency or blockchain SDK. While not "
                "inherently malicious, this capability should match the tool's "
                "declared purpose.",
                file=rel_path,
                line=line_num,
                evidence=line.strip()[:200],
                category="skill-behavioral",
            ))

        # Crypto transaction / transfer calls
        if CRYPTO_TRANSACTION.search(line):
            findings.append(_make_finding(
                f"SKILL_CRYPTO_TRANSACTION-{rel_path}:{line_num}",
                _contextual_severity("high", rel_path),
                "Crypto transaction/transfer operation",
                "Skill performs cryptocurrency transactions (transfer, swap, buy, "
                "sign). Combined with hardcoded addresses, this enables wallet "
                "drain attacks.",
                file=rel_path,
                line=line_num,
                evidence=line.strip()[:200],
            ))

    return findings


def _analyze_content(repo_path: Path) -> list[dict]:
    """Scan skill content for known attack patterns."""
    findings = []

    for path in repo_path.rglob('*'):
        if not path.is_file():
            continue
        if any(skip in path.parts for skip in SKIP_DIRS):
            continue
        if path.suffix.lower() not in CONTENT_EXTENSIONS:
            continue

        try:
            rel_path = str(path.relative_to(repo_path))
        except ValueError:
            continue

        findings.extend(_scan_file_content(path, rel_path))

    return findings


# ── Main analysis ────────────────────────────────────────────────

def analyze_repo(repo_path: str) -> dict:
    """Analyze an OpenClaw skill directory."""
    repo = Path(repo_path).resolve()

    if not repo.is_dir():
        return {"error": f"Not a directory: {repo_path}"}

    # Format detection: look for SKILL.md or claw.json
    skill_md = repo / "SKILL.md"
    claw_json = repo / "claw.json"
    if not skill_md.exists() and not claw_json.exists():
        return {
            "format": "openclaw-skill",
            "format_detected": False,
            "findings": [],
            "manifest_found": False,
            "permissions_declared": {},
            "warning_count": 0,
            "critical_count": 0,
        }

    findings = []
    findings.extend(_analyze_manifest(repo))
    findings.extend(_analyze_content(repo))

    warning_count = sum(1 for f in findings if f["severity"] in ("medium", "low", "info"))
    critical_count = sum(1 for f in findings if f["severity"] in ("critical", "high"))

    return {
        "format": "openclaw-skill",
        "format_detected": True,
        "findings": findings,
        "manifest_found": skill_md.exists() or claw_json.exists(),
        "permissions_declared": {},
        "warning_count": warning_count,
        "critical_count": critical_count,
    }


# ── CLI Entry Point ──────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} /path/to/skill-repo [output.json]")
        sys.exit(1)

    repo_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "/tmp/skill-analysis.json"

    report = analyze_repo(repo_path)

    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)

    # Summary to stdout
    print(f"Format detected:   {report.get('format_detected', False)}")
    print(f"Manifest found:    {report.get('manifest_found', False)}")
    print(f"Critical/High:     {report.get('critical_count', 0)}")
    print(f"Warnings:          {report.get('warning_count', 0)}")
    print(f"Total findings:    {len(report.get('findings', []))}")
    print(f"\nOutput: {output_path}")

    # Exit code: non-zero if critical findings
    if report.get('critical_count', 0) > 0:
        sys.exit(2)


if __name__ == "__main__":
    main()
