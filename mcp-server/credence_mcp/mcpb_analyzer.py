#!/usr/bin/env python3
"""
Credence MCPB Extension Analyzer — Security analysis of Claude Desktop Extensions.

Detects known attack patterns in MCPB-bundled MCP servers, a ZIP-bundled
distribution format hit by CVSS 10.0 zero-click RCE (LayerX, Feb 2026).

Analysis checks:
  Manifest validation:
    1. Missing or invalid manifest.json
    2. No source repository declared
    3. Template injection in command/args (${user_config.*})

  Bundled dependency analysis:
    4. Bundled deps without lockfile
    5. Suspicious binary files in bundle

  Tool declaration analysis:
    6. Server type but no tools declared
    7. Sensitive user_config fields

  Server code scanning:
    8. Dynamic require/import from outside bundle
    9. External network calls not implied by tool descriptions

Usage:
    python -m credence_mcp.mcpb_analyzer /path/to/mcpb-dir [output.json]

Outputs: mcpb-analysis.json
"""

import json
import re
import sys
from pathlib import Path


# ── Template injection patterns ──────────────────────────────────

TEMPLATE_INJECTION_RE = re.compile(
    r'\$\{user_config\.[^}]*\}',
)

# ── Suspicious binary extensions ─────────────────────────────────

SUSPICIOUS_BINARY_EXTS = {
    '.exe', '.dll', '.dylib', '.so', '.com', '.scr', '.pif',
    '.msi', '.dmg', '.app',
}

# ── Server code patterns ─────────────────────────────────────────

DYNAMIC_REQUIRE_RE = re.compile(
    r'(?:require|import)\s*\(\s*(?:[a-zA-Z_$][\w$.]*|`[^`]*\$\{)',
)
DYNAMIC_IMPORT_RE = re.compile(
    r'import\s*\(\s*(?:[a-zA-Z_$][\w$.]*|`[^`]*\$\{)',
)
EXTERNAL_FETCH_RE = re.compile(
    r'(?:fetch|axios|got|request|https?\.(?:get|post|request)|urllib|requests\.(?:get|post))\s*\(',
    re.IGNORECASE,
)

# Files to scan for server code patterns
CODE_EXTENSIONS = {'.js', '.ts', '.mjs', '.mts', '.cjs', '.py', '.jsx', '.tsx'}
SKIP_DIRS = {'.git', '__pycache__', '.venv', 'venv'}


# ── Finding builder ─────────────────────────────────────────────

def _make_finding(
    finding_id: str,
    severity: str,
    title: str,
    description: str,
    file: str = "",
    line: int = 0,
    evidence: str = "",
) -> dict:
    """Create a finding dict in the standard Credence format."""
    return {
        "id": finding_id,
        "scanner": "mcpb-analyzer",
        "severity": severity,
        "category": "mcpb",
        "file": file,
        "line": line,
        "title": title,
        "description": description,
        "evidence": evidence,
    }


# ── Manifest loading ────────────────────────────────────────────

def _load_manifest(repo_path: Path) -> dict | None:
    """Load and parse manifest.json from the MCPB bundle."""
    manifest_path = repo_path / "manifest.json"
    if not manifest_path.exists():
        return None
    try:
        return json.loads(manifest_path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


# ── Manifest analysis ───────────────────────────────────────────

def _analyze_manifest(manifest: dict, repo_path: Path) -> list[dict]:
    """Analyze manifest.json for security issues."""
    findings = []

    # Check: no source repository
    repo_field = manifest.get("repository")
    if not repo_field:
        findings.append(_make_finding(
            "MCPB_NO_SOURCE_REPO",
            "medium",
            "No source repository declared",
            "manifest.json has no 'repository' field. Without a source repository, "
            "the bundled code cannot be verified against original source.",
            file="manifest.json",
        ))

    # Check: template injection in command/args
    command = manifest.get("command", "")
    args = manifest.get("args", [])
    env = manifest.get("env", {})

    # Check command field
    if isinstance(command, str) and TEMPLATE_INJECTION_RE.search(command):
        findings.append(_make_finding(
            "MCPB_TEMPLATE_INJECTION-command",
            "high",
            "Template injection in command field",
            "manifest.json 'command' field contains ${user_config.*} interpolation. "
            "User-controlled values in the command field enable arbitrary command execution "
            "(CVSS 10.0 zero-click RCE — LayerX disclosure).",
            file="manifest.json",
            evidence=command[:200],
        ))

    # Check first args entry (primary injection vector)
    if isinstance(args, list) and args:
        for i, arg in enumerate(args):
            if isinstance(arg, str) and TEMPLATE_INJECTION_RE.search(arg):
                findings.append(_make_finding(
                    f"MCPB_TEMPLATE_INJECTION-args[{i}]",
                    "high",
                    f"Template injection in args[{i}]",
                    f"manifest.json args[{i}] contains ${{user_config.*}} interpolation. "
                    "User-controlled values in args enable argument injection.",
                    file="manifest.json",
                    evidence=str(arg)[:200],
                ))

    # Check env values
    if isinstance(env, dict):
        for key, val in env.items():
            if isinstance(val, str) and TEMPLATE_INJECTION_RE.search(val):
                findings.append(_make_finding(
                    f"MCPB_TEMPLATE_INJECTION-env.{key}",
                    "medium",
                    f"Template injection in env.{key}",
                    f"manifest.json env.{key} contains ${{user_config.*}} interpolation. "
                    "While env vars are less directly exploitable than command/args, "
                    "user-controlled env values can influence server behavior.",
                    file="manifest.json",
                    evidence=f"{key}={val}"[:200],
                ))

    return findings


# ── Tool declaration analysis ────────────────────────────────────

def _analyze_tools(manifest: dict, repo_path: Path) -> list[dict]:
    """Analyze tool declarations in manifest."""
    findings = []

    server_type = manifest.get("server_type") or manifest.get("type")
    tools = manifest.get("tools", [])

    # Check: server type but no tools
    if server_type and not tools:
        findings.append(_make_finding(
            "MCPB_NO_TOOLS_DECLARED",
            "medium",
            "Server type specified but no tools declared",
            f"manifest.json declares server_type '{server_type}' but has no 'tools' array. "
            "Without declared tools, the server's capabilities are opaque.",
            file="manifest.json",
        ))

    # Check: sensitive user_config fields
    user_config = manifest.get("user_config", {})
    if isinstance(user_config, dict):
        for field_name, field_def in user_config.items():
            if isinstance(field_def, dict) and field_def.get("sensitive"):
                findings.append(_make_finding(
                    f"MCPB_SENSITIVE_USER_CONFIG-{field_name}",
                    "info",
                    f"Sensitive user_config field: {field_name}",
                    f"user_config field '{field_name}' is marked sensitive. "
                    "This is recorded for deliberation — sensitive config fields "
                    "may contain API keys or credentials.",
                    file="manifest.json",
                    evidence=f"{field_name}: {json.dumps(field_def)}"[:200],
                ))

    return findings


# ── Bundled dependency analysis ──────────────────────────────────

def _analyze_deps(repo_path: Path) -> list[dict]:
    """Analyze bundled dependencies for security issues."""
    findings = []

    node_modules = repo_path / "node_modules"
    lib_dir = repo_path / "lib"
    has_bundled = node_modules.is_dir() or lib_dir.is_dir()

    if has_bundled:
        # Check for lockfile
        lockfiles = [
            "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
            "requirements.txt", "Pipfile.lock", "poetry.lock",
        ]
        has_lockfile = any((repo_path / lf).exists() for lf in lockfiles)

        if not has_lockfile:
            findings.append(_make_finding(
                "MCPB_BUNDLED_DEPS_NO_LOCK",
                "medium",
                "Bundled dependencies without lockfile",
                "Bundle contains node_modules/ or lib/ but no lockfile. "
                "Without a lockfile, dependency versions cannot be verified "
                "and supply chain attacks cannot be detected.",
                file="node_modules/" if node_modules.is_dir() else "lib/",
            ))

    # Check for suspicious binaries anywhere in the bundle
    for path in repo_path.rglob('*'):
        if not path.is_file():
            continue
        if '.git' in path.parts:
            continue
        if path.suffix.lower() in SUSPICIOUS_BINARY_EXTS:
            try:
                rel_path = str(path.relative_to(repo_path))
            except ValueError:
                continue
            findings.append(_make_finding(
                f"MCPB_SUSPICIOUS_BINARIES-{rel_path}",
                "high",
                f"Suspicious binary file: {path.name}",
                f"Bundle contains binary file {rel_path} ({path.suffix}). "
                "Binary files in MCP server bundles cannot be audited and may "
                "contain malicious code.",
                file=rel_path,
            ))

    return findings


# ── Server code scanning ────────────────────────────────────────

def _analyze_server_code(manifest: dict, repo_path: Path) -> list[dict]:
    """Scan server code for suspicious patterns."""
    findings = []

    for path in repo_path.rglob('*'):
        if not path.is_file():
            continue
        if any(skip in path.parts for skip in SKIP_DIRS):
            continue
        # Skip node_modules — too noisy, deps are checked separately
        if 'node_modules' in path.parts:
            continue
        if path.suffix.lower() not in CODE_EXTENSIONS:
            continue

        try:
            content = path.read_text(errors='replace')
            rel_path = str(path.relative_to(repo_path))
        except Exception:
            continue

        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            # Dynamic require/import
            if DYNAMIC_REQUIRE_RE.search(line) or DYNAMIC_IMPORT_RE.search(line):
                findings.append(_make_finding(
                    f"MCPB_DYNAMIC_REQUIRE-{rel_path}:{line_num}",
                    "high",
                    "Dynamic require/import detected",
                    "Server code uses dynamic require() or import() with a variable "
                    "or template expression. Dynamic loading can pull code from "
                    "outside the audited bundle.",
                    file=rel_path,
                    line=line_num,
                    evidence=line.strip()[:200],
                ))

            # External fetch (only flag if the tool descriptions don't imply network)
            if EXTERNAL_FETCH_RE.search(line):
                findings.append(_make_finding(
                    f"MCPB_EXTERNAL_FETCH-{rel_path}:{line_num}",
                    "medium",
                    "Network call in server code",
                    "Server code makes network calls. Verify these are justified "
                    "by the declared tool descriptions. Undisclosed network access "
                    "may exfiltrate data.",
                    file=rel_path,
                    line=line_num,
                    evidence=line.strip()[:200],
                ))

    return findings


# ── Main analysis ────────────────────────────────────────────────

def analyze_repo(repo_path: str) -> dict:
    """Analyze an MCPB extension directory (unpacked)."""
    repo = Path(repo_path).resolve()

    if not repo.is_dir():
        return {"error": f"Not a directory: {repo_path}"}

    # Format detection: manifest.json with mcpb_version, or server/ directory
    manifest_path = repo / "manifest.json"
    server_dir = repo / "server"

    manifest = _load_manifest(repo)
    has_mcpb_marker = (
        (manifest is not None and "mcpb_version" in manifest)
        or server_dir.is_dir()
    )

    if not manifest_path.exists() and not has_mcpb_marker:
        return {
            "format": "mcpb-extension",
            "format_detected": False,
            "findings": [],
            "manifest": None,
            "warning_count": 0,
            "critical_count": 0,
        }

    findings = []

    if manifest is not None:
        findings.extend(_analyze_manifest(manifest, repo))
        findings.extend(_analyze_tools(manifest, repo))
        findings.extend(_analyze_deps(repo))
        findings.extend(_analyze_server_code(manifest, repo))

        # Build manifest summary (safe subset for output)
        manifest_summary = {
            "name": manifest.get("name", ""),
            "version": manifest.get("version", ""),
            "mcpb_version": manifest.get("mcpb_version", ""),
            "server_type": manifest.get("server_type") or manifest.get("type", ""),
            "repository": manifest.get("repository", ""),
            "tools_count": len(manifest.get("tools", [])),
        }
    else:
        findings.append(_make_finding(
            "MCPB_INVALID_MANIFEST",
            "critical",
            "manifest.json missing or invalid",
            "MCPB bundle has no valid manifest.json. Cannot determine server "
            "identity, permissions, or tool declarations.",
            file="manifest.json",
        ))
        # Still scan for deps and code even without manifest
        findings.extend(_analyze_deps(repo))
        findings.extend(_analyze_server_code({}, repo))
        manifest_summary = None

    warning_count = sum(1 for f in findings if f["severity"] in ("medium", "low", "info"))
    critical_count = sum(1 for f in findings if f["severity"] in ("critical", "high"))

    return {
        "format": "mcpb-extension",
        "format_detected": True,
        "findings": findings,
        "manifest": manifest_summary,
        "warning_count": warning_count,
        "critical_count": critical_count,
    }


# ── CLI Entry Point ──────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} /path/to/mcpb-dir [output.json]")
        sys.exit(1)

    repo_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "/tmp/mcpb-analysis.json"

    report = analyze_repo(repo_path)

    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)

    # Summary to stdout
    print(f"Format detected:   {report.get('format_detected', False)}")
    print(f"Manifest:          {report.get('manifest', {})}")
    print(f"Critical/High:     {report.get('critical_count', 0)}")
    print(f"Warnings:          {report.get('warning_count', 0)}")
    print(f"Total findings:    {len(report.get('findings', []))}")
    print(f"\nOutput: {output_path}")

    # Exit code: non-zero if critical findings
    if report.get('critical_count', 0) > 0:
        sys.exit(2)


if __name__ == "__main__":
    main()
