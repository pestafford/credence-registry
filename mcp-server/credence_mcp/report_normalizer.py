#!/usr/bin/env python3
"""
Credence Report Normalizer — Unified evidence format from all scanner outputs.

Takes raw output from Semgrep, Bandit, Trivy, GitLeaks, npm audit, pip-audit,
ESLint, and MCP Tool Analyzer and normalizes to a single evidence.json with
consistent schema. This is the input for deliberation-mcp adversarial analysis.

Usage:
    python report_normalizer.py /path/to/scan-results/ [output.json] [--source-dir /path/to/repo]
"""

import argparse
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Optional


def normalize_semgrep(path: Path) -> list[dict]:
    """Normalize Semgrep SAST results."""
    try:
        data = json.loads(path.read_text())
    except Exception:
        return []

    findings = []
    for r in data.get("results", []):
        finding = {
            "id": f"semgrep-{r.get('check_id', 'unknown')}-{r.get('path', '')}:{r.get('start', {}).get('line', 0)}",
            "scanner": "semgrep",
            "severity": _map_severity(r.get("extra", {}).get("severity", "WARNING")),
            "category": "sast",
            "file": r.get("path", ""),
            "line": r.get("start", {}).get("line", 0),
            "title": r.get("check_id", "").split(".")[-1],
            "description": r.get("extra", {}).get("message", ""),
            "cwe": r.get("extra", {}).get("metadata", {}).get("cwe", []),
        }
        snippet = r.get("extra", {}).get("lines", "")
        if snippet:
            finding["source_context"] = {
                "lines": [[r.get("start", {}).get("line", 0), snippet.rstrip()]],
                "flagged_line": r.get("start", {}).get("line", 0),
                "source": "scanner",
            }
        findings.append(finding)
    return findings


def normalize_bandit(path: Path) -> list[dict]:
    """Normalize Bandit Python security results."""
    try:
        data = json.loads(path.read_text())
    except Exception:
        return []

    findings = []
    for r in data.get("results", []):
        finding = {
            "id": f"bandit-{r.get('test_id', 'unknown')}-{r.get('filename', '')}:{r.get('line_number', 0)}",
            "scanner": "bandit",
            "severity": _map_severity(r.get("issue_severity", "LOW")),
            "category": "sast",
            "file": r.get("filename", ""),
            "line": r.get("line_number", 0),
            "title": r.get("test_name", ""),
            "description": r.get("issue_text", ""),
            "confidence": r.get("issue_confidence", ""),
        }
        snippet = r.get("code", "")
        if snippet:
            finding["source_context"] = {
                "lines": [[r.get("line_number", 0), snippet.strip()]],
                "flagged_line": r.get("line_number", 0),
                "source": "scanner",
            }
        findings.append(finding)
    return findings


def normalize_trivy(path: Path) -> list[dict]:
    """Normalize Trivy CVE scan results."""
    try:
        data = json.loads(path.read_text())
    except Exception:
        return []

    findings = []
    for result in data.get("Results", []):
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities", []):
            findings.append({
                "id": f"trivy-{vuln.get('VulnerabilityID', 'unknown')}",
                "scanner": "trivy",
                "severity": _map_severity(vuln.get("Severity", "UNKNOWN")),
                "category": "cve",
                "file": target,
                "line": 0,
                "title": vuln.get("VulnerabilityID", ""),
                "description": vuln.get("Title", vuln.get("Description", ""))[:300],
                "package": vuln.get("PkgName", ""),
                "installed_version": vuln.get("InstalledVersion", ""),
                "fixed_version": vuln.get("FixedVersion", ""),
                "cwe": vuln.get("CweIDs", []),
            })
    return findings


def normalize_gitleaks(path: Path) -> list[dict]:
    """Normalize GitLeaks secrets detection results."""
    try:
        data = json.loads(path.read_text())
    except Exception:
        return []

    if not isinstance(data, list):
        return []

    findings = []
    for r in data:
        # Redact secret: show only first4...last4
        secret = r.get("Secret", "")
        if len(secret) > 8:
            redacted = f"[secret: {secret[:4]}...{secret[-4:]}]"
        elif secret:
            redacted = "[secret: ****]"
        else:
            redacted = ""
        finding = {
            "id": f"gitleaks-{r.get('RuleID', 'unknown')}-{r.get('File', '')}:{r.get('StartLine', 0)}",
            "scanner": "gitleaks",
            "severity": "critical",
            "category": "secrets",
            "file": r.get("File", ""),
            "line": r.get("StartLine", 0),
            "title": f"Secret detected: {r.get('RuleID', 'unknown')}",
            "description": r.get("Description", ""),
            "secret_type": r.get("RuleID", ""),
            "commit": r.get("Commit", ""),
        }
        if redacted:
            finding["source_context"] = {
                "lines": [[r.get("StartLine", 0), redacted]],
                "flagged_line": r.get("StartLine", 0),
                "source": "scanner_redacted",
            }
        findings.append(finding)
    return findings


def normalize_npm_audit(path: Path) -> list[dict]:
    """Normalize npm audit results."""
    try:
        data = json.loads(path.read_text())
    except Exception:
        return []

    if data.get("skipped"):
        return []

    findings = []
    vulns = data.get("vulnerabilities", {})
    for name, info in vulns.items():
        if isinstance(info, dict):
            findings.append({
                "id": f"npm-{name}-{info.get('severity', 'unknown')}",
                "scanner": "npm-audit",
                "severity": _map_severity(info.get("severity", "low")),
                "category": "cve",
                "file": "package.json",
                "line": 0,
                "title": f"Vulnerable dependency: {name}",
                "description": info.get("via", [{}])[0] if isinstance(info.get("via"), list) else str(info.get("via", "")),
                "package": name,
                "range": info.get("range", ""),
            })
    return findings


def normalize_pip_audit(path: Path) -> list[dict]:
    """Normalize pip-audit results."""
    try:
        data = json.loads(path.read_text())
    except Exception:
        return []

    if isinstance(data, dict) and data.get("skipped"):
        return []

    if not isinstance(data, list):
        return []

    findings = []
    for r in data:
        findings.append({
            "id": f"pip-{r.get('name', 'unknown')}-{r.get('id', '')}",
            "scanner": "pip-audit",
            "severity": "medium",  # pip-audit output does not include severity; default to medium
            "category": "cve",
            "file": "requirements.txt",
            "line": 0,
            "title": f"Vulnerable dependency: {r.get('name', 'unknown')}",
            "description": r.get("description", ""),
            "package": r.get("name", ""),
            "installed_version": r.get("version", ""),
            "vuln_id": r.get("id", ""),
        })
    return findings


def normalize_eslint(path: Path) -> list[dict]:
    """Normalize ESLint security results."""
    try:
        data = json.loads(path.read_text())
    except Exception:
        return []

    if isinstance(data, dict) and data.get("skipped"):
        return []

    if not isinstance(data, list):
        return []

    findings = []
    for file_result in data:
        filepath = file_result.get("filePath", "")
        for msg in file_result.get("messages", []):
            if msg.get("severity", 0) >= 1:
                finding = {
                    "id": f"eslint-{msg.get('ruleId', 'unknown')}",
                    "scanner": "eslint",
                    "severity": "medium" if msg.get("severity") == 2 else "low",
                    "category": "sast",
                    "file": filepath,
                    "line": msg.get("line", 0),
                    "title": msg.get("ruleId", "unknown"),
                    "description": msg.get("message", ""),
                }
                source_line = msg.get("source", "")
                if source_line:
                    finding["source_context"] = {
                        "lines": [[msg.get("line", 0), source_line.rstrip()]],
                        "flagged_line": msg.get("line", 0),
                        "source": "scanner",
                    }
                findings.append(finding)
    return findings


def normalize_mcp_tools(path: Path) -> list[dict]:
    """Normalize MCP Tool Analyzer results."""
    try:
        data = json.loads(path.read_text())
    except Exception:
        return []

    findings = []
    for f in data.get("findings", []):
        finding = {
            "id": f"mcp-{f.get('finding_type', 'unknown')}-{f.get('tool_name', '*')}",
            "scanner": "mcp-tool-analyzer",
            "severity": f.get("severity", "medium"),
            "category": "mcp-tool",
            "file": f.get("file_path", ""),
            "line": f.get("line_number", 0),
            "title": f"{f.get('finding_type', 'UNKNOWN')}: {f.get('tool_name', '*')}",
            "description": f.get("description", ""),
            "evidence": f.get("evidence", ""),
        }
        if f.get("source_context"):
            finding["source_context"] = f["source_context"]
        findings.append(finding)
    return findings


def normalize_skill_analyzer(path: Path) -> list[dict]:
    """Normalize OpenClaw Skill Analyzer results."""
    try:
        data = json.loads(path.read_text())
    except Exception:
        return []

    findings = []
    for f in data.get("findings", []):
        finding = {
            "id": f.get("id", "unknown"),
            "scanner": "skill-analyzer",
            "severity": f.get("severity", "medium"),
            "category": f.get("category", "skill"),
            "file": f.get("file", ""),
            "line": f.get("line", 0),
            "title": f.get("title", ""),
            "description": f.get("description", ""),
            "evidence": f.get("evidence", ""),
        }
        if f.get("source_context"):
            finding["source_context"] = f["source_context"]
        findings.append(finding)
    return findings


def normalize_mcpb_analyzer(path: Path) -> list[dict]:
    """Normalize MCPB Extension Analyzer results."""
    try:
        data = json.loads(path.read_text())
    except Exception:
        return []

    findings = []
    for f in data.get("findings", []):
        finding = {
            "id": f.get("id", "unknown"),
            "scanner": "mcpb-analyzer",
            "severity": f.get("severity", "medium"),
            "category": "mcpb",
            "file": f.get("file", ""),
            "line": f.get("line", 0),
            "title": f.get("title", ""),
            "description": f.get("description", ""),
            "evidence": f.get("evidence", ""),
        }
        if f.get("source_context"):
            finding["source_context"] = f["source_context"]
        findings.append(finding)
    return findings


# ── Helpers ──────────────────────────────────────────────────────

def _map_severity(raw: str) -> str:
    """Normalize severity string to: critical, high, medium, low, info."""
    s = raw.upper().strip()
    if s in ("CRITICAL", "CRIT"):
        return "critical"
    if s in ("HIGH", "ERROR"):
        return "high"
    if s in ("MEDIUM", "MODERATE", "WARNING", "WARN"):
        return "medium"
    if s in ("LOW", "INFO", "NOTE"):
        return "low"
    return "info"


_TEST_DIRS = frozenset({'__tests__', 'test', 'tests', 'spec', 'test_data', 'testdata', 'fixtures'})
_PATTERN_DIRS = frozenset({'patterns', 'rules', 'detectors', 'signatures'})
_TEST_FILE_RE = re.compile(r'(?:^test_|\.test\.|\.spec\.|_test\.)', re.IGNORECASE)


def _compute_file_context(file_path: str) -> dict:
    """Compute structural metadata tags for a finding's file path."""
    if not file_path:
        return {}
    path = PurePosixPath(file_path)
    parts_lower = {p.lower() for p in path.parts}
    in_test = bool(parts_lower & _TEST_DIRS)
    is_test = bool(_TEST_FILE_RE.search(path.name))
    in_pattern = bool(parts_lower & _PATTERN_DIRS)
    return {
        "in_test_dir": in_test,
        "file_is_test": is_test,
        "in_pattern_dir": in_pattern,
        "file_is_pattern_definition": in_pattern and not is_test,
    }


def enrich_source_context(findings: list[dict], source_dir: str) -> None:
    """Read actual source files and add/replace 5-line snippets on findings.

    Mutates findings in place. Skips findings without file/line,
    binary files, and unreadable files.
    """
    source_path = Path(source_dir)
    file_cache: dict[str, list[str] | None] = {}

    for f in findings:
        file_rel = f.get("file", "")
        line = f.get("line", 0)
        if not file_rel or line <= 0:
            continue

        # Cache file contents
        if file_rel not in file_cache:
            full_path = source_path / file_rel
            try:
                raw = full_path.read_bytes()
                # Skip binary files (null byte in first 8KB)
                if b'\x00' in raw[:8192]:
                    file_cache[file_rel] = None
                else:
                    file_cache[file_rel] = raw.decode('utf-8', errors='replace').split('\n')
            except Exception:
                file_cache[file_rel] = None

        lines = file_cache[file_rel]
        if lines is None:
            continue

        # 5-line window (1-based line number)
        start = max(0, line - 1 - 2)
        end = min(len(lines), line + 2)
        f["source_context"] = {
            "lines": [[i + 1, lines[i][:500]] for i in range(start, end)],
            "flagged_line": line,
            "source": "file_read",
        }


# ── Main ─────────────────────────────────────────────────────────

def normalize_all(scan_dir: str, source_dir: str | None = None) -> dict:
    """Normalize all scanner outputs in a directory to unified evidence format."""
    d = Path(scan_dir)

    all_findings = []

    scanner_map = {
        "semgrep.json": normalize_semgrep,
        "semgrep-results.json": normalize_semgrep,
        "bandit.json": normalize_bandit,
        "bandit-results.json": normalize_bandit,
        "trivy.json": normalize_trivy,
        "trivy-results.json": normalize_trivy,
        "gitleaks.json": normalize_gitleaks,
        "gitleaks-results.json": normalize_gitleaks,
        "npm-audit.json": normalize_npm_audit,
        "npm-audit-results.json": normalize_npm_audit,
        "pip-audit.json": normalize_pip_audit,
        "pip-audit-results.json": normalize_pip_audit,
        "eslint.json": normalize_eslint,
        "eslint-results.json": normalize_eslint,
        "mcp-tools.json": normalize_mcp_tools,
        "mcp-tool-analysis.json": normalize_mcp_tools,
        "skill-analysis.json": normalize_skill_analyzer,
        "skill-analysis-results.json": normalize_skill_analyzer,
        "mcpb-analysis.json": normalize_mcpb_analyzer,
        "mcpb-analysis-results.json": normalize_mcpb_analyzer,
    }

    scanners_run = []
    for filename, normalizer in scanner_map.items():
        path = d / filename
        if path.exists():
            findings = normalizer(path)
            all_findings.extend(findings)
            if findings:
                scanners_run.append(filename.replace("-results", "").replace(".json", ""))

    # Pass 1: Deduplicate by id (same scanner, same finding)
    seen_ids = set()
    id_unique = []
    for f in all_findings:
        fid = f.get("id", "")
        if fid not in seen_ids:
            seen_ids.add(fid)
            id_unique.append(f)

    # Pass 2: Cross-scanner deduplication on (file, line, category).
    # When Semgrep and Bandit both flag the same file:line in the same
    # category, keep the finding with the higher severity.
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    location_best = {}  # (file, line, category) -> finding
    for f in id_unique:
        loc = (f.get("file", ""), f.get("line", 0), f.get("category", ""))
        # Skip location-based dedup for findings without a real file:line
        # (e.g. CVE findings where line=0 and file is a package target)
        if loc[1] == 0 and loc[2] in ("cve",):
            location_best[("_no_dedup_", id(f), loc[2])] = f
            continue
        existing = location_best.get(loc)
        if existing is None:
            location_best[loc] = f
        else:
            # Keep the higher severity (lower order number)
            existing_rank = severity_order.get(existing.get("severity", "info"), 5)
            new_rank = severity_order.get(f.get("severity", "info"), 5)
            if new_rank < existing_rank:
                location_best[loc] = f
    unique = list(location_best.values())
    unique.sort(key=lambda f: severity_order.get(f.get("severity", "info"), 5))

    # Enrich with file_context tags
    for f in unique:
        ctx = _compute_file_context(f.get("file", ""))
        if ctx:
            f["file_context"] = ctx

    # Enrich with source code snippets from actual files
    if source_dir:
        enrich_source_context(unique, source_dir)

    # Summary
    by_severity = {}
    by_category = {}
    by_scanner = {}
    for f in unique:
        sev = f.get("severity", "info")
        cat = f.get("category", "other")
        scn = f.get("scanner", "unknown")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_category[cat] = by_category.get(cat, 0) + 1
        by_scanner[scn] = by_scanner.get(scn, 0) + 1

    return {
        "evidence_version": "1.0.0",
        "total_findings": len(unique),
        "by_severity": by_severity,
        "by_category": by_category,
        "by_scanner": by_scanner,
        "scanners_run": list(set(scanners_run)),
        "findings": unique
    }


def main():
    parser = argparse.ArgumentParser(
        description="Normalize scanner outputs to unified evidence format."
    )
    parser.add_argument("scan_dir", help="Directory containing scanner result files")
    parser.add_argument(
        "output", nargs="?", default="/tmp/evidence.json",
        help="Output path (default: /tmp/evidence.json)",
    )
    parser.add_argument(
        "--source-dir",
        help="Path to scanned repo for 5-line source enrichment",
    )
    args = parser.parse_args()

    evidence = normalize_all(args.scan_dir, source_dir=args.source_dir)

    with open(args.output, 'w') as f:
        json.dump(evidence, f, indent=2)

    print(f"Total findings: {evidence['total_findings']}")
    print(f"By severity:    {evidence['by_severity']}")
    print(f"By category:    {evidence['by_category']}")
    print(f"Scanners:       {evidence['scanners_run']}")
    print(f"\nOutput: {args.output}")


if __name__ == "__main__":
    main()
