#!/usr/bin/env python3
"""
Credence Trust Score — Three-dimension trust scoring for MCP servers.

Computes Security, Provenance, and Behavioral sub-scores from scan evidence
and provenance flags, then aggregates into a final preliminary verdict.

Methodology: credence-docs/SCORING-METHODOLOGY.md
Framework references: CVSS v4.0, OpenSSF Scorecard, FIPS 199, SLSA v1.0

Usage:
    python trust_score.py /tmp/scan-summary.json [/tmp/evidence.json]

Reads scan-summary.json for provenance flags and scan counts.
Optionally reads evidence.json for severity-weighted scoring (if available).
Writes updated scan-summary.json with trust_dimensions, aggregate_score, and verdict.
"""

import json
import sys
from pathlib import Path


# ── Severity weights (OpenSSF Scorecard risk tier weights) ───────────
SEVERITY_WEIGHT = {
    "critical": 10,
    "high": 7.5,
    "medium": 5,
    "low": 2.5,
    "info": 0,
}

# ── Security dimension ───────────────────────────────────────────────

# Category multipliers applied to each finding's severity weight
CATEGORY_MULTIPLIER = {
    "secrets": 2.0,   # Immediately exploitable, OWASP max ease-of-exploit
    "skill": 1.5,     # Skills-as-installers are direct attack vectors (OpenClaw campaigns)
    "sast": 1.0,      # Baseline code-level findings
    "mcpb": 1.0,      # Bundled code analysis, same risk tier as sast
    "cve": 0.8,       # Often transitive/non-exploitable, per EPSS data
}

# Category caps prevent one noisy scanner from dominating (Socket.dev model)
CATEGORY_CAP = {
    "secrets": 60,
    "skill": 40,    # More headroom for skill-specific attacks (installer pattern)
    "sast": 30,
    "mcpb": 30,     # Same as sast
    "cve": 30,
}

# ── Provenance dimension ─────────────────────────────────────────────

# Flat deductions per flag (calibrated against OURA attack, SLSA-aligned)
# NON_GITHUB_HOST: GitLab, Bitbucket, self-hosted — can't verify fork/account/contributor
#   status via GitHub API. Meaningful gap but not inherently suspicious.
# REPO_API_ERROR: GitHub API call failed — provenance unverified, not a free pass.
PROVENANCE_DEDUCTION = {
    "COORDINATED_FORK_NETWORK": 30,
    "ORIGINAL_AUTHOR_EXCLUDED": 25,
    "REPO_OWNER_DIFFERS_FROM_CLAIMED_AUTHOR": 20,
    "NON_GITHUB_HOST": 20,
    "ACCOUNT_YOUNG_LT_30_DAYS": 20,
    "REPO_API_ERROR": 15,
    "LOCKFILE_HASH_MISMATCH": 15,
    "IS_FORK": 10,
    "ACCOUNT_YOUNG_LT_90_DAYS": 10,
    "NO_LOCKFILE": 5,
    "CONTRIBUTORS_UNAVAILABLE": 5,
    # ACCOUNT_YOUNG_LT_180_DAYS is recorded but not scored
    "ACCOUNT_YOUNG_LT_180_DAYS": 0,
    # Skill / MCPB provenance flags
    "SKILL_NO_MANIFEST": 10,           # No permissions declared — opaque skill
    "SKILL_EXTERNAL_PAYLOAD": 15,      # Install instructions reference external URLs
    "MCPB_NO_SOURCE_REPO": 10,         # Can't verify source against bundle
    "MCPB_SOURCE_MISMATCH": 25,        # Bundled code differs from repo (Phase 2)
}

# Hard-reject patterns (score forced to 0)
def _provenance_hard_reject(flags: list[str]) -> bool:
    """Check for unambiguous attack patterns that force provenance to 0."""
    if "COORDINATED_FORK_NETWORK" in flags:
        return True
    if "IS_FORK" in flags and "ORIGINAL_AUTHOR_EXCLUDED" in flags:
        return True
    return False


# ── Aggregation ──────────────────────────────────────────────────────

# Dimension weights (OpenSSF risk tier assignments)
# Provenance=Critical(10), Behavioral=High(7.5), Security=High(7.5)
DIM_WEIGHT = {
    "provenance": 10,
    "behavioral": 7.5,
    "security": 7.5,
}
DIM_WEIGHT_SUM = sum(DIM_WEIGHT.values())  # 25

# Verdict bands (aligned with CVSS v4.0 severity boundaries: 3.9/6.9/8.9)
VERDICT_BANDS = [
    (90, "VERIFIED_PRELIMINARY"),
    (70, "CONDITIONAL_PRELIMINARY"),
    (40, "FLAGGED_PRELIMINARY"),
    (0, "REJECTED_PRELIMINARY"),
]


# ── Scoring functions ────────────────────────────────────────────────

def score_security(findings: list[dict]) -> tuple[int, dict]:
    """
    Compute Security dimension score from normalized findings.

    Args:
        findings: List of normalized findings from evidence.json.
                  Each must have 'severity' and 'category' fields.

    Returns:
        (score, breakdown) where breakdown shows per-category deductions.
    """
    # Accumulate raw deductions per category
    raw_deductions = {"secrets": 0.0, "skill": 0.0, "sast": 0.0, "mcpb": 0.0, "cve": 0.0}

    for f in findings:
        cat = f.get("category", "")
        sev = f.get("severity", "info")

        # Only score security categories (mcp-tool goes to behavioral)
        if cat not in raw_deductions:
            continue

        weight = SEVERITY_WEIGHT.get(sev, 0)
        multiplier = CATEGORY_MULTIPLIER.get(cat, 1.0)
        raw_deductions[cat] += weight * multiplier

    # Apply caps
    capped = {}
    for cat, raw in raw_deductions.items():
        cap = CATEGORY_CAP.get(cat, 100)
        capped[cat] = min(raw, cap)

    total_deduction = sum(capped.values())
    score = max(0, round(100 - total_deduction))

    breakdown = {
        "raw_deductions": {k: round(v, 1) for k, v in raw_deductions.items()},
        "capped_deductions": {k: round(v, 1) for k, v in capped.items()},
        "total_deduction": round(total_deduction, 1),
    }

    return score, breakdown


def score_security_from_counts(scan_results: dict) -> tuple[int, dict]:
    """
    Fallback: compute Security dimension from finding counts when
    evidence.json is not available. Uses medium severity as default
    since per-finding severity is unknown.

    This is less accurate than score_security() but allows scoring
    when only scan-summary.json exists (e.g., evidence.json not yet wired).
    """
    raw_deductions = {"secrets": 0.0, "skill": 0.0, "sast": 0.0, "mcpb": 0.0, "cve": 0.0}

    # Map scan_results fields to categories (all assumed medium severity)
    count_map = {
        "gitleaks_secrets": ("secrets", "critical"),  # secrets are always critical
        "semgrep_findings": ("sast", "medium"),
        "bandit_findings": ("sast", "medium"),
        "eslint_security_issues": ("sast", "medium"),
        "skill_critical": ("skill", "high"),
        "skill_warnings": ("skill", "medium"),
        "mcpb_critical": ("mcpb", "high"),
        "mcpb_warnings": ("mcpb", "medium"),
        "trivy_vulnerabilities": ("cve", "medium"),
        "npm_audit_vulnerabilities": ("cve", "medium"),
        "pip_audit_vulnerabilities": ("cve", "medium"),
    }

    for field, (cat, default_sev) in count_map.items():
        count = scan_results.get(field, 0)
        if not isinstance(count, (int, float)):
            continue
        weight = SEVERITY_WEIGHT.get(default_sev, 5)
        multiplier = CATEGORY_MULTIPLIER.get(cat, 1.0)
        raw_deductions[cat] += count * weight * multiplier

    capped = {}
    for cat, raw in raw_deductions.items():
        cap = CATEGORY_CAP.get(cat, 100)
        capped[cat] = min(raw, cap)

    total_deduction = sum(capped.values())
    score = max(0, round(100 - total_deduction))

    breakdown = {
        "mode": "count-based (no evidence.json)",
        "raw_deductions": {k: round(v, 1) for k, v in raw_deductions.items()},
        "capped_deductions": {k: round(v, 1) for k, v in capped.items()},
        "total_deduction": round(total_deduction, 1),
    }

    return score, breakdown


def score_provenance(flags: list[str], tool_type: str = "") -> tuple[int, dict]:
    """
    Compute Provenance dimension score from provenance flags.

    Args:
        flags: List of provenance flag strings from scan-summary.json.
        tool_type: Tool type from scan-summary (e.g. "openclaw-skill").

    Returns:
        (score, breakdown) with deduction details and override status.
    """
    # Check hard-reject overrides first
    if _provenance_hard_reject(flags):
        override_reason = []
        if "COORDINATED_FORK_NETWORK" in flags:
            override_reason.append("COORDINATED_FORK_NETWORK detected")
        if "IS_FORK" in flags and "ORIGINAL_AUTHOR_EXCLUDED" in flags:
            override_reason.append("IS_FORK + ORIGINAL_AUTHOR_EXCLUDED (SmartLoader pattern)")

        return 0, {
            "hard_reject": True,
            "override_reason": override_reason,
            "flags_present": flags,
        }

    # Mutual exclusivity: LT_30 takes precedence over LT_90
    active_flags = list(flags)
    if "ACCOUNT_YOUNG_LT_30_DAYS" in active_flags and "ACCOUNT_YOUNG_LT_90_DAYS" in active_flags:
        active_flags.remove("ACCOUNT_YOUNG_LT_90_DAYS")

    # Waive NO_LOCKFILE for OpenClaw skills — monorepo skills never have lockfiles
    if tool_type == "openclaw-skill" and "NO_LOCKFILE" in active_flags:
        active_flags.remove("NO_LOCKFILE")

    # Sum deductions
    deductions = {}
    for flag in active_flags:
        ded = PROVENANCE_DEDUCTION.get(flag, 0)
        if ded > 0:
            deductions[flag] = ded

    total_deduction = sum(deductions.values())
    score = max(0, round(100 - total_deduction))

    breakdown = {
        "hard_reject": False,
        "flags_present": flags,
        "deductions": deductions,
        "total_deduction": total_deduction,
    }

    return score, breakdown


def score_behavioral(findings: list[dict]) -> tuple[int, dict]:
    """
    Compute Behavioral dimension score from MCP tool analysis findings.

    Args:
        findings: List of normalized findings from evidence.json where
                  category == 'mcp-tool'.

    Returns:
        (score, breakdown) with per-finding deductions.
    """
    mcp_findings = [f for f in findings if f.get("category") == "mcp-tool"]

    total_deduction = 0.0
    finding_impacts = []

    for f in mcp_findings:
        sev = f.get("severity", "info")
        weight = SEVERITY_WEIGHT.get(sev, 0)
        total_deduction += weight
        finding_impacts.append({
            "title": f.get("title", ""),
            "severity": sev,
            "impact": weight,
        })

    score = max(0, round(100 - total_deduction))

    breakdown = {
        "mcp_findings_count": len(mcp_findings),
        "finding_impacts": finding_impacts,
        "total_deduction": round(total_deduction, 1),
    }

    return score, breakdown


def score_behavioral_from_counts(scan_results: dict) -> tuple[int, dict]:
    """
    Fallback: compute Behavioral dimension from MCP tool warning/critical
    counts when evidence.json is not available.
    """
    # mcp_tool_critical maps to high severity (7.5) per analyzer classification
    # mcp_tool_warnings maps to medium severity (5)
    critical_count = scan_results.get("mcp_tool_critical", 0) or 0
    warning_count = scan_results.get("mcp_tool_warnings", 0) or 0

    critical_deduction = critical_count * SEVERITY_WEIGHT["high"]
    warning_deduction = warning_count * SEVERITY_WEIGHT["medium"]
    total_deduction = critical_deduction + warning_deduction

    score = max(0, round(100 - total_deduction))

    breakdown = {
        "mode": "count-based (no evidence.json)",
        "mcp_tool_critical": critical_count,
        "mcp_tool_warnings": warning_count,
        "total_deduction": round(total_deduction, 1),
    }

    return score, breakdown


def aggregate(security: int, provenance: int, behavioral: int) -> tuple[int, str, dict]:
    """
    Combine three dimension scores into aggregate score and verdict.

    Applies weighted average (OpenSSF tier weights) then FIPS 199
    hard overrides (weakest dimension caps the aggregate).

    Returns:
        (aggregate_score, verdict, breakdown)
    """
    # Weighted average
    raw_aggregate = (
        provenance * DIM_WEIGHT["provenance"]
        + behavioral * DIM_WEIGHT["behavioral"]
        + security * DIM_WEIGHT["security"]
    ) / DIM_WEIGHT_SUM

    aggregate_score = round(raw_aggregate)
    override_applied = None

    # Hard overrides (FIPS 199 high water mark — most severe first)
    if provenance == 0:
        aggregate_score = 0
        override_applied = "provenance_hard_reject"
    elif min(security, provenance, behavioral) <= 39:
        if aggregate_score > 39:
            aggregate_score = 39
            override_applied = f"dimension_cap_39 (min={min(security, provenance, behavioral)})"
    elif min(security, provenance, behavioral) <= 69:
        if aggregate_score > 69:
            aggregate_score = 69
            override_applied = f"dimension_cap_69 (min={min(security, provenance, behavioral)})"

    # Determine verdict
    verdict = "REJECTED_PRELIMINARY"
    for threshold, v in VERDICT_BANDS:
        if aggregate_score >= threshold:
            verdict = v
            break

    breakdown = {
        "raw_aggregate": round(raw_aggregate, 1),
        "override_applied": override_applied,
        "dimension_weights": dict(DIM_WEIGHT),
    }

    return aggregate_score, verdict, breakdown


# ── Main entry point ─────────────────────────────────────────────────

def compute_trust_score(summary: dict, evidence: dict | None = None) -> dict:
    """
    Compute the full trust score from scan-summary and optional evidence.

    Args:
        summary: Parsed scan-summary.json
        evidence: Parsed evidence.json (optional; enables severity-weighted scoring)

    Returns:
        Dict with trust_dimensions, aggregate_score, verdict, and breakdowns.
    """
    flags = summary.get("provenance_flags", [])
    scan_results = summary.get("scan_results", {})
    tool_type = summary.get("tool_type", "")

    findings = evidence.get("findings", []) if evidence else []

    # Security dimension
    if findings:
        security_score, security_breakdown = score_security(findings)
    else:
        security_score, security_breakdown = score_security_from_counts(scan_results)

    # Provenance dimension
    provenance_score, provenance_breakdown = score_provenance(flags, tool_type)

    # Behavioral dimension
    if findings:
        behavioral_score, behavioral_breakdown = score_behavioral(findings)
    else:
        behavioral_score, behavioral_breakdown = score_behavioral_from_counts(scan_results)

    # Aggregate
    aggregate_score, verdict, aggregate_breakdown = aggregate(
        security_score, provenance_score, behavioral_score
    )

    return {
        "trust_dimensions": {
            "security": security_score,
            "provenance": provenance_score,
            "behavioral": behavioral_score,
        },
        "aggregate_score": aggregate_score,
        "thinktank_verdict": verdict,
        "scoring_version": "1.0.0",
        "breakdowns": {
            "security": security_breakdown,
            "provenance": provenance_breakdown,
            "behavioral": behavioral_breakdown,
            "aggregate": aggregate_breakdown,
        },
    }


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <scan-summary.json> [evidence.json]")
        print()
        print("Computes trust score and writes results back to scan-summary.json.")
        print("If evidence.json is provided, uses severity-weighted scoring.")
        print("Otherwise falls back to count-based scoring from scan-summary.json.")
        sys.exit(1)

    summary_path = Path(sys.argv[1])
    evidence_path = Path(sys.argv[2]) if len(sys.argv) > 2 else None

    # Load scan-summary
    summary = json.loads(summary_path.read_text())

    # Load evidence (optional)
    evidence = None
    if evidence_path and evidence_path.exists():
        evidence = json.loads(evidence_path.read_text())
        print(f"Loaded evidence: {evidence.get('total_findings', 0)} findings")
    else:
        print("No evidence.json — using count-based scoring (less accurate)")

    # Compute
    result = compute_trust_score(summary, evidence)

    # Merge into summary
    summary["trust_dimensions"] = result["trust_dimensions"]
    summary["trust_score"] = result["aggregate_score"]
    summary["thinktank_verdict"] = result["thinktank_verdict"]
    summary["scoring_version"] = result["scoring_version"]
    summary["scoring_breakdowns"] = result["breakdowns"]

    # Write back
    summary_path.write_text(json.dumps(summary, indent=2))

    # Report
    dims = result["trust_dimensions"]
    print(f"\nTrust Dimensions:")
    print(f"  Security:   {dims['security']}/100")
    print(f"  Provenance: {dims['provenance']}/100")
    print(f"  Behavioral: {dims['behavioral']}/100")
    print(f"\nAggregate:    {result['aggregate_score']}/100")
    print(f"Verdict:      {result['thinktank_verdict']}")

    agg = result["breakdowns"]["aggregate"]
    if agg.get("override_applied"):
        print(f"Override:     {agg['override_applied']}")

    print(f"\nUpdated: {summary_path}")


if __name__ == "__main__":
    main()
