#!/usr/bin/env python3
"""
Credence ThinkTank Adapter — Interface between Credence pipeline and ThinkTank swarm.

Credence side only. Handles:
  1. build_request()  — assembles scan artifacts into the ThinkTank request schema
  2. process_response() — parses ThinkTank output and updates scan-summary.json

ThinkTank owns its own invocation, agent prompts, and debate logic.
This module only handles serialization/deserialization at the boundary.

Usage (CLI):
    # Build request payload from scan artifacts:
    python thinktank_adapter.py build /path/to/scan-artifacts [--output request.json]

    # Process ThinkTank response back into scan-summary:
    python thinktank_adapter.py process /path/to/response.json /path/to/scan-summary.json

Usage (Python):
    from thinktank_adapter import build_request, process_response
    
    request = build_request(scan_dir="/tmp")
    # ... send request to ThinkTank, get response ...
    updated_summary = process_response(response, scan_summary)
"""

import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path


# ── Request Builder ──────────────────────────────────────────────

def build_request(
    scan_dir: str = "/tmp",
    repo_dir: str | None = None,
    submitter: str | None = None,
) -> dict:
    """
    Assemble the ThinkTank request payload from Credence scan artifacts.

    Reads from the scan directory:
      - scan-summary.json  (required)
      - evidence.json      (optional — normalized findings from report_normalizer)
      - mcp-tool-analysis.json / tool-analysis.json (optional)
      - identity.json      (optional — provenance details)

    Reads from the repo directory (if provided):
      - README.md          (optional)
      - package.json       (optional)
      - pyproject.toml     (optional)

    Returns the complete request dict per THINKTANK_INTERFACE.md schema.
    """
    scan_path = Path(scan_dir)

    # ── Required: scan-summary.json ──
    summary = _load_json(scan_path / "scan-summary.json")
    if summary is None:
        raise FileNotFoundError(f"scan-summary.json not found in {scan_dir}")

    # ── Optional: evidence.json ──
    evidence = _load_json(scan_path / "evidence.json")

    # ── Optional: tool analysis (try both names) ──
    tool_analysis = (
        _load_json(scan_path / "tool-analysis.json")
        or _load_json(scan_path / "mcp-tool-analysis.json")
    )

    # ── Optional: identity.json ──
    identity = _load_json(scan_path / "identity.json")

    # ── Optional: repo context ──
    readme = ""
    package_metadata = None
    if repo_dir:
        repo_path = Path(repo_dir)
        readme = _load_text(repo_path / "README.md")
        package_metadata = (
            _load_json(repo_path / "package.json")
            or _load_toml_raw(repo_path / "pyproject.toml")
        )

    # ── Assemble request ──
    request = {
        "request_id": summary.get("commit_sha", str(uuid.uuid4())),
        "submitted_at": datetime.now(timezone.utc).isoformat(),

        "server": {
            "name": summary.get("server_name", ""),
            "repo_url": summary.get("repo_url", ""),
            "commit_sha": summary.get("commit_sha", ""),
            "readme": readme,
            "package_metadata": package_metadata,
        },

        "provenance": _build_provenance(summary, identity, submitter),

        "scan_results": summary.get("scan_results", {}),

        "evidence": _build_evidence(evidence),

        "tool_analysis": _build_tool_analysis(tool_analysis),

        "hashes": {
            "source_hash": summary.get("source_hash", ""),
            "source_hash_method": summary.get("source_hash_method", "merkle-tree-sha256"),
            "lockfile_hash": summary.get("lockfile_hash", "none"),
            "lockfile_name": summary.get("lockfile_name", "none"),
        },

        "preliminary_score": {
            "trust_score": summary.get("trust_score"),
            "verdict": summary.get("thinktank_verdict", "PENDING"),
        },
    }

    return request


def _build_provenance(summary: dict, identity: dict | None, submitter: str | None) -> dict:
    """Extract provenance fields from scan-summary and identity."""
    identity = identity or {}
    author = summary.get("author_identity", {})

    return {
        "is_fork": summary.get("is_fork", author.get("is_fork", False)),
        "provenance_flags": summary.get(
            "provenance_flags",
            author.get("provenance_flags", [])
        ),
        "repo_owner": author.get("repo_owner", identity.get("repo_owner", "")),
        "submitter": submitter or identity.get("submitter", ""),
        "submitter_is_verified": identity.get("verified", False),
        "account_age_days": identity.get("account_age_days"),
        "contributor_count": identity.get("contributor_count"),
    }


def _build_evidence(evidence: dict | None) -> dict:
    """Normalize evidence into the request schema."""
    if evidence is None:
        return {
            "total_findings": 0,
            "by_severity": {},
            "by_scanner": {},
            "findings": [],
        }

    return {
        "total_findings": sum(evidence.get("by_severity", {}).values()),
        "by_severity": evidence.get("by_severity", {}),
        "by_scanner": evidence.get("by_scanner", {}),
        "findings": evidence.get("findings", []),
    }


def _build_tool_analysis(tool_analysis: dict | None) -> dict:
    """Normalize tool analysis into the request schema."""
    if tool_analysis is None:
        return {
            "tools_analyzed": 0,
            "description_hashes": {},
            "permissions_summary": {},
            "findings": [],
        }

    return {
        "tools_analyzed": tool_analysis.get("tools_analyzed", 0),
        "description_hashes": tool_analysis.get("description_hashes", {}),
        "permissions_summary": tool_analysis.get("permissions_summary", {}),
        "findings": tool_analysis.get("findings", []),
    }


# ── Response Processor ───────────────────────────────────────────

def process_response(response: dict, scan_summary: dict) -> dict:
    """
    Process ThinkTank response and update scan-summary with verdict data.

    Validates required fields, writes ThinkTank output into the attestation
    structure, and strips the _PRELIMINARY suffix from the verdict.

    Returns the updated scan_summary dict (mutates in place and returns).
    """
    # ── Validate required fields ──
    required = ["request_id", "verdict", "confidence", "trust_score"]
    missing = [f for f in required if f not in response]
    if missing:
        raise ValueError(f"ThinkTank response missing required fields: {missing}")

    verdict = response["verdict"]
    if verdict not in ("APPROVED", "CONDITIONAL", "REJECTED"):
        raise ValueError(f"Invalid verdict: {verdict}. Must be APPROVED, CONDITIONAL, or REJECTED.")

    confidence = response["confidence"]
    if not isinstance(confidence, (int, float)) or not (0 <= confidence <= 100):
        raise ValueError(f"Invalid confidence: {confidence}. Must be 0-100.")

    trust_score = response["trust_score"]
    if not isinstance(trust_score, (int, float)) or not (0 <= trust_score <= 100):
        raise ValueError(f"Invalid trust_score: {trust_score}. Must be 0-100.")

    # ── Update scan-summary ──
    scan_summary["thinktank_verdict"] = verdict
    scan_summary["trust_score"] = int(trust_score)

    # ── Write debate data ──
    debate = response.get("debate", {})
    score_adj = response.get("score_adjustment", {})
    flags = response.get("flags", {})

    scan_summary["thinktank_debate"] = {
        "confidence": int(confidence),
        "risk_summary": response.get("risk_summary", ""),
        "agent_count": debate.get("agent_count", 0),
        "rounds": debate.get("rounds", 0),
        "highlights": debate.get("highlights", []),
        "dissenting_opinions": debate.get("dissenting_opinions", []),
        "completed_at": response.get("completed_at", datetime.now(timezone.utc).isoformat()),
    }

    scan_summary["thinktank_score_adjustment"] = {
        "original_score": score_adj.get("original_score", scan_summary.get("trust_score")),
        "adjusted_score": score_adj.get("adjusted_score", int(trust_score)),
        "adjustment_reason": score_adj.get("adjustment_reason", "No adjustment"),
    }

    scan_summary["thinktank_flags"] = {
        "needs_human_review": flags.get("needs_human_review", False),
        "novel_attack_pattern": flags.get("novel_attack_pattern", False),
        "recommended_actions": flags.get("recommended_actions", []),
    }

    return scan_summary


# ── Response Validation (for ThinkTank to self-check) ────────────

RESPONSE_SCHEMA_REQUIRED = {
    "request_id": str,
    "verdict": str,
    "confidence": (int, float),
    "trust_score": (int, float),
    "risk_summary": str,
}

RESPONSE_SCHEMA_OPTIONAL = {
    "completed_at": str,
    "debate": dict,
    "score_adjustment": dict,
    "flags": dict,
}


def validate_response(response: dict) -> list[str]:
    """
    Validate a ThinkTank response against the interface schema.
    Returns list of error strings (empty = valid).

    ThinkTank can call this to self-check before sending.
    """
    errors = []

    # Required fields
    for field, expected_type in RESPONSE_SCHEMA_REQUIRED.items():
        if field not in response:
            errors.append(f"Missing required field: {field}")
        elif not isinstance(response[field], expected_type):
            errors.append(f"Field '{field}' must be {expected_type}, got {type(response[field])}")

    # Verdict values
    if "verdict" in response and response["verdict"] not in ("APPROVED", "CONDITIONAL", "REJECTED"):
        errors.append(f"verdict must be APPROVED|CONDITIONAL|REJECTED, got '{response['verdict']}'")

    # Range checks
    for field in ("confidence", "trust_score"):
        if field in response and isinstance(response[field], (int, float)):
            if not (0 <= response[field] <= 100):
                errors.append(f"{field} must be 0-100, got {response[field]}")

    # Debate structure
    debate = response.get("debate", {})
    if debate:
        highlights = debate.get("highlights", [])
        for i, h in enumerate(highlights):
            if not isinstance(h, dict):
                errors.append(f"debate.highlights[{i}] must be dict")
                continue
            for req_field in ("agent_role", "position", "key_argument"):
                if req_field not in h:
                    errors.append(f"debate.highlights[{i}] missing '{req_field}'")

    return errors


# ── File Helpers ─────────────────────────────────────────────────

def _load_json(path: Path) -> dict | None:
    """Load a JSON file, return None if missing or invalid."""
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def _load_text(path: Path) -> str:
    """Load a text file, return empty string if missing."""
    try:
        return path.read_text(errors="replace")
    except (FileNotFoundError, OSError):
        return ""


def _load_toml_raw(path: Path) -> dict | None:
    """Load pyproject.toml as raw text in a dict (avoids tomllib dependency)."""
    try:
        content = path.read_text()
        return {"_raw": content, "_source": "pyproject.toml"}
    except (FileNotFoundError, OSError):
        return None


# ── CLI ──────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  thinktank_adapter.py build <scan-dir> [--repo <repo-dir>] [--submitter <user>] [--output <file>]")
        print("  thinktank_adapter.py process <response.json> <scan-summary.json>")
        print("  thinktank_adapter.py validate <response.json>")
        sys.exit(1)

    command = sys.argv[1]

    if command == "build":
        scan_dir = sys.argv[2] if len(sys.argv) > 2 else "/tmp"
        repo_dir = None
        submitter = None
        output = None

        # Parse optional flags
        args = sys.argv[3:]
        i = 0
        while i < len(args):
            if args[i] == "--repo" and i + 1 < len(args):
                repo_dir = args[i + 1]
                i += 2
            elif args[i] == "--submitter" and i + 1 < len(args):
                submitter = args[i + 1]
                i += 2
            elif args[i] == "--output" and i + 1 < len(args):
                output = args[i + 1]
                i += 2
            else:
                i += 1

        request = build_request(scan_dir, repo_dir, submitter)

        if output:
            Path(output).write_text(json.dumps(request, indent=2))
            print(f"Request written to {output}")
        else:
            print(json.dumps(request, indent=2))

        # Summary to stderr
        ev = request["evidence"]
        ta = request["tool_analysis"]
        print(
            f"\nPayload: server={request['server']['name']}, "
            f"commit={request['server']['commit_sha'][:8]}, "
            f"findings={ev['total_findings']}, "
            f"tools={ta['tools_analyzed']}, "
            f"preliminary={request['preliminary_score']['verdict']}",
            file=sys.stderr,
        )

    elif command == "process":
        if len(sys.argv) < 4:
            print("Usage: thinktank_adapter.py process <response.json> <scan-summary.json>")
            sys.exit(1)

        response_path = Path(sys.argv[2])
        summary_path = Path(sys.argv[3])

        response = json.loads(response_path.read_text())
        summary = json.loads(summary_path.read_text())

        updated = process_response(response, summary)

        summary_path.write_text(json.dumps(updated, indent=2))
        print(f"Updated {summary_path}")
        print(f"  Verdict: {updated['thinktank_verdict']}")
        print(f"  Score: {updated['trust_score']}")
        print(f"  Confidence: {updated['thinktank_debate']['confidence']}")

        flags = updated.get("thinktank_flags", {})
        if flags.get("needs_human_review"):
            print("  ⚠️  NEEDS HUMAN REVIEW")
        if flags.get("novel_attack_pattern"):
            print("  🔴 NOVEL ATTACK PATTERN DETECTED")

    elif command == "validate":
        if len(sys.argv) < 3:
            print("Usage: thinktank_adapter.py validate <response.json>")
            sys.exit(1)

        response = json.loads(Path(sys.argv[2]).read_text())
        errors = validate_response(response)

        if errors:
            print(f"❌ {len(errors)} validation error(s):")
            for e in errors:
                print(f"  - {e}")
            sys.exit(1)
        else:
            print("✅ Response is valid")

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
