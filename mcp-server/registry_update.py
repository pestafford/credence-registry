#!/usr/bin/env python3
"""
Credence Registry Updater — Build attestation, sign, and update registry.json.

Takes a scored scan-summary.json, builds a registry attestation entry,
signs it with the Credence Ed25519 key, and upserts it into registry.json.

Usage:
    python registry_update.py /tmp/scan-summary.json registry.json --key /path/to/key.pem
    python registry_update.py /tmp/scan-summary.json registry.json --key-env CREDENCE_SIGNING_KEY
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from signing import sign_attestation_from_pem


def build_attestation(summary: dict) -> dict:
    """Build a registry attestation object from a scored scan-summary."""
    scan_results = summary.get("scan_results", {})

    return {
        "commit_sha": summary.get("commit_sha", ""),
        "source_hash": summary.get("source_hash", ""),
        "source_hash_method": summary.get("source_hash_method", "merkle-tree-sha256"),
        "attested_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "pipeline_version": summary.get("pipeline_version", "0.2.0"),
        "scoring_version": summary.get("scoring_version", "1.0.0"),
        "trust_score": summary.get("trust_score"),
        "trust_dimensions": summary.get("trust_dimensions", {}),
        "thinktank_verdict": summary.get("thinktank_verdict", "PENDING"),
        "author_identity": {
            "repo_owner": summary.get("repo_url", "").rstrip("/").split("/")[-2] if "/" in summary.get("repo_url", "") else "",
            "identity_match": "REPO_OWNER_DIFFERS_FROM_CLAIMED_AUTHOR" not in summary.get("provenance_flags", []),
            "is_fork": summary.get("is_fork", False),
            "provenance_flags": summary.get("provenance_flags", []),
        },
        "scan_summary": {
            "semgrep_findings": scan_results.get("semgrep_findings", 0),
            "bandit_findings": scan_results.get("bandit_findings", 0),
            "trivy_vulnerabilities": scan_results.get("trivy_vulnerabilities", 0),
            "gitleaks_secrets": scan_results.get("gitleaks_secrets", 0),
            "mcp_tool_warnings": scan_results.get("mcp_tool_warnings", 0),
            "mcp_tool_critical": scan_results.get("mcp_tool_critical", 0),
        },
        "lockfile_name": summary.get("lockfile_name", "none"),
        "lockfile_hash": summary.get("lockfile_hash", "none"),
    }


def derive_server_id(summary: dict) -> str:
    """Derive a server_id from repo URL: owner/repo-name format."""
    repo_url = summary.get("repo_url", "")
    # https://github.com/owner/repo -> owner/repo
    parts = repo_url.rstrip("/").split("/")
    if len(parts) >= 2:
        return f"{parts[-2]}/{parts[-1]}"
    return summary.get("server_name", "unknown")


def upsert_registry(registry: dict, server_id: str, server_name: str,
                    repo_url: str, attestation: dict, scan_id: str) -> dict:
    """Insert or update a server entry in the registry."""
    servers = registry.get("servers", [])

    attestation_url = f"https://github.com/pestafford/credence-registry/tree/main/scan-results/{scan_id}"

    # Build the server entry
    entry = {
        "server_id": server_id,
        "server_name": server_name,
        "repo_url": repo_url,
        "attestation": attestation,
        "attestation_url": attestation_url,
    }

    # Check if server already exists (update vs insert)
    found = False
    for i, s in enumerate(servers):
        if s.get("server_id") == server_id:
            servers[i] = entry
            found = True
            break

    if not found:
        servers.append(entry)

    registry["servers"] = servers
    registry["updated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return registry


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <scan-summary.json> <registry.json> [--key <path> | --key-env <var>]")
        sys.exit(1)

    summary_path = Path(sys.argv[1])
    registry_path = Path(sys.argv[2])

    # Parse key source
    pem_data = None
    i = 3
    while i < len(sys.argv):
        if sys.argv[i] == "--key" and i + 1 < len(sys.argv):
            pem_data = Path(sys.argv[i + 1]).read_text()
            i += 2
        elif sys.argv[i] == "--key-env" and i + 1 < len(sys.argv):
            env_var = sys.argv[i + 1]
            pem_data = os.environ.get(env_var)
            if not pem_data:
                print(f"Error: environment variable {env_var} is not set")
                sys.exit(1)
            i += 2
        else:
            i += 1

    # Load inputs
    summary = json.loads(summary_path.read_text())
    registry = json.loads(registry_path.read_text())

    # Build attestation
    attestation = build_attestation(summary)

    # Sign if key provided
    if pem_data:
        attestation = sign_attestation_from_pem(attestation, pem_data)
        print(f"Attestation signed (ed25519)")
    else:
        print("Warning: no signing key provided — attestation will be unsigned")

    # Derive identifiers
    server_id = derive_server_id(summary)
    server_name = summary.get("server_name", server_id)
    repo_url = summary.get("repo_url", "")
    commit_sha = summary.get("commit_sha", "")
    scan_id = commit_sha[:8] if commit_sha else "unknown"

    # Upsert
    registry = upsert_registry(registry, server_id, server_name,
                               repo_url, attestation, scan_id)

    # Write
    registry_path.write_text(json.dumps(registry, indent=2))

    # Report
    score = summary.get("trust_score", "?")
    verdict = summary.get("thinktank_verdict", "?")
    print(f"\nRegistry updated: {registry_path}")
    print(f"  Server:  {server_id}")
    print(f"  Commit:  {commit_sha[:12]}")
    print(f"  Score:   {score}/100")
    print(f"  Verdict: {verdict}")
    print(f"  Signed:  {'yes' if pem_data else 'no'}")
    print(f"  Servers in registry: {len(registry['servers'])}")


if __name__ == "__main__":
    main()
