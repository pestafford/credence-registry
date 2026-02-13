#!/usr/bin/env python3
"""
Credence Registry Updater — Build attestation, sign, and update registry.

Writes per-server attestation files under registry/servers/ and maintains
a lightweight registry/index.json. Also generates a backward-compatible
registry.json at the project root.

Usage:
    python registry_update.py /tmp/scan-summary.json registry/ --key-env CREDENCE_SIGNING_KEY
    python registry_update.py /tmp/scan-summary.json registry/ --key /path/to/key.pem

    # Backward compat: if second arg is a .json file, treat parent as project root
    python registry_update.py /tmp/scan-summary.json registry.json --key-env CREDENCE_SIGNING_KEY
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from credence_mcp.signing import sign_attestation_from_pem


def build_attestation(summary: dict) -> dict:
    """Build a registry attestation object from a scored scan-summary."""
    att = {
        "commit_sha": summary.get("commit_sha", ""),
        "source_hash": summary.get("source_hash", ""),
        "source_hash_method": summary.get("source_hash_method", "merkle-tree-sha256"),
        "attested_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "pipeline_version": summary.get("pipeline_version", "0.2.0"),
        "scoring_version": summary.get("scoring_version", "1.0.0"),
        "trust_score": summary.get("trust_score"),
        "trust_dimensions": summary.get("trust_dimensions", {}),
        "thinktank_verdict": summary.get("thinktank_verdict", "PENDING").replace("_PRELIMINARY", ""),
        "author_identity": {
            "repo_owner": summary.get("repo_url", "").rstrip("/").split("/")[-2] if "/" in summary.get("repo_url", "") else "",
            "identity_match": "REPO_OWNER_DIFFERS_FROM_CLAIMED_AUTHOR" not in summary.get("provenance_flags", []),
            "is_fork": summary.get("is_fork", False),
            "provenance_flags": summary.get("provenance_flags", []),
            "maintainer_verified": summary.get("maintainer_verified", False),
            "verify_reason": summary.get("verify_reason", ""),
        },
        "lockfile_name": summary.get("lockfile_name", "none"),
        "lockfile_hash": summary.get("lockfile_hash", "none"),
    }

    threat_type = summary.get("threat_type")
    if threat_type:
        att["threat_type"] = threat_type

    return att


def derive_server_id(summary: dict) -> str:
    """Derive a server_id from repo URL + server_path.

    For monorepos with a server_path, appends the last path segment
    so each server gets a unique ID (e.g. modelcontextprotocol/servers/memory).
    """
    repo_url = summary.get("repo_url", "")
    server_path = summary.get("server_path", "").strip("/")
    # https://github.com/owner/repo -> owner/repo
    parts = repo_url.rstrip("/").split("/")
    if len(parts) >= 2:
        base = f"{parts[-2]}/{parts[-1]}"
        if server_path:
            # Use last segment of path for readability: src/memory -> memory
            suffix = server_path.rstrip("/").split("/")[-1]
            return f"{base}/{suffix}"
        return base
    return summary.get("server_name", "unknown")


def _server_id_to_path(server_id: str, registry_dir: Path) -> Path:
    """Map server_id to its per-server file path."""
    return registry_dir / "servers" / f"{server_id}.json"


def _find_existing_entry(servers: list, server_id: str, repo_url: str,
                         server_path: str) -> int:
    """Find the index of an existing entry for this server, or -1.

    Match priority:
      1. Exact server_id match
      2. Same repo_url with compatible path (handles ID migration)
    """
    # 1. Exact server_id
    for i, s in enumerate(servers):
        if s.get("server_id") == server_id:
            return i

    # 2. Fallback: match by repo_url
    norm_url = repo_url.rstrip("/")
    path_suffix = server_path.rstrip("/").split("/")[-1] if server_path else ""

    repo_matches = [(i, s) for i, s in enumerate(servers)
                    if s.get("repo_url", "").rstrip("/") == norm_url]

    if not repo_matches:
        return -1

    if path_suffix:
        # Monorepo: match entry whose server_id ends with the same suffix,
        # or an entry with no suffix (pre-monorepo scan of this server)
        for i, s in repo_matches:
            sid = s.get("server_id", "")
            sid_suffix = sid.rstrip("/").split("/")[-1] if "/" in sid else ""
            if sid_suffix == path_suffix:
                return i
        # Single entry for this repo with no path suffix -> migration
        if len(repo_matches) == 1:
            existing_id = repo_matches[0][1].get("server_id", "")
            if existing_id.count("/") < 2:
                return repo_matches[0][0]
    else:
        # No path: match the single entry for this repo
        if len(repo_matches) == 1:
            return repo_matches[0][0]

    return -1


def _build_index_entry(server_id: str, server_name: str, canonical_name: str,
                       repo_url: str, attestation: dict) -> dict:
    """Build a lightweight index entry from a full server entry."""
    author = attestation.get("author_identity", {})
    entry = {
        "server_id": server_id,
        "server_name": server_name,
        "canonical_name": canonical_name,
        "repo_url": repo_url,
        "repo_owner": author.get("repo_owner", ""),
        "trust_score": attestation.get("trust_score"),
        "thinktank_verdict": attestation.get("thinktank_verdict", "PENDING"),
        "scoring_version": attestation.get("scoring_version", ""),
        "attested_at": attestation.get("attested_at", ""),
        "attestation_file": f"servers/{server_id}.json",
    }

    threat_type = attestation.get("threat_type")
    if threat_type:
        entry["threat_type"] = threat_type

    return entry


def upsert_registry(index: dict, server_id: str, server_name: str,
                    repo_url: str, attestation: dict, scan_id: str,
                    canonical_name: str = "",
                    server_path: str = "",
                    registry_dir: Path = None) -> dict:
    """Insert or update a server in the index and write its per-server file."""
    servers = index.get("servers", [])

    attestation_url = f"https://github.com/pestafford/credence-registry/tree/main/scan-results/{scan_id}"

    # Build the full server entry (written to per-server file)
    full_entry = {
        "server_id": server_id,
        "server_name": server_name,
        "canonical_name": canonical_name,
        "repo_url": repo_url,
        "attestation": attestation,
        "attestation_url": attestation_url,
    }

    # Build the index entry (lightweight summary)
    index_entry = _build_index_entry(server_id, server_name, canonical_name,
                                     repo_url, attestation)

    # Find existing entry in index
    idx = _find_existing_entry(servers, server_id, repo_url, server_path)
    old_id = None
    if idx >= 0:
        old_id = servers[idx].get("server_id", "")
        servers[idx] = index_entry
        if old_id != server_id:
            print(f"  Migrated server_id: {old_id} -> {server_id}")
    else:
        servers.append(index_entry)

    index["servers"] = servers
    index["updated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Write per-server file
    if registry_dir:
        server_file = _server_id_to_path(server_id, registry_dir)
        server_file.parent.mkdir(parents=True, exist_ok=True)
        server_file.write_text(json.dumps(full_entry, indent=2))
        print(f"  Per-server file: {server_file}")

        # If server_id changed, remove the old per-server file
        if old_id and old_id != server_id:
            old_file = _server_id_to_path(old_id, registry_dir)
            if old_file.exists():
                old_file.unlink()
                print(f"  Removed old file: {old_file}")

    return index


def _build_compat_registry(index: dict, registry_dir: Path) -> dict:
    """Reconstruct a full registry.json from index + per-server files."""
    compat = {
        "schema_version": index.get("schema_version", "0.3.0"),
        "registry_name": index.get("registry_name", ""),
        "registry_url": index.get("registry_url", ""),
        "maintainer": index.get("maintainer", ""),
        "signing_public_key": index.get("signing_public_key", ""),
        "updated_at": index.get("updated_at", ""),
        "servers": [],
    }

    for entry in index.get("servers", []):
        server_file = registry_dir / entry.get("attestation_file", "")
        if server_file.exists():
            full_entry = json.loads(server_file.read_text())
            compat["servers"].append(full_entry)

    return compat


def remove_server(server_id: str, registry_dir: Path, project_root: Path):
    """Remove a server from the registry index and delete its per-server file."""
    index_path = registry_dir / "index.json"
    compat_path = project_root / "registry.json"

    if not index_path.exists():
        print(f"Error: {index_path} not found")
        sys.exit(1)

    index = json.loads(index_path.read_text())
    servers = index.get("servers", [])
    original_count = len(servers)

    # Filter out the server
    servers = [s for s in servers if s.get("server_id") != server_id]

    if len(servers) == original_count:
        print(f"Error: server_id '{server_id}' not found in registry")
        sys.exit(1)

    index["servers"] = servers
    index["updated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Write updated index
    index_path.write_text(json.dumps(index, indent=2))

    # Delete per-server file
    server_file = _server_id_to_path(server_id, registry_dir)
    if server_file.exists():
        server_file.unlink()
        # Clean up empty parent directories
        for parent in server_file.parents:
            if parent == registry_dir / "servers":
                break
            try:
                parent.rmdir()
            except OSError:
                break
        print(f"  Deleted: {server_file}")

    # Regenerate compat registry.json
    compat = _build_compat_registry(index, registry_dir)
    compat_path.write_text(json.dumps(compat, indent=2))

    print(f"\nRemoved '{server_id}' from registry")
    print(f"  Servers remaining: {len(servers)}")
    print(f"  scan-results/ left intact (still counts toward total scans)")


def main():
    # Handle --remove mode
    if len(sys.argv) >= 3 and sys.argv[1] == "--remove":
        server_id = sys.argv[2]
        target_path = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("registry/")

        if target_path.suffix == ".json" or target_path.is_file():
            project_root = target_path.parent
            registry_dir = project_root / "registry"
        else:
            registry_dir = target_path
            project_root = registry_dir.parent

        remove_server(server_id, registry_dir, project_root)
        return

    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <scan-summary.json> <registry-dir|registry.json> [--key <path> | --key-env <var>]")
        print(f"       {sys.argv[0]} --remove <server_id> [registry-dir]")
        sys.exit(1)

    summary_path = Path(sys.argv[1])
    target_path = Path(sys.argv[2])

    # Detect whether target is a directory (new) or a file (backward compat)
    if target_path.suffix == ".json" or target_path.is_file():
        # Old-style: registry.json — derive registry_dir and project_root
        project_root = target_path.parent
        registry_dir = project_root / "registry"
    else:
        # New-style: registry/ directory
        registry_dir = target_path
        project_root = registry_dir.parent

    index_path = registry_dir / "index.json"
    compat_path = project_root / "registry.json"

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

    # Load or create index
    if index_path.exists():
        index = json.loads(index_path.read_text())
    elif compat_path.exists():
        # Bootstrap from existing registry.json
        old_registry = json.loads(compat_path.read_text())
        index = {
            "schema_version": "0.3.0",
            "registry_name": old_registry.get("registry_name", ""),
            "registry_url": old_registry.get("registry_url", ""),
            "maintainer": old_registry.get("maintainer", ""),
            "signing_public_key": old_registry.get("signing_public_key", ""),
            "updated_at": old_registry.get("updated_at", ""),
            "servers": [],
        }
        # Migrate existing entries
        for entry in old_registry.get("servers", []):
            sid = entry.get("server_id", "")
            att = entry.get("attestation", {})
            ie = _build_index_entry(
                sid, entry.get("server_name", ""),
                entry.get("canonical_name", ""),
                entry.get("repo_url", ""), att
            )
            index["servers"].append(ie)
            # Write per-server file
            server_file = _server_id_to_path(sid, registry_dir)
            server_file.parent.mkdir(parents=True, exist_ok=True)
            server_file.write_text(json.dumps(entry, indent=2))
        print(f"Bootstrapped registry/ from {compat_path} ({len(index['servers'])} servers)")
    else:
        index = {
            "schema_version": "0.3.0",
            "registry_name": "Credence MCP Server Registry",
            "registry_url": "https://credence.securingthesingularity.com",
            "maintainer": "Phil Stafford <phil@securingthesingularity.com>",
            "signing_public_key": "",
            "updated_at": "",
            "servers": [],
        }

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
    canonical_name = summary.get("canonical_name", "")
    repo_url = summary.get("repo_url", "")
    server_path = summary.get("server_path", "")
    commit_sha = summary.get("commit_sha", "")
    scan_id = commit_sha[:8] if commit_sha else "unknown"

    # Upsert (writes per-server file + updates index)
    index = upsert_registry(index, server_id, server_name,
                            repo_url, attestation, scan_id,
                            canonical_name=canonical_name,
                            server_path=server_path,
                            registry_dir=registry_dir)

    # Write index
    registry_dir.mkdir(parents=True, exist_ok=True)
    index_path.write_text(json.dumps(index, indent=2))

    # Write backward-compatible registry.json
    compat = _build_compat_registry(index, registry_dir)
    compat_path.write_text(json.dumps(compat, indent=2))

    # Report
    score = summary.get("trust_score", "?")
    verdict = summary.get("thinktank_verdict", "?")
    print(f"\nRegistry updated: {registry_dir}")
    print(f"  Server:  {server_id}")
    print(f"  Commit:  {commit_sha[:12]}")
    print(f"  Score:   {score}/100")
    print(f"  Verdict: {verdict}")
    print(f"  Signed:  {'yes' if pem_data else 'no'}")
    print(f"  Servers in registry: {len(index['servers'])}")
    print(f"  Compat registry.json: {compat_path}")


if __name__ == "__main__":
    main()
