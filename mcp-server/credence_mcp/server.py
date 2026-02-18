"""
Credence MCP Server — Install-time trust verification for MCP servers.

This server connects to the Credence Registry and exposes tools that
AI agents, MCP clients, and developers can use to check whether an
MCP server has been attested before installing or connecting to it.

Usage:
    As MCP server (stdio):   python credence_server.py
    As MCP server (HTTP):    python credence_server.py --transport http --port 8400
"""

import json
import hashlib
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional, List

import httpx
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field, ConfigDict, field_validator

# ── Configuration ────────────────────────────────────────────────

INDEX_URL = os.getenv(
    "CREDENCE_INDEX_URL",
    "https://raw.githubusercontent.com/pestafford/credence-registry/main/registry/index.json"
)

REGISTRY_BASE_URL = os.getenv(
    "CREDENCE_REGISTRY_BASE_URL",
    "https://raw.githubusercontent.com/pestafford/credence-registry/main/registry/"
)

CACHE_TTL_SECONDS = int(os.getenv("CREDENCE_CACHE_TTL", "300"))  # 5 minutes
PUBLIC_KEY_URL = os.getenv(
    "CREDENCE_PUBLIC_KEY_URL",
    "https://raw.githubusercontent.com/pestafford/credence-registry/main/credence_key.pub"
)
VERSION_URL = os.getenv(
    "CREDENCE_VERSION_URL",
    "https://credence.securingthesingularity.com/version.json"
)

# ── Server Init ──────────────────────────────────────────────────

mcp = FastMCP("credence_mcp")

# ── Registry Cache ───────────────────────────────────────────────

_index_cache = None
_index_cache_timestamp = None
_detail_cache = {}
_public_key_cache = None


async def _fetch_index() -> dict:
    """Fetch registry index.json from GitHub, with caching."""
    global _index_cache, _index_cache_timestamp

    now = datetime.now(timezone.utc)
    if (
        _index_cache is not None
        and _index_cache_timestamp is not None
        and (now - _index_cache_timestamp).total_seconds() < CACHE_TTL_SECONDS
    ):
        return _index_cache

    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(INDEX_URL)
        resp.raise_for_status()
        _index_cache = resp.json()
        _index_cache_timestamp = now

    return _index_cache


async def _fetch_server_detail(attestation_file: str) -> dict:
    """Fetch a single per-server attestation file, with caching."""
    if attestation_file in _detail_cache:
        return _detail_cache[attestation_file]

    url = REGISTRY_BASE_URL + attestation_file
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        detail = resp.json()
        _detail_cache[attestation_file] = detail

    return detail


async def _fetch_public_key():
    """Fetch and cache the Credence signing public key."""
    global _public_key_cache
    if _public_key_cache is not None:
        return _public_key_cache

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(PUBLIC_KEY_URL)
            if resp.status_code == 200:
                from credence_mcp.signing import load_public_key_pem
                _public_key_cache = load_public_key_pem(resp.text)
                return _public_key_cache
    except Exception:
        pass
    return None


_version_notice = None
_version_checked = False


async def _check_version() -> str:
    """Check for newer version. Returns notice string or empty. Never throws."""
    global _version_notice, _version_checked
    if _version_checked:
        return _version_notice or ""
    _version_checked = True
    try:
        from credence_mcp import __version__
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(VERSION_URL)
            resp.raise_for_status()
            data = resp.json()
            latest = data.get("mcp_server", __version__)
            if latest != __version__:
                _version_notice = (
                    f"\n\n---\nUpdate available: Credence {latest} "
                    f"(you have {__version__}). "
                    "Run: pip install --upgrade git+https://github.com/"
                    "pestafford/credence-registry.git#subdirectory=mcp-server"
                )
                return _version_notice
    except Exception:
        pass
    _version_notice = ""
    return ""


async def _verify_server_signature(attestation: dict) -> dict:
    """Verify signature on an attestation. Returns status dict."""
    sig = attestation.get("signature")
    if not sig:
        return {"verified": None, "message": "unsigned"}

    pubkey = await _fetch_public_key()
    if pubkey is None:
        return {"verified": None, "message": "could not fetch public key"}

    try:
        from credence_mcp.signing import verify_attestation
        valid, msg = verify_attestation(attestation, pubkey)
        return {"verified": valid, "message": msg}
    except Exception as e:
        return {"verified": None, "message": f"verification error: {str(e)}"}


def _find_server_in_index(index: dict, query: str) -> Optional[dict]:
    """Find a server in the index by ID, repo URL, or name (case-insensitive partial match)."""
    servers = index.get("servers", [])
    query_lower = query.lower().strip().rstrip("/")

    for server in servers:
        # Exact ID match
        if server.get("server_id", "").lower() == query_lower:
            return server

        # Repo URL match (normalize trailing slashes)
        repo = server.get("repo_url", "").lower().rstrip("/")
        if repo == query_lower or repo.endswith(query_lower):
            return server

        # Name match
        if query_lower in server.get("server_name", "").lower():
            return server

    return None


# ── Input Models ─────────────────────────────────────────────────

class CheckServerInput(BaseModel):
    """Input for checking trust status of an MCP server."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    server: str = Field(
        ...,
        description="Repository URL, server ID (owner/repo), or server name to check. "
                    "Examples: 'https://github.com/owner/mcp-server', 'owner/mcp-server', 'Oura Ring MCP'",
        min_length=1,
        max_length=500
    )


class VerifyHashInput(BaseModel):
    """Input for verifying a local source hash against the registry."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    server: str = Field(
        ...,
        description="Repository URL or server ID to verify against",
        min_length=1,
        max_length=500
    )
    source_hash: str = Field(
        ...,
        description="SHA-256 hash of the local source code to verify. "
                    "Generate with: find . -type f -not -path './.git/*' | sort | xargs sha256sum | sha256sum",
        min_length=64,
        max_length=64,
        pattern=r"^[a-f0-9]{64}$"
    )


class HashLocalInput(BaseModel):
    """Input for computing the source hash of a local directory."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    path: str = Field(
        ...,
        description="Absolute path to the local MCP server directory to hash",
        min_length=1,
        max_length=1000
    )


class ListServersInput(BaseModel):
    """Input for listing attested servers."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    limit: int = Field(default=20, description="Maximum results to return", ge=1, le=100)
    offset: int = Field(default=0, description="Offset for pagination", ge=0)
    min_trust_score: Optional[int] = Field(
        default=None,
        description="Only return servers with trust score >= this value (0-100)",
        ge=0, le=100
    )


class ResponseFormat(str, Enum):
    MARKDOWN = "markdown"
    JSON = "json"


# ── Tools ────────────────────────────────────────────────────────

@mcp.tool(
    name="credence_check_server",
    annotations={
        "title": "Check MCP Server Trust Status",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def credence_check_server(params: CheckServerInput) -> str:
    """Check whether an MCP server has a Credence attestation and what its trust status is.

    Use this BEFORE installing or connecting to an MCP server you haven't used before.
    Returns the trust score, provenance flags, scan results, and verdict
    if an attestation exists. If no attestation exists, returns a warning.

    Args:
        params: Server identifier (repo URL, ID, or name)

    Returns:
        Trust status report including score, provenance, and recommendations
    """
    try:
        index = await _fetch_index()
    except Exception as e:
        return json.dumps({
            "status": "error",
            "message": f"Could not reach Credence Registry: {str(e)}. "
                       "The registry may be temporarily unavailable. "
                       "Proceed with caution and verify the server manually."
        })

    match = _find_server_in_index(index, params.server)

    if match is None:
        return json.dumps({
            "status": "not_attested",
            "server_query": params.server,
            "message": "No Credence attestation found for this server. "
                       "This does NOT necessarily mean the server is malicious — "
                       "it means it hasn't been analyzed by Credence yet. "
                       "Evaluate carefully: check the repo owner's history, "
                       "account age, contributor list, and whether it's a fork.",
            "recommendation": "PROCEED_WITH_CAUTION",
            "submit_url": "https://credence.securingthesingularity.com/#submit"
        })

    # Fetch full detail
    try:
        detail = await _fetch_server_detail(match["attestation_file"])
    except Exception as e:
        return json.dumps({
            "status": "error",
            "message": f"Found server in index but could not fetch detail: {str(e)}"
        })

    # Build trust report from detail
    attestation = detail.get("attestation", {})
    provenance = attestation.get("author_identity", {})
    flags = provenance.get("provenance_flags", [])
    trust_score = attestation.get("trust_score")
    verdict = attestation.get("thinktank_verdict", "UNKNOWN")
    scan = attestation.get("scan_summary", {})

    # Determine recommendation
    if verdict == "REJECTED" or trust_score is not None and trust_score < 30:
        recommendation = "DO_NOT_INSTALL"
        risk = "HIGH"
    elif verdict == "CONDITIONAL" or flags or (trust_score is not None and trust_score < 70):
        recommendation = "REVIEW_BEFORE_INSTALLING"
        risk = "MEDIUM"
    else:
        recommendation = "SAFE_TO_INSTALL"
        risk = "LOW"

    # Verify signature
    sig_result = await _verify_server_signature(attestation)

    threat_type = attestation.get("threat_type") or match.get("threat_type")

    result = {
        "status": "attested",
        "server_id": detail.get("server_id"),
        "server_name": detail.get("server_name"),
        "repo_url": detail.get("repo_url"),
        "risk": risk,
        "recommendation": recommendation,
        "trust_score": trust_score,
        "thinktank_verdict": verdict,
        "commit_sha": attestation.get("commit_sha"),
        "source_hash": attestation.get("source_hash"),
        "attested_at": attestation.get("attested_at"),
        "signature": sig_result,
        "provenance": {
            "identity_match": provenance.get("identity_match"),
            "is_fork": provenance.get("is_fork", False),
            "flags": flags
        },
        "scan_summary": scan,
        "attestation_url": detail.get("attestation_url"),
        "message": _build_human_message(risk, recommendation, verdict, flags, trust_score, threat_type)
    }

    if threat_type:
        result["threat_type"] = threat_type

    return json.dumps(result) + await _check_version()


def _build_human_message(risk, recommendation, verdict, flags, trust_score, threat_type=None):
    """Build a natural-language summary for the agent."""
    if recommendation == "DO_NOT_INSTALL":
        if threat_type == "adversarial":
            msg = "Adversarial patterns detected — do not install. "
            msg += "This server exhibits intentionally malicious behavior. "
        elif threat_type == "vulnerability":
            msg = "Critical vulnerabilities detected. "
            msg += "This server has serious security issues that need remediation. "
        else:
            msg = "This server has been analyzed by Credence and is NOT recommended for installation. "
            if verdict == "REJECTED":
                msg += "Adversarial analysis rejected it. "
        if flags:
            msg += f"Provenance flags: {', '.join(flags)}. "
        return msg + "Do not connect to this server."

    if recommendation == "REVIEW_BEFORE_INSTALLING":
        msg = f"This server has a Credence attestation with trust score {trust_score}/100. "
        msg += "Some concerns were identified. "
        if flags:
            msg += f"Provenance flags: {', '.join(flags)}. "
        return msg + "Review the attestation details before proceeding."

    return (
        f"This server has a Credence attestation with trust score {trust_score}/100. "
        f"Verdict: {verdict}. No provenance flags. Safe to install."
    )


@mcp.tool(
    name="credence_verify_hash",
    annotations={
        "title": "Verify Source Hash Against Attestation",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def credence_verify_hash(params: VerifyHashInput) -> str:
    """Verify that the source code you're about to install matches the Credence attestation.

    After cloning or downloading an MCP server, compute its source hash and compare
    against the attested hash. If they don't match, the code has been modified since
    Credence analyzed it — do not install.

    Args:
        params: Server identifier and local source hash

    Returns:
        Verification result: match, mismatch, or no attestation found
    """
    try:
        index = await _fetch_index()
    except Exception as e:
        return json.dumps({
            "status": "error",
            "message": f"Could not reach Credence Registry: {str(e)}"
        })

    match = _find_server_in_index(index, params.server)

    if match is None:
        return json.dumps({
            "status": "not_attested",
            "message": "No attestation found for this server. Cannot verify hash."
        })

    # Fetch detail for full attestation
    try:
        detail = await _fetch_server_detail(match["attestation_file"])
    except Exception as e:
        return json.dumps({
            "status": "error",
            "message": f"Could not fetch server detail: {str(e)}"
        })

    attestation = detail.get("attestation", {})
    attested_hash = attestation.get("source_hash", "")

    if not attested_hash:
        return json.dumps({
            "status": "no_hash",
            "message": "Attestation exists but contains no source hash. Cannot verify."
        })

    # Verify attestation signature before trusting the hash
    sig_result = await _verify_server_signature(attestation)
    if sig_result.get("verified") is False:
        return json.dumps({
            "status": "signature_invalid",
            "message": (
                "ATTESTATION SIGNATURE INVALID. The attestation data cannot be trusted. "
                f"Reason: {sig_result.get('message')}. "
                "Do NOT rely on this hash comparison."
            )
        })

    # Normalize — registry stores as "sha256:abc123..." or just the hash
    attested_clean = attested_hash.replace("sha256:", "").strip().lower()
    local_clean = params.source_hash.strip().lower()

    match_result = attested_clean == local_clean

    return json.dumps({
        "status": "verified" if match_result else "mismatch",
        "match": match_result,
        "local_hash": local_clean,
        "attested_hash": attested_clean,
        "attested_commit": attestation.get("commit_sha"),
        "message": (
            "Source hash matches the Credence attestation. "
            "This code is identical to what was analyzed. Safe to proceed."
        ) if match_result else (
            "SOURCE HASH MISMATCH. The code you have does NOT match what Credence analyzed. "
            "The code may have been modified after attestation — possibly tampered with. "
            "Do NOT install this server. Re-clone from the attested commit or request a new attestation."
        )
    })


@mcp.tool(
    name="credence_hash_local",
    annotations={
        "title": "Compute Source Hash of Local MCP Server",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False
    }
)
async def credence_hash_local(params: HashLocalInput) -> str:
    """Compute the Merkle-tree SHA-256 source hash of a local MCP server directory.

    Use this to generate a hash that can be verified against a Credence attestation.
    This uses the same algorithm as the Credence pipeline: sort all files (excluding .git),
    hash each file, then hash the concatenated hashes.

    Args:
        params: Path to the local directory

    Returns:
        The computed source hash
    """
    target = Path(params.path).resolve()
    if not target.is_dir():
        return json.dumps({
            "status": "error",
            "message": f"Path is not a directory: {params.path}"
        })

    try:
        # Collect all files, excluding .git
        files = sorted(
            str(f.relative_to(target))
            for f in target.rglob("*")
            if f.is_file() and ".git" not in f.parts
        )

        if not files:
            return json.dumps({
                "status": "error",
                "message": "No files found in directory (excluding .git)"
            })

        # Hash each file, then hash the concatenation
        file_hashes = []
        for rel_path in files:
            full_path = target / rel_path
            h = hashlib.sha256()
            with open(full_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            file_hashes.append(f"{h.hexdigest()}  {rel_path}")

        # Final Merkle hash
        combined = "\n".join(file_hashes)
        source_hash = hashlib.sha256(combined.encode()).hexdigest()

        return json.dumps({
            "status": "success",
            "source_hash": source_hash,
            "files_hashed": len(files),
            "path": str(target),
            "message": f"Source hash computed: {source_hash} ({len(files)} files). "
                       "Use credence_verify_hash to check this against the registry."
        })

    except Exception as e:
        return json.dumps({
            "status": "error",
            "message": f"Error computing hash: {str(e)}"
        })


@mcp.tool(
    name="credence_list_servers",
    annotations={
        "title": "List Attested MCP Servers",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def credence_list_servers(params: ListServersInput) -> str:
    """List all MCP servers that have Credence attestations.

    Returns a paginated list of attested servers with their trust scores
    and verdicts. Use min_trust_score to filter for servers above a threshold.

    Args:
        params: Pagination and filter options

    Returns:
        List of attested servers with summary information
    """
    try:
        index = await _fetch_index()
    except Exception as e:
        return json.dumps({
            "status": "error",
            "message": f"Could not reach Credence Registry: {str(e)}"
        })

    servers = index.get("servers", [])

    # Filter by trust score if specified
    if params.min_trust_score is not None:
        servers = [
            s for s in servers
            if (s.get("trust_score") or 0) >= params.min_trust_score
        ]

    total = len(servers)
    page = servers[params.offset:params.offset + params.limit]

    results = []
    for s in page:
        results.append({
            "server_id": s.get("server_id"),
            "server_name": s.get("server_name"),
            "trust_score": s.get("trust_score"),
            "verdict": s.get("thinktank_verdict"),
            "attested_at": s.get("attested_at"),
        })

    return json.dumps({
        "status": "success",
        "total": total,
        "count": len(results),
        "offset": params.offset,
        "servers": results,
        "registry_updated": index.get("updated_at")
    })


# ── Audit Tool ───────────────────────────────────────────────────

@mcp.tool(
    name="credence_audit_config",
    annotations={
        "title": "Audit All Configured MCP Servers",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def credence_audit_config(params: dict = {}) -> str:
    """Audit all MCP servers in the user's Claude Desktop or Claude Code config.

    Reads the local MCP client config, resolves each server to a package/repo,
    and checks every one against the Credence Registry. Reports which servers
    are attested, unattested, or flagged.

    Use this to give the user a complete picture of their MCP server trust posture.

    Returns:
        Audit results for all configured servers
    """
    try:
        from credence_mcp.config_resolver import find_config_file, resolve_all
    except ImportError:
        return json.dumps({
            "status": "error",
            "message": "Config resolver not available. Use the CLI instead: credence audit"
        })

    try:
        config_path, servers = resolve_all()
    except FileNotFoundError as e:
        return json.dumps({
            "status": "error",
            "message": str(e)
        })

    try:
        index = await _fetch_index()
    except Exception as e:
        return json.dumps({
            "status": "error",
            "message": f"Could not reach Credence Registry: {str(e)}"
        })

    results = []
    for server in servers:
        query = server.repo_url or server.package_name or server.name
        match = _find_server_in_index(index, query) if query else None

        if match is None and server.package_name:
            match = _find_server_in_index(index, server.package_name)
        if match is None:
            match = _find_server_in_index(index, server.name)

        entry = {
            "name": server.name,
            "type": server.server_type,
            "package": server.package_name,
            "repo_url": server.repo_url,
            "version": server.version,
        }

        if match:
            score = match.get("trust_score")
            verdict = match.get("thinktank_verdict")
            entry["status"] = "attested"
            entry["trust_score"] = score
            entry["verdict"] = verdict

            if verdict == "REJECTED" or (score is not None and score < 30):
                entry["recommendation"] = "REMOVE"
            elif (score is not None and score < 70):
                entry["recommendation"] = "REVIEW"
            else:
                entry["recommendation"] = "OK"
        else:
            entry["status"] = "not_attested"
            entry["recommendation"] = "SUBMIT_FOR_ANALYSIS"

        if server.resolve_error:
            entry["resolve_error"] = server.resolve_error

        results.append(entry)

    attested = sum(1 for r in results if r["status"] == "attested" and r["recommendation"] == "OK")
    flagged = sum(1 for r in results if r.get("recommendation") in ("REVIEW", "REMOVE"))
    unattested = sum(1 for r in results if r["status"] == "not_attested")

    return json.dumps({
        "status": "success",
        "config_path": str(config_path),
        "total_servers": len(results),
        "attested": attested,
        "flagged": flagged,
        "unattested": unattested,
        "servers": results,
        "message": _build_audit_message(attested, flagged, unattested, len(results))
    }) + await _check_version()


def _build_audit_message(attested, flagged, unattested, total):
    if flagged > 0:
        return (f"Found {flagged} server(s) that need attention. "
                f"{attested}/{total} attested and clean, {unattested} not yet analyzed.")
    if unattested > 0:
        return (f"{attested}/{total} servers attested. {unattested} haven't been analyzed yet. "
                "Consider submitting them for analysis at https://credence.securingthesingularity.com/#submit")
    return f"All {total} configured servers are attested and clean."


# ── Main ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    transport = "stdio"
    port = 8400

    for i, arg in enumerate(sys.argv[1:], 1):
        if arg == "--transport" and i < len(sys.argv) - 1:
            transport = sys.argv[i + 1]
        if arg == "--port" and i < len(sys.argv) - 1:
            port = int(sys.argv[i + 1])

    if transport == "http":
        mcp.run(transport="streamable-http", host="0.0.0.0", port=port)
    else:
        mcp.run(transport="stdio")
