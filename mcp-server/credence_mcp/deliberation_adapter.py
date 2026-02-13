#!/usr/bin/env python3
"""
Credence Deliberation Adapter — Interface between Credence pipeline and deliberation-mcp server.

Credence side only. Handles:
  1. build_request()    — assembles scan artifacts into the deliberation request schema
  2. invoke()           — calls the deliberate_credence MCP tool via subprocess stdio
  3. process_response() — parses deliberation output and updates scan-summary.json

The deliberation-mcp server owns its own agent prompts, debate logic, and LLM calls.
This module only handles serialization/deserialization at the boundary.

Usage (CLI):
    # Build request payload from scan artifacts:
    python -m credence_mcp.deliberation_adapter build /path/to/scan-artifacts [--output request.json]

    # Run full pipeline: build request, invoke deliberation server, process response:
    python -m credence_mcp.deliberation_adapter run /path/to/scan-artifacts /path/to/scan-summary.json [--repo <repo-dir>] [--timeout 300]

    # Process a pre-existing deliberation response back into scan-summary:
    python -m credence_mcp.deliberation_adapter process /path/to/response.json /path/to/scan-summary.json

    # Validate a deliberation response:
    python -m credence_mcp.deliberation_adapter validate /path/to/response.json

Usage (Python):
    from credence_mcp.deliberation_adapter import build_request, invoke, process_response

    request = build_request(scan_dir="/tmp")
    response = invoke(request)  # calls deliberate_credence via MCP stdio
    updated_summary = process_response(response, scan_summary)
"""

import json
import queue
import subprocess
import sys
import threading
import time
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
    Assemble the deliberation request payload from Credence scan artifacts.

    Reads from the scan directory:
      - scan-summary.json  (required)
      - evidence.json      (optional — normalized findings from report_normalizer)
      - mcp-tool-analysis.json / tool-analysis.json (optional)
      - identity.json      (optional — provenance details)

    Reads from the repo directory (if provided):
      - README.md          (optional)
      - package.json       (optional)
      - pyproject.toml     (optional)

    Returns the complete request dict per the deliberation-mcp integration spec.
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
    package_metadata = ""
    if repo_dir:
        repo_path = Path(repo_dir)
        readme = _load_text(repo_path / "README.md")
        raw = (
            _load_json(repo_path / "package.json")
            or _load_toml_raw(repo_path / "pyproject.toml")
        )
        if raw:
            package_metadata = json.dumps(raw) if isinstance(raw, dict) else str(raw)

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
        "account_age_days": identity.get("account_age_days") or 0,
        "contributor_count": identity.get("contributor_count") or 0,
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


# ── MCP Invocation ───────────────────────────────────────────────

def invoke(
    request: dict,
    server_command: list[str] | None = None,
    timeout: int = 300,
) -> dict:
    """
    Call the deliberate_credence tool on the deliberation-mcp server via stdio.

    Uses the MCP JSON-RPC protocol over stdin/stdout with proper sequencing:
      1. Send initialize request, wait for response
      2. Send initialized notification
      3. Send tools/call with deliberate_credence, wait for response
      4. Parse the deliberation result

    Args:
        request: The deliberation request payload (from build_request).
        server_command: Command to start the deliberation server.
                       Defaults to ["deliberation-mcp"].
        timeout: Seconds to wait for the deliberation to complete.
                 A 5-agent, 5-round deliberation typically takes 15-25 LLM calls.

    Returns:
        The parsed deliberation response dict.

    Raises:
        TimeoutError: If deliberation exceeds timeout.
        RuntimeError: If the server returns an error or invalid response.
    """
    if server_command is None:
        server_command = ["deliberation-mcp"]

    # Start the MCP server as a subprocess
    proc = subprocess.Popen(
        server_command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,  # line-buffered
    )

    # Background thread reads stdout lines into a queue
    responses: queue.Queue[str] = queue.Queue()

    def _reader():
        try:
            for line in proc.stdout:
                line = line.strip()
                if line:
                    responses.put(line)
        except (ValueError, OSError):
            pass  # pipe closed

    reader_thread = threading.Thread(target=_reader, daemon=True)
    reader_thread.start()

    def _send(msg: dict):
        proc.stdin.write(json.dumps(msg) + "\n")
        proc.stdin.flush()

    def _wait_for(msg_id: int, step_timeout: float) -> dict:
        """Read lines from queue until we get a JSON-RPC response with the given id."""
        deadline = time.monotonic() + step_timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"Timed out waiting for response id={msg_id} after {step_timeout}s"
                )
            try:
                line = responses.get(timeout=min(remaining, 1.0))
            except queue.Empty:
                if proc.poll() is not None:
                    raise RuntimeError(
                        f"Deliberation server exited unexpectedly (code {proc.returncode})"
                    )
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue  # skip non-JSON lines (logging, etc.)
            if msg.get("id") == msg_id:
                return msg
            # else: notification or different id — keep reading

    try:
        # Step 1: Initialize
        _send({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "credence-pipeline", "version": "0.2.0"},
            },
        })
        init_resp = _wait_for(msg_id=1, step_timeout=15)
        if "error" in init_resp:
            raise RuntimeError(f"Initialize failed: {init_resp['error']}")

        # Step 2: Send initialized notification (no response expected)
        _send({"jsonrpc": "2.0", "method": "notifications/initialized"})

        # Step 3: Call deliberate_credence tool
        _send({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "deliberate_credence",
                "arguments": {
                    "payload": json.dumps(request),
                },
            },
        })
        tool_resp = _wait_for(msg_id=2, step_timeout=timeout)

        if "error" in tool_resp:
            raise RuntimeError(
                f"Deliberation server error: {tool_resp['error'].get('message', tool_resp['error'])}"
            )

        # Step 4: Extract the tool result
        result = tool_resp.get("result", {})
        content = result.get("content", [])
        for item in content:
            if item.get("type") == "text":
                text = item["text"]
                if not text:
                    raise RuntimeError("Deliberation returned empty text content")
                try:
                    return json.loads(text)
                except json.JSONDecodeError:
                    # The server may return the result directly as a dict
                    # rather than as a JSON string, or it may be plain text
                    raise RuntimeError(
                        f"Deliberation returned non-JSON text ({len(text)} chars): "
                        f"{text[:500]}"
                    )

        # No text content — dump the full response for debugging
        raise RuntimeError(
            f"No text content in deliberation response. "
            f"Full result: {json.dumps(tool_resp)[:1000]}"
        )

    except TimeoutError:
        raise
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


# ── Response Processor ───────────────────────────────────────────

def process_response(response: dict, scan_summary: dict) -> dict:
    """
    Process deliberation response and update scan-summary with verdict data.

    Validates required fields, writes deliberation output into the attestation
    structure, and strips the _PRELIMINARY suffix from the verdict.

    Returns the updated scan_summary dict (mutates in place and returns).
    """
    # ── Validate required fields ──
    required = ["request_id", "verdict", "confidence", "trust_score"]
    missing = [f for f in required if f not in response]
    if missing:
        raise ValueError(f"Deliberation response missing required fields: {missing}")

    verdict = response["verdict"]
    if verdict not in ("APPROVED", "CONDITIONAL", "REJECTED"):
        raise ValueError(f"Invalid verdict: {verdict}. Must be APPROVED, CONDITIONAL, or REJECTED.")

    confidence = response["confidence"]
    if not isinstance(confidence, (int, float)) or not (0 <= confidence <= 100):
        raise ValueError(f"Invalid confidence: {confidence}. Must be 0-100.")

    trust_score = response["trust_score"]
    if not isinstance(trust_score, (int, float)) or not (0 <= trust_score <= 100):
        raise ValueError(f"Invalid trust_score: {trust_score}. Must be 0-100.")

    # ── Update scan-summary (verdict + score only) ──
    # Deliberation detail (debate, score_adjustment, flags) stays in the
    # deliberation-mcp repo via .deliberations/ push — never in scan-summary.
    scan_summary["thinktank_verdict"] = verdict
    scan_summary["trust_score"] = int(trust_score)

    return scan_summary


# ── Response Validation ──────────────────────────────────────────

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
    Validate a deliberation response against the interface schema.
    Returns list of error strings (empty = valid).
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

        # Spec guarantees dissenting_opinions is never empty
        dissenting = debate.get("dissenting_opinions", [])
        if not dissenting:
            errors.append("debate.dissenting_opinions must not be empty (REQ-502)")

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
        print("  deliberation_adapter build <scan-dir> [--repo <repo-dir>] [--submitter <user>] [--output <file>]")
        print("  deliberation_adapter run <scan-dir> <scan-summary.json> [--repo <repo-dir>] [--timeout 300] [--server-cmd <cmd>]")
        print("  deliberation_adapter process <response.json> <scan-summary.json>")
        print("  deliberation_adapter validate <response.json>")
        sys.exit(1)

    command = sys.argv[1]

    if command == "build":
        _cli_build()

    elif command == "run":
        _cli_run()

    elif command == "process":
        _cli_process()

    elif command == "validate":
        _cli_validate()

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


def _cli_build():
    scan_dir = sys.argv[2] if len(sys.argv) > 2 else "/tmp"
    repo_dir = None
    submitter = None
    output = None

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


def _cli_run():
    """Build request, invoke deliberation server, process response — all in one."""
    if len(sys.argv) < 4:
        print("Usage: deliberation_adapter run <scan-dir> <scan-summary.json> [--repo <repo-dir>] [--timeout 300] [--server-cmd <cmd>]")
        sys.exit(1)

    scan_dir = sys.argv[2]
    summary_path = Path(sys.argv[3])
    repo_dir = None
    timeout = 300
    server_cmd = None

    args = sys.argv[4:]
    i = 0
    while i < len(args):
        if args[i] == "--repo" and i + 1 < len(args):
            repo_dir = args[i + 1]
            i += 2
        elif args[i] == "--timeout" and i + 1 < len(args):
            timeout = int(args[i + 1])
            i += 2
        elif args[i] == "--server-cmd" and i + 1 < len(args):
            server_cmd = args[i + 1].split()
            i += 2
        else:
            i += 1

    summary = json.loads(summary_path.read_text())

    # Step 1: Build request
    print("Building deliberation request...", file=sys.stderr)
    request = build_request(scan_dir, repo_dir)

    # Step 2: Invoke deliberation server
    print("Invoking deliberation server...", file=sys.stderr)
    try:
        response = invoke(request, server_command=server_cmd, timeout=timeout)
    except (TimeoutError, RuntimeError) as e:
        print(f"Deliberation failed: {e}", file=sys.stderr)
        print("Falling back to preliminary score.", file=sys.stderr)
        # Leave _PRELIMINARY suffix intact — no update
        summary_path.write_text(json.dumps(summary, indent=2))
        sys.exit(0)

    # Step 3: Process response
    print("Processing deliberation response...", file=sys.stderr)
    updated = process_response(response, summary)

    summary_path.write_text(json.dumps(updated, indent=2))
    print(f"Updated {summary_path}")
    print(f"  Verdict: {updated['thinktank_verdict']}")
    print(f"  Score: {updated['trust_score']}")
    print(f"  Confidence: {response.get('confidence', '?')}")

    flags = response.get("flags", {})
    if flags.get("needs_human_review"):
        print("  NEEDS HUMAN REVIEW")
    if flags.get("novel_attack_pattern"):
        print("  NOVEL ATTACK PATTERN DETECTED")


def _cli_process():
    if len(sys.argv) < 4:
        print("Usage: deliberation_adapter process <response.json> <scan-summary.json>")
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
    print(f"  Confidence: {response.get('confidence', '?')}")

    flags = response.get("flags", {})
    if flags.get("needs_human_review"):
        print("  NEEDS HUMAN REVIEW")
    if flags.get("novel_attack_pattern"):
        print("  NOVEL ATTACK PATTERN DETECTED")


def _cli_validate():
    if len(sys.argv) < 3:
        print("Usage: deliberation_adapter validate <response.json>")
        sys.exit(1)

    response = json.loads(Path(sys.argv[2]).read_text())
    errors = validate_response(response)

    if errors:
        print(f"{len(errors)} validation error(s):")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)
    else:
        print("Response is valid")


if __name__ == "__main__":
    main()
