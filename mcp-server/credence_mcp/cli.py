#!/usr/bin/env python3
"""
Credence CLI — Check MCP server trust status from the command line.

Usage:
    credence check <server>             Check trust status of a single server
    credence verify <server> [--path]   Hash local code and verify against attestation
    credence list [--min-score N]       List all attested servers
    credence audit [--config PATH]      Audit all servers in your MCP client config
    credence guard <server> [-- cmd]    Check trust, then run a command only if safe
    credence watch [--config PATH]      Watch config for changes, alert on unattested servers

Examples:
    credence check https://github.com/owner/mcp-server
    credence check owner/mcp-server
    credence verify owner/mcp-server --path ./my-local-clone
    credence list --min-score 70
    credence audit
    credence audit --config ~/custom/claude_desktop_config.json
    credence guard owner/mcp-server -- claude mcp add my-server
    credence watch

Exit codes:
    0 = attested, safe to install (or audit passed)
    1 = not attested or error
    2 = attested, but flagged (review recommended)
    3 = rejected or hash mismatch (do not install)
    4 = audit found unattested or flagged servers
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx

from credence_mcp.config_resolver import (
    find_config_file,
    resolve_all,
    resolve_server,
    parse_config,
    ResolvedServer,
)

REGISTRY_URL = "https://raw.githubusercontent.com/pestafford/credence-registry/main/registry.json"
PUBLIC_KEY_URL = "https://raw.githubusercontent.com/pestafford/credence-registry/main/credence_key.pub"

_public_key_cache = None


def _get_public_key():
    """Fetch and cache the Credence signing public key."""
    global _public_key_cache
    if _public_key_cache is not None:
        return _public_key_cache
    try:
        resp = httpx.get(PUBLIC_KEY_URL, timeout=10.0)
        if resp.status_code == 200:
            from credence_mcp.signing import load_public_key_pem
            _public_key_cache = load_public_key_pem(resp.text)
            return _public_key_cache
    except Exception:
        pass
    return None


def _verify_signature(server: dict) -> tuple[bool | None, str]:
    """Verify the signature on a server attestation. Returns (valid, message).
    Returns (None, message) if no signature or no public key available."""
    att = server.get("attestation", {})
    sig = att.get("signature")
    if not sig:
        return None, "unsigned"

    pubkey = _get_public_key()
    if pubkey is None:
        return None, "could not fetch public key"

    try:
        from credence_mcp.signing import verify_attestation
        valid, msg = verify_attestation(att, pubkey)
        return valid, msg
    except Exception as e:
        return None, f"verification error: {e}"

# ── Colors ───────────────────────────────────────────────────────

class C:
    """Terminal colors — degrades gracefully if not a TTY."""
    if sys.stdout.isatty():
        GREEN = "\033[92m"
        YELLOW = "\033[93m"
        RED = "\033[91m"
        BOLD = "\033[1m"
        DIM = "\033[2m"
        RESET = "\033[0m"
        ORANGE = "\033[38;5;208m"
    else:
        GREEN = YELLOW = RED = BOLD = DIM = RESET = ORANGE = ""


# ── Registry ─────────────────────────────────────────────────────

def fetch_registry() -> dict:
    resp = httpx.get(REGISTRY_URL, timeout=15.0)
    resp.raise_for_status()
    return resp.json()


def find_server(registry: dict, query: str) -> dict | None:
    query_lower = query.lower().strip().rstrip("/")
    for server in registry.get("servers", []):
        if server.get("server_id", "").lower() == query_lower:
            return server
        repo = server.get("repo_url", "").lower().rstrip("/")
        if repo == query_lower or repo.endswith(query_lower):
            return server
        if query_lower in server.get("server_name", "").lower():
            return server
    return None


# ── Hashing ──────────────────────────────────────────────────────

def compute_source_hash(path: Path) -> str:
    files = sorted(
        str(f.relative_to(path))
        for f in path.rglob("*")
        if f.is_file() and ".git" not in f.parts
    )
    file_hashes = []
    for rel_path in files:
        full_path = path / rel_path
        h = hashlib.sha256()
        with open(full_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        file_hashes.append(f"{h.hexdigest()}  {rel_path}")

    combined = "\n".join(file_hashes)
    return hashlib.sha256(combined.encode()).hexdigest()


# ── Commands ─────────────────────────────────────────────────────

def cmd_check(args) -> int:
    print(f"{C.DIM}Checking Credence Registry...{C.RESET}")

    try:
        registry = fetch_registry()
    except Exception as e:
        print(f"{C.RED}Error:{C.RESET} Could not reach registry: {e}")
        return 1

    server = find_server(registry, args.server)

    if server is None:
        print(f"\n{C.YELLOW}⚠  NOT ATTESTED{C.RESET}")
        print(f"   No Credence attestation found for: {C.BOLD}{args.server}{C.RESET}")
        print(f"   This doesn't mean it's malicious — it hasn't been analyzed yet.")
        print(f"\n   {C.DIM}Submit for analysis: https://pestafford.github.io/credence-registry/#submit{C.RESET}")
        return 1

    att = server.get("attestation", {})
    provenance = att.get("author_identity", {})
    flags = provenance.get("provenance_flags", [])
    trust_score = att.get("trust_score")
    verdict = att.get("thinktank_verdict", "UNKNOWN")
    scan = att.get("scan_summary", {})

    # Header
    print(f"\n{C.BOLD}{server.get('server_name', server.get('server_id'))}{C.RESET}")
    print(f"   {C.DIM}{server.get('repo_url', '')}{C.RESET}")

    # Trust score
    if trust_score is not None:
        if trust_score >= 70:
            color = C.GREEN
        elif trust_score >= 40:
            color = C.YELLOW
        else:
            color = C.RED
        print(f"\n   Trust score:  {color}{C.BOLD}{trust_score}/100{C.RESET}")
    else:
        print(f"\n   Trust score:  {C.DIM}pending{C.RESET}")

    # Verdict
    verdict_colors = {"APPROVED": C.GREEN, "CONDITIONAL": C.YELLOW, "REJECTED": C.RED}
    vc = verdict_colors.get(verdict, C.DIM)
    print(f"   Verdict:      {vc}{verdict}{C.RESET}")

    # Provenance
    id_match = provenance.get("identity_match")
    if id_match is True:
        print(f"   Identity:     {C.GREEN}verified{C.RESET}")
    elif id_match is False:
        print(f"   Identity:     {C.RED}MISMATCH{C.RESET}")
    else:
        print(f"   Identity:     {C.DIM}unknown{C.RESET}")

    if flags:
        print(f"   Flags:        {C.YELLOW}{', '.join(flags)}{C.RESET}")

    # Commit and hash
    commit = att.get("commit_sha", "")
    if commit:
        print(f"   Commit:       {C.DIM}{commit[:12]}{C.RESET}")
    source_hash = att.get("source_hash", "")
    if source_hash:
        display_hash = source_hash.replace("sha256:", "")[:16]
        print(f"   Source hash:  {C.DIM}{display_hash}...{C.RESET}")

    # Attested date
    attested = att.get("attested_at", "")
    if attested:
        print(f"   Attested:     {C.DIM}{attested}{C.RESET}")

    # Signature verification
    sig_valid, sig_msg = _verify_signature(server)
    if sig_valid is True:
        print(f"   Signature:    {C.GREEN}verified ✔{C.RESET}")
    elif sig_valid is False:
        print(f"   Signature:    {C.RED}INVALID ✘{C.RESET} — {sig_msg}")
    else:
        print(f"   Signature:    {C.DIM}{sig_msg}{C.RESET}")

    # Scan summary if present
    if scan:
        findings = sum(v for v in scan.values() if isinstance(v, int))
        if findings > 0:
            print(f"\n   Scan findings: {C.YELLOW}{findings} total{C.RESET}")
            for k, v in scan.items():
                if isinstance(v, int) and v > 0:
                    print(f"     {k}: {v}")

    # Recommendation
    if verdict == "REJECTED" or (trust_score is not None and trust_score < 30):
        print(f"\n   {C.RED}{C.BOLD}✘ DO NOT INSTALL{C.RESET}")
        return 3
    elif verdict == "CONDITIONAL" or flags or (trust_score is not None and trust_score < 70):
        print(f"\n   {C.YELLOW}{C.BOLD}⚠ REVIEW BEFORE INSTALLING{C.RESET}")
        return 2
    else:
        print(f"\n   {C.GREEN}{C.BOLD}✔ SAFE TO INSTALL{C.RESET}")
        return 0


def cmd_verify(args) -> int:
    path = Path(args.path).resolve()
    if not path.is_dir():
        print(f"{C.RED}Error:{C.RESET} Not a directory: {args.path}")
        return 1

    print(f"{C.DIM}Computing source hash for {path}...{C.RESET}")
    local_hash = compute_source_hash(path)
    print(f"   Local hash: {C.DIM}{local_hash}{C.RESET}")

    print(f"{C.DIM}Checking Credence Registry...{C.RESET}")
    try:
        registry = fetch_registry()
    except Exception as e:
        print(f"{C.RED}Error:{C.RESET} Could not reach registry: {e}")
        return 1

    server = find_server(registry, args.server)
    if server is None:
        print(f"\n{C.YELLOW}⚠  No attestation found for: {args.server}{C.RESET}")
        return 1

    attested_hash = server.get("attestation", {}).get("source_hash", "")
    attested_clean = attested_hash.replace("sha256:", "").strip().lower()

    print(f"   Attested:   {C.DIM}{attested_clean}{C.RESET}")

    # Verify attestation signature before trusting the hash
    sig_valid, sig_msg = _verify_signature(server)
    if sig_valid is True:
        print(f"   Signature:  {C.GREEN}verified ✔{C.RESET}")
    elif sig_valid is False:
        print(f"\n   {C.RED}{C.BOLD}✘ ATTESTATION SIGNATURE INVALID{C.RESET}")
        print(f"   {sig_msg}")
        print(f"   The attestation data cannot be trusted. Do NOT rely on this hash.")
        return 3
    else:
        print(f"   Signature:  {C.YELLOW}{sig_msg}{C.RESET} (proceeding with caution)")

    if local_hash == attested_clean:
        print(f"\n   {C.GREEN}{C.BOLD}✔ HASH MATCH{C.RESET} — code is identical to attested version")
        return 0
    else:
        print(f"\n   {C.RED}{C.BOLD}✘ HASH MISMATCH{C.RESET}")
        print(f"   The code you have does NOT match what Credence analyzed.")
        print(f"   It may have been modified after attestation. Do NOT install.")
        return 3


def cmd_list(args) -> int:
    print(f"{C.DIM}Fetching Credence Registry...{C.RESET}")

    try:
        registry = fetch_registry()
    except Exception as e:
        print(f"{C.RED}Error:{C.RESET} Could not reach registry: {e}")
        return 1

    servers = registry.get("servers", [])

    if args.min_score is not None:
        servers = [
            s for s in servers
            if s.get("attestation", {}).get("trust_score", 0) >= args.min_score
        ]

    if not servers:
        print(f"\n{C.DIM}No attested servers found.{C.RESET}")
        return 0

    print(f"\n{C.BOLD}Attested MCP Servers ({len(servers)}){C.RESET}\n")

    for s in servers:
        att = s.get("attestation", {})
        score = att.get("trust_score")
        verdict = att.get("thinktank_verdict", "?")
        flags = att.get("author_identity", {}).get("provenance_flags", [])

        if score is not None and score >= 70:
            indicator = f"{C.GREEN}●{C.RESET}"
        elif score is not None and score >= 40:
            indicator = f"{C.YELLOW}●{C.RESET}"
        elif score is not None:
            indicator = f"{C.RED}●{C.RESET}"
        else:
            indicator = f"{C.DIM}○{C.RESET}"

        name = s.get("server_name", s.get("server_id", "unknown"))
        score_str = f"{score}/100" if score is not None else "pending"
        flag_str = f" {C.YELLOW}[{', '.join(flags)}]{C.RESET}" if flags else ""

        print(f"  {indicator} {C.BOLD}{name}{C.RESET}  {C.DIM}{score_str}  {verdict}{C.RESET}{flag_str}")
        print(f"    {C.DIM}{s.get('repo_url', '')}{C.RESET}")

    return 0


# ── Audit ─────────────────────────────────────────────────────────

def cmd_audit(args) -> int:
    """Audit all MCP servers in the user's config."""
    config_path = Path(args.config) if args.config else None

    try:
        config_path, servers = resolve_all(config_path)
    except FileNotFoundError as e:
        print(f"{C.RED}Error:{C.RESET} {e}")
        return 1

    print(f"{C.DIM}Config: {config_path}{C.RESET}")
    print(f"{C.DIM}Found {len(servers)} configured MCP server(s){C.RESET}")
    print(f"{C.DIM}Checking Credence Registry...{C.RESET}")

    try:
        registry = fetch_registry()
    except Exception as e:
        print(f"{C.RED}Error:{C.RESET} Could not reach registry: {e}")
        return 1

    attested = 0
    unattested = 0
    flagged = 0
    errors = 0

    print(f"\n{C.BOLD}MCP Server Audit{C.RESET}")
    print(f"{'─' * 60}\n")

    for server in servers:
        # Print server header
        type_badge = f"{C.DIM}[{server.server_type}]{C.RESET}"
        print(f"  {C.BOLD}{server.name}{C.RESET} {type_badge}")
        print(f"  {C.DIM}{server.command} {' '.join(server.args[:3])}{'...' if len(server.args) > 3 else ''}{C.RESET}")

        if server.resolve_error:
            print(f"  {C.RED}✘ Resolution error: {server.resolve_error}{C.RESET}")
            errors += 1
            print()
            continue

        # Show what we resolved
        if server.package_name:
            print(f"  Package: {C.DIM}{server.package_name}{C.RESET}", end="")
            if server.version:
                print(f" {C.DIM}v{server.version}{C.RESET}", end="")
            print()

        if server.repo_url:
            print(f"  Repo:    {C.DIM}{server.repo_url}{C.RESET}")

        # Check against registry
        query = server.repo_url or server.package_name or server.name
        match = find_server(registry, query) if query else None

        if match is None and server.package_name:
            # Try alternative lookups
            match = find_server(registry, server.package_name)
        if match is None:
            match = find_server(registry, server.name)

        if match:
            att = match.get("attestation", {})
            score = att.get("trust_score")
            verdict = att.get("thinktank_verdict", "?")
            flags = att.get("author_identity", {}).get("provenance_flags", [])

            if verdict == "REJECTED" or (score is not None and score < 30):
                print(f"  {C.RED}{C.BOLD}✘ REJECTED{C.RESET} — score: {score}/100, verdict: {verdict}")
                flagged += 1
            elif flags or verdict == "CONDITIONAL" or (score is not None and score < 70):
                print(f"  {C.YELLOW}{C.BOLD}⚠ FLAGGED{C.RESET} — score: {score}/100, verdict: {verdict}")
                if flags:
                    print(f"  Flags: {C.YELLOW}{', '.join(flags)}{C.RESET}")
                flagged += 1
            else:
                print(f"  {C.GREEN}✔ ATTESTED{C.RESET} — score: {score}/100, verdict: {verdict}")
                attested += 1
        else:
            print(f"  {C.YELLOW}○ NOT ATTESTED{C.RESET} — no Credence record found")
            if not server.repo_url:
                print(f"  {C.DIM}  (could not resolve to a repo URL for registry lookup){C.RESET}")
            unattested += 1

        print()

    # Summary
    print(f"{'─' * 60}")
    total = len(servers)
    print(f"\n  {C.BOLD}Audit Summary{C.RESET}")
    print(f"  {C.GREEN}✔ Attested:    {attested}/{total}{C.RESET}")
    if unattested:
        print(f"  {C.YELLOW}○ Unattested:  {unattested}/{total}{C.RESET}")
    if flagged:
        print(f"  {C.RED}⚠ Flagged:     {flagged}/{total}{C.RESET}")
    if errors:
        print(f"  {C.RED}✘ Errors:      {errors}/{total}{C.RESET}")

    if unattested == 0 and flagged == 0 and errors == 0:
        print(f"\n  {C.GREEN}{C.BOLD}All servers attested. Looking good.{C.RESET}")
        return 0
    else:
        print(f"\n  {C.YELLOW}Submit unattested servers: https://pestafford.github.io/credence-registry/#submit{C.RESET}")
        return 4 if (flagged or unattested) else 0


# ── Guard ─────────────────────────────────────────────────────────

def cmd_guard(args) -> int:
    """Check trust, then optionally run a command only if safe."""
    print(f"{C.DIM}Credence guard checking: {args.server}{C.RESET}")

    try:
        registry = fetch_registry()
    except Exception as e:
        print(f"{C.RED}Error:{C.RESET} Could not reach registry: {e}")
        if not args.allow_unattested:
            print(f"Cannot verify server. Use --allow-unattested to proceed anyway.")
            return 1
        else:
            print(f"{C.YELLOW}Warning:{C.RESET} Proceeding without verification (--allow-unattested)")
            return _run_guarded_command(args)

    server = find_server(registry, args.server)

    if server is None:
        print(f"\n{C.YELLOW}⚠ NOT ATTESTED:{C.RESET} {args.server}")
        print(f"  No Credence attestation found for this server.")

        if args.allow_unattested:
            print(f"  {C.YELLOW}Proceeding anyway (--allow-unattested){C.RESET}")
            return _run_guarded_command(args)
        else:
            print(f"  {C.BOLD}Blocked.{C.RESET} Use --allow-unattested to override.")
            print(f"  Submit for analysis: https://pestafford.github.io/credence-registry/#submit")
            return 1

    att = server.get("attestation", {})
    trust_score = att.get("trust_score")
    verdict = att.get("thinktank_verdict", "UNKNOWN")
    flags = att.get("author_identity", {}).get("provenance_flags", [])

    if verdict == "REJECTED" or (trust_score is not None and trust_score < 30):
        print(f"\n{C.RED}{C.BOLD}✘ REJECTED:{C.RESET} {args.server}")
        print(f"  Trust score: {trust_score}/100, Verdict: {verdict}")
        if flags:
            print(f"  Flags: {', '.join(flags)}")
        print(f"  {C.RED}{C.BOLD}Command blocked.{C.RESET} This server failed Credence review.")
        return 3

    if flags or verdict == "CONDITIONAL" or (trust_score is not None and trust_score < 70):
        print(f"\n{C.YELLOW}{C.BOLD}⚠ FLAGGED:{C.RESET} {args.server}")
        print(f"  Trust score: {trust_score}/100, Verdict: {verdict}")
        if flags:
            print(f"  Flags: {', '.join(flags)}")

        if args.allow_flagged:
            print(f"  {C.YELLOW}Proceeding anyway (--allow-flagged){C.RESET}")
            return _run_guarded_command(args)
        else:
            print(f"  {C.BOLD}Blocked.{C.RESET} Use --allow-flagged to override.")
            return 2

    # APPROVED
    print(f"\n{C.GREEN}✔ APPROVED:{C.RESET} {args.server} — score: {trust_score}/100")
    return _run_guarded_command(args)


def _run_guarded_command(args) -> int:
    """Run the command after the guard check."""
    if not args.command:
        return 0  # No command to run, just the check

    cmd = args.command
    print(f"\n{C.DIM}Running: {' '.join(cmd)}{C.RESET}")

    try:
        result = subprocess.run(cmd)
        return result.returncode
    except FileNotFoundError:
        print(f"{C.RED}Error:{C.RESET} Command not found: {cmd[0]}")
        return 1
    except Exception as e:
        print(f"{C.RED}Error:{C.RESET} {e}")
        return 1


# ── Watch ─────────────────────────────────────────────────────────

def cmd_watch(args) -> int:
    """Watch config file for changes, alert on unattested servers."""
    config_path = Path(args.config) if args.config else find_config_file()

    if config_path is None:
        print(f"{C.RED}Error:{C.RESET} Could not find MCP client config file.")
        return 1

    if not config_path.exists():
        print(f"{C.RED}Error:{C.RESET} Config file not found: {config_path}")
        return 1

    print(f"{C.BOLD}Credence Watch{C.RESET}")
    print(f"Monitoring: {C.DIM}{config_path}{C.RESET}")
    print(f"Checking every {args.interval}s. Press Ctrl+C to stop.\n")

    last_mtime = 0
    known_servers = set()

    # Initial load
    try:
        registry = fetch_registry()
    except Exception as e:
        print(f"{C.YELLOW}Warning:{C.RESET} Could not reach registry on startup: {e}")
        registry = {"servers": []}

    try:
        while True:
            current_mtime = config_path.stat().st_mtime

            if current_mtime != last_mtime:
                last_mtime = current_mtime

                try:
                    servers_config = parse_config(config_path)
                except Exception as e:
                    print(f"{C.RED}Error parsing config:{C.RESET} {e}")
                    time.sleep(args.interval)
                    continue

                current_names = set(servers_config.keys())
                new_servers = current_names - known_servers

                if new_servers:
                    # Refresh registry for new checks
                    try:
                        registry = fetch_registry()
                    except Exception:
                        pass

                    timestamp = time.strftime("%H:%M:%S")

                    for name in new_servers:
                        server_conf = servers_config[name]
                        resolved = resolve_server(name, server_conf)

                        print(f"[{timestamp}] {C.BOLD}New server detected: {name}{C.RESET}")
                        print(f"  {C.DIM}{resolved.command} {' '.join(resolved.args[:3])}{C.RESET}")

                        query = resolved.repo_url or resolved.package_name or name
                        match = find_server(registry, query) if query else None

                        if match:
                            att = match.get("attestation", {})
                            score = att.get("trust_score")
                            verdict = att.get("thinktank_verdict", "?")
                            flags = att.get("author_identity", {}).get("provenance_flags", [])

                            if verdict == "REJECTED" or (score is not None and score < 30):
                                print(f"  {C.RED}{C.BOLD}✘ REJECTED — score: {score}/100{C.RESET}")
                                _alert(f"REJECTED MCP server added: {name} (score: {score})")
                            elif flags or (score is not None and score < 70):
                                print(f"  {C.YELLOW}{C.BOLD}⚠ FLAGGED — score: {score}/100{C.RESET}")
                                _alert(f"Flagged MCP server added: {name} (score: {score})")
                            else:
                                print(f"  {C.GREEN}✔ ATTESTED — score: {score}/100{C.RESET}")
                        else:
                            print(f"  {C.YELLOW}○ NOT ATTESTED — no Credence record{C.RESET}")
                            _alert(f"Unattested MCP server added: {name}")

                        print()

                removed = known_servers - current_names
                for name in removed:
                    timestamp = time.strftime("%H:%M:%S")
                    print(f"[{timestamp}] {C.DIM}Server removed: {name}{C.RESET}")

                known_servers = current_names

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print(f"\n{C.DIM}Watch stopped.{C.RESET}")
        return 0


def _alert(message: str):
    """Send a system notification if possible."""
    system = sys.platform

    try:
        if system == "darwin":
            subprocess.run([
                "osascript", "-e",
                f'display notification "{message}" with title "Credence"'
            ], capture_output=True, timeout=5)
        elif system == "linux":
            subprocess.run([
                "notify-send", "Credence", message
            ], capture_output=True, timeout=5)
        # Windows: could use plyer or win10toast, skip for now
    except Exception:
        pass  # Silent fail — terminal output is the primary channel


# ── Entry Point ──────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="credence",
        description="Credence — Install-time trust verification for MCP servers",
        epilog="Docs: https://pestafford.github.io/credence-registry/"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # check
    p_check = sub.add_parser("check", help="Check trust status of an MCP server")
    p_check.add_argument("server", help="Repo URL, server ID (owner/repo), or name")

    # verify
    p_verify = sub.add_parser("verify", help="Verify local source hash against attestation")
    p_verify.add_argument("server", help="Repo URL or server ID")
    p_verify.add_argument("--path", default=".", help="Path to local server directory (default: .)")

    # list
    p_list = sub.add_parser("list", help="List all attested servers")
    p_list.add_argument("--min-score", type=int, default=None, help="Minimum trust score filter")

    # audit
    p_audit = sub.add_parser("audit", help="Audit all MCP servers in your client config")
    p_audit.add_argument("--config", default=None, help="Path to config file (auto-detected if omitted)")

    # guard
    p_guard = sub.add_parser("guard", help="Check trust, then run a command only if safe")
    p_guard.add_argument("server", help="Repo URL or server ID to check")
    p_guard.add_argument("--allow-unattested", action="store_true",
                         help="Allow command to proceed for unattested servers")
    p_guard.add_argument("--allow-flagged", action="store_true",
                         help="Allow command to proceed for flagged servers")
    p_guard.add_argument("command", nargs="*", help="Command to run if check passes (after --)")

    # watch
    p_watch = sub.add_parser("watch", help="Watch config for changes, alert on unattested servers")
    p_watch.add_argument("--config", default=None, help="Path to config file (auto-detected if omitted)")
    p_watch.add_argument("--interval", type=int, default=5, help="Check interval in seconds (default: 5)")

    args = parser.parse_args()

    if args.command == "check":
        sys.exit(cmd_check(args))
    elif args.command == "verify":
        sys.exit(cmd_verify(args))
    elif args.command == "list":
        sys.exit(cmd_list(args))
    elif args.command == "audit":
        sys.exit(cmd_audit(args))
    elif args.command == "guard":
        sys.exit(cmd_guard(args))
    elif args.command == "watch":
        sys.exit(cmd_watch(args))


if __name__ == "__main__":
    main()
