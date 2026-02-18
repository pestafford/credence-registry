#!/usr/bin/env python3
"""
Credence Batch Scanner — Two-phase scan orchestrator with triage-ordered deliberation.

Phase 1 (free): Clone, run deterministic scanners, normalize, score, generate badge.
Phase 2 (paid): Deliberate in triage order (lowest preliminary score first),
                with budget caps and incremental registry publishing.

Usage:
    # Phase 1 only
    python -m credence_mcp.batch_scanner skills.txt --output batch-results/ --phase1-only

    # Phase 2 with budget cap
    python -m credence_mcp.batch_scanner batch-results/ --resume --deliberate --budget 100

    # Resume Phase 2, publish as we go
    python -m credence_mcp.batch_scanner batch-results/ --resume --deliberate --budget 200 --publish
"""

import argparse
import asyncio
import hashlib
import json
import logging
import os
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("credence.batch")


# ── Data types ────────────────────────────────────────────

@dataclass
class ScanTarget:
    url: str
    name: str = ""
    category: str = ""
    source: str = ""
    metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.name:
            # Derive name from URL: https://github.com/owner/repo -> owner/repo
            parts = self.url.rstrip("/").split("/")
            self.name = f"{parts[-2]}/{parts[-1]}" if len(parts) >= 2 else self.url


@dataclass
class ScanResult:
    target: ScanTarget
    scan_dir: str = ""
    commit_sha: str = ""
    preliminary_score: int | None = None
    preliminary_verdict: str = ""
    final_score: int | None = None
    final_verdict: str = ""
    status: str = "pending"  # pending / phase1_done / phase2_done / error
    error: str = ""


# ── Input parsing ─────────────────────────────────────────

def load_targets(path: str) -> list[ScanTarget]:
    """Load scan targets from a text file (one URL per line) or JSON array."""
    p = Path(path)
    text = p.read_text().strip()

    if not text:
        return []

    # Try JSON first
    if text.startswith("[") or text.startswith("{"):
        data = json.loads(text)
        if isinstance(data, dict):
            data = [data]
        return [
            ScanTarget(
                url=item if isinstance(item, str) else item["url"],
                name=item.get("name", "") if isinstance(item, dict) else "",
                category=item.get("category", "") if isinstance(item, dict) else "",
                source=item.get("source", "") if isinstance(item, dict) else "",
                metadata=item.get("metadata", {}) if isinstance(item, dict) else {},
            )
            for item in data
        ]

    # Plain text: one URL per line
    targets = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            targets.append(ScanTarget(url=line))
    return targets


# ── Checkpoint ────────────────────────────────────────────

class Checkpoint:
    """Persistent progress tracker with atomic saves."""

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.path = self.output_dir / "checkpoint.json"
        self.data: dict = {}
        self._load()

    def _load(self):
        if self.path.exists():
            self.data = json.loads(self.path.read_text())
        else:
            self.data = {
                "version": "1.0",
                "created_at": _now_iso(),
                "updated_at": _now_iso(),
                "input_file": "",
                "phase1_completed": 0,
                "phase2_completed": 0,
                "phase2_estimated_spend": 0.0,
                "targets": {},
            }

    def get_status(self, url: str) -> str:
        entry = self.data["targets"].get(url)
        return entry["status"] if entry else "pending"

    def mark_phase1(self, url: str, result: ScanResult):
        self.data["targets"][url] = {
            "status": "phase1_done",
            "name": result.target.name,
            "scan_dir": result.scan_dir,
            "commit_sha": result.commit_sha,
            "preliminary_score": result.preliminary_score,
            "preliminary_verdict": result.preliminary_verdict,
            "final_score": None,
            "final_verdict": None,
            "error": None,
        }
        self.data["phase1_completed"] = sum(
            1 for t in self.data["targets"].values()
            if t["status"] in ("phase1_done", "phase2_done")
        )
        self.data["updated_at"] = _now_iso()

    def mark_phase2(self, url: str, result: ScanResult):
        entry = self.data["targets"].get(url, {})
        entry["status"] = "phase2_done"
        entry["final_score"] = result.final_score
        entry["final_verdict"] = result.final_verdict
        self.data["targets"][url] = entry
        self.data["phase2_completed"] = sum(
            1 for t in self.data["targets"].values() if t["status"] == "phase2_done"
        )
        self.data["updated_at"] = _now_iso()

    def mark_error(self, url: str, error: str, name: str = ""):
        self.data["targets"][url] = {
            "status": "error",
            "name": name,
            "scan_dir": "",
            "commit_sha": "",
            "preliminary_score": None,
            "preliminary_verdict": None,
            "final_score": None,
            "final_verdict": None,
            "error": error,
        }
        self.data["updated_at"] = _now_iso()

    def get_triage_order(self) -> list[str]:
        """Return URLs sorted by preliminary_score ascending (most suspicious first)."""
        eligible = [
            (url, entry)
            for url, entry in self.data["targets"].items()
            if entry["status"] == "phase1_done"
        ]
        eligible.sort(key=lambda x: x[1].get("preliminary_score") or 0)
        return [url for url, _ in eligible]

    def save(self):
        self.output_dir.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=2))
        os.replace(str(tmp), str(self.path))

    def summary(self) -> dict:
        targets = self.data["targets"]
        statuses = [t["status"] for t in targets.values()]
        scores = [
            t["preliminary_score"] for t in targets.values()
            if t.get("preliminary_score") is not None
        ]
        return {
            "total": len(targets),
            "pending": statuses.count("pending"),
            "phase1_done": statuses.count("phase1_done"),
            "phase2_done": statuses.count("phase2_done"),
            "errors": statuses.count("error"),
            "score_distribution": {
                "0-39": sum(1 for s in scores if s <= 39),
                "40-69": sum(1 for s in scores if 40 <= s <= 69),
                "70-89": sum(1 for s in scores if 70 <= s <= 89),
                "90+": sum(1 for s in scores if s >= 90),
            },
        }


# ── Phase 1: Deterministic scanning ──────────────────────

async def clone_repo(url: str, dest: str, shallow: bool = True) -> tuple[str, str]:
    """Clone a repo and return (commit_sha, repo_path)."""
    args = ["git", "clone"]
    if shallow:
        args.extend(["--depth", "1"])
    args.extend([url, dest])

    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"git clone failed: {stderr.decode().strip()}")

    # Get HEAD sha
    proc2 = await asyncio.create_subprocess_exec(
        "git", "rev-parse", "HEAD",
        cwd=dest, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc2.communicate()
    sha = stdout.decode().strip()

    return sha, dest


def compute_source_hash(repo_path: str) -> str:
    """Merkle-tree SHA-256 of all tracked files."""
    repo = Path(repo_path)
    files = sorted(
        f for f in repo.rglob("*")
        if f.is_file() and ".git" not in f.parts
    )
    hasher = hashlib.sha256()
    for f in files:
        file_hash = hashlib.sha256(f.read_bytes()).hexdigest()
        hasher.update(f"{file_hash}  {f.relative_to(repo)}\n".encode())
    return hasher.hexdigest()


def detect_tool_type(repo_path: str) -> str:
    """Detect the tool type from repo contents."""
    p = Path(repo_path)
    if (p / "SKILL.md").exists() or (p / "claw.json").exists():
        return "openclaw-skill"
    manifest = p / "manifest.json"
    if manifest.exists():
        try:
            data = json.loads(manifest.read_text())
            if "mcpb_version" in data:
                return "mcpb-extension"
        except (json.JSONDecodeError, OSError):
            pass
    return "mcp-server"


def detect_scanners(repo_path: str, full_scan: bool = False) -> list[str]:
    """Detect which scanners to run based on repo contents."""
    scanners = ["skill_analyzer", "mcpb_analyzer", "gitleaks"]

    if full_scan:
        return scanners + ["semgrep", "bandit", "trivy"]

    p = Path(repo_path)
    has_python = any(p.rglob("*.py"))
    has_js = any(p.rglob("*.js")) or any(p.rglob("*.ts")) or any(p.rglob("*.mjs"))
    has_deps = any(
        (p / f).exists()
        for f in [
            "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
            "requirements.txt", "Pipfile", "pyproject.toml", "Cargo.toml", "go.mod",
        ]
    )

    if has_python or has_js:
        scanners.append("semgrep")
    if has_python:
        scanners.append("bandit")
    if has_deps:
        scanners.append("trivy")

    return scanners


async def run_scanner(name: str, repo_path: str, scan_dir: str) -> dict:
    """Run a single scanner and return its output dict."""
    scan_path = Path(scan_dir)

    if name == "skill_analyzer":
        from credence_mcp.skill_analyzer import analyze_repo
        result = analyze_repo(repo_path)
        (scan_path / "skill-analysis.json").write_text(json.dumps(result, indent=2))
        return result

    if name == "mcpb_analyzer":
        from credence_mcp.mcpb_analyzer import analyze_repo
        result = analyze_repo(repo_path)
        (scan_path / "mcpb-analysis.json").write_text(json.dumps(result, indent=2))
        return result

    # Subprocess-based scanners
    output_file = scan_path / f"{name}-results.json"
    empty_default = "[]" if name == "gitleaks" else '{"results":[]}'

    try:
        if name == "gitleaks":
            cmd = [
                "gitleaks", "detect", "--source", repo_path,
                "--report-format", "json", "--report-path", str(output_file),
            ]
        elif name == "semgrep":
            cmd = [
                "semgrep", "scan", "--config", "auto", "--json",
                "--output", str(output_file), repo_path,
            ]
        elif name == "bandit":
            cmd = [
                "bandit", "-r", repo_path, "-f", "json",
                "-o", str(output_file),
            ]
        elif name == "trivy":
            cmd = [
                "trivy", "fs", "--format", "json",
                "--output", str(output_file), repo_path,
            ]
        else:
            log.warning(f"Unknown scanner: {name}")
            return {}

        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=120)

    except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
        log.warning(f"Scanner {name} failed: {e}")
        output_file.write_text(empty_default)

    # gitleaks exits 1 when it finds leaks (not an error)
    if not output_file.exists():
        output_file.write_text(empty_default)

    try:
        return json.loads(output_file.read_text())
    except json.JSONDecodeError:
        output_file.write_text(empty_default)
        return json.loads(empty_default)


def _count_findings(scan_dir: str) -> dict:
    """Count scanner findings from output files for scan-summary."""
    p = Path(scan_dir)
    counts = {
        "semgrep_findings": 0,
        "bandit_findings": 0,
        "trivy_vulnerabilities": 0,
        "gitleaks_secrets": 0,
        "mcp_tool_warnings": 0,
        "mcp_tool_critical": 0,
        "skill_warnings": 0,
        "skill_critical": 0,
        "mcpb_warnings": 0,
        "mcpb_critical": 0,
    }

    def _safe_load(filename):
        f = p / filename
        if f.exists():
            try:
                return json.loads(f.read_text())
            except json.JSONDecodeError:
                pass
        return None

    semgrep = _safe_load("semgrep-results.json")
    if semgrep and isinstance(semgrep, dict):
        counts["semgrep_findings"] = len(semgrep.get("results", []))

    bandit = _safe_load("bandit-results.json")
    if bandit and isinstance(bandit, dict):
        counts["bandit_findings"] = len(bandit.get("results", []))

    trivy = _safe_load("trivy-results.json")
    if trivy and isinstance(trivy, dict):
        for r in trivy.get("Results", []):
            counts["trivy_vulnerabilities"] += len(r.get("Vulnerabilities", []))

    gitleaks = _safe_load("gitleaks-results.json")
    if gitleaks and isinstance(gitleaks, list):
        counts["gitleaks_secrets"] = len(gitleaks)

    skill = _safe_load("skill-analysis.json")
    if skill and isinstance(skill, dict):
        counts["skill_warnings"] = skill.get("warning_count", 0)
        counts["skill_critical"] = skill.get("critical_count", 0)

    mcpb = _safe_load("mcpb-analysis.json")
    if mcpb and isinstance(mcpb, dict):
        counts["mcpb_warnings"] = mcpb.get("warning_count", 0)
        counts["mcpb_critical"] = mcpb.get("critical_count", 0)

    return counts


def _detect_lockfile(repo_path: str) -> tuple[str, str]:
    """Detect lockfile and compute its hash. Returns (name, hash) or ("none", "none")."""
    p = Path(repo_path)
    for lf in [
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        "Pipfile.lock", "poetry.lock", "Cargo.lock", "go.sum",
    ]:
        f = p / lf
        if f.exists():
            h = hashlib.sha256(f.read_bytes()).hexdigest()
            return lf, h
    return "none", "none"


def _stash_context_files(repo_path: str, scan_dir: str):
    """Copy context files from repo to scan dir for Phase 2 deliberation."""
    for filename in ["README.md", "readme.md", "package.json", "pyproject.toml"]:
        src = Path(repo_path) / filename
        if src.exists():
            shutil.copy2(str(src), str(Path(scan_dir) / filename))


def build_scan_summary(
    target: ScanTarget,
    commit_sha: str,
    source_hash: str,
    scan_dir: str,
    tool_type: str,
    lockfile_name: str,
    lockfile_hash: str,
) -> dict:
    """Build a scan-summary.json dict from scanner outputs."""
    provenance_flags = []
    if lockfile_name == "none":
        provenance_flags.append("NO_LOCKFILE")

    # Skill-specific provenance: no manifest
    skill_path = Path(scan_dir) / "skill-analysis.json"
    if skill_path.exists():
        try:
            skill_data = json.loads(skill_path.read_text())
            if skill_data.get("format_detected") and not skill_data.get("manifest_found"):
                provenance_flags.append("SKILL_NO_MANIFEST")
        except json.JSONDecodeError:
            pass

    return {
        "server_name": target.name,
        "canonical_name": "",
        "server_path": "",
        "tool_type": tool_type,
        "maintainer_verified": False,
        "verify_reason": "Batch scan — no submitter verification",
        "repo_url": target.url,
        "commit_sha": commit_sha,
        "source_hash": source_hash,
        "source_hash_method": "merkle-tree-sha256",
        "is_fork": False,
        "provenance_flags": provenance_flags,
        "lockfile_name": lockfile_name,
        "lockfile_hash": lockfile_hash,
        "scan_results": _count_findings(scan_dir),
        "scan_timestamp": _now_iso(),
        "pipeline_version": "0.2.0",
        "thinktank_verdict": "PENDING",
        "trust_score": None,
    }


async def run_phase1(
    target: ScanTarget,
    output_dir: str,
    full_scan: bool = False,
) -> ScanResult:
    """Run Phase 1 (deterministic scanning) for a single target."""
    result = ScanResult(target=target)

    # Sanitize dir name: owner_repo
    parts = target.url.rstrip("/").split("/")
    dir_name = f"{parts[-2]}_{parts[-1]}" if len(parts) >= 2 else "unknown"
    scan_dir = str(Path(output_dir) / dir_name)
    Path(scan_dir).mkdir(parents=True, exist_ok=True)
    result.scan_dir = scan_dir

    # Clone to temp dir
    clone_dir = tempfile.mkdtemp(prefix="credence-clone-")
    try:
        sha, repo_path = await clone_repo(target.url, clone_dir)
        result.commit_sha = sha

        # Source hash
        source_hash = compute_source_hash(repo_path)

        # Detect tool type
        tool_type = detect_tool_type(repo_path)

        # Detect lockfile
        lockfile_name, lockfile_hash = _detect_lockfile(repo_path)

        # Detect and run scanners
        scanners = detect_scanners(repo_path, full_scan)
        for scanner_name in scanners:
            try:
                await run_scanner(scanner_name, repo_path, scan_dir)
            except Exception as e:
                log.warning(f"Scanner {scanner_name} failed for {target.name}: {e}")

        # Stash context files for Phase 2
        _stash_context_files(repo_path, scan_dir)

        # Build scan summary
        summary = build_scan_summary(
            target, sha, source_hash, scan_dir,
            tool_type, lockfile_name, lockfile_hash,
        )

        # Normalize findings
        from credence_mcp.report_normalizer import normalize_all
        evidence = normalize_all(scan_dir)
        evidence_path = Path(scan_dir) / "evidence.json"
        evidence_path.write_text(json.dumps(evidence, indent=2))

        # Compute trust score
        from credence_mcp.trust_score import compute_trust_score
        score_result = compute_trust_score(summary, evidence)
        summary.update({
            "trust_dimensions": score_result["trust_dimensions"],
            "trust_score": score_result["aggregate_score"],
            "thinktank_verdict": score_result["thinktank_verdict"],
            "scoring_version": score_result["scoring_version"],
        })

        # Write scan summary
        summary_path = Path(scan_dir) / "scan-summary.json"
        summary_path.write_text(json.dumps(summary, indent=2))

        # Generate badge
        from credence_mcp.badge_generator import generate_badge
        badge_svg = generate_badge(summary["trust_score"], summary["thinktank_verdict"])
        (Path(scan_dir) / "badge.svg").write_text(badge_svg)

        result.preliminary_score = summary["trust_score"]
        result.preliminary_verdict = summary["thinktank_verdict"]
        result.status = "phase1_done"

    except Exception as e:
        result.status = "error"
        result.error = str(e)
        log.error(f"Phase 1 failed for {target.name}: {e}")

    finally:
        # Always clean up clone
        shutil.rmtree(clone_dir, ignore_errors=True)

    return result


async def run_phase1_batch(
    targets: list[ScanTarget],
    output_dir: str,
    checkpoint: Checkpoint,
    concurrency: int = 4,
    full_scan: bool = False,
    verbose: bool = False,
) -> list[ScanResult]:
    """Run Phase 1 for all targets with concurrency control."""
    sem = asyncio.Semaphore(concurrency)
    results: list[ScanResult] = []
    progress = ProgressReporter("Phase 1: Deterministic Scanning", len(targets))

    async def scan_one(target: ScanTarget):
        # Skip already completed
        status = checkpoint.get_status(target.url)
        if status in ("phase1_done", "phase2_done"):
            progress.skip()
            return

        # Check disk space (1GB minimum)
        stat = os.statvfs(output_dir)
        free_gb = (stat.f_bavail * stat.f_frsize) / (1024**3)
        if free_gb < 1.0:
            log.error(f"Low disk space ({free_gb:.1f}GB free). Pausing.")
            checkpoint.save()
            return

        async with sem:
            progress.start_item(target.name)
            result = await run_phase1(target, output_dir, full_scan)
            results.append(result)

            if result.status == "phase1_done":
                checkpoint.mark_phase1(target.url, result)
                progress.complete(result.preliminary_score)
            else:
                checkpoint.mark_error(target.url, result.error, target.name)
                progress.error()

            # Save checkpoint periodically (every item for safety)
            checkpoint.save()

    tasks = [scan_one(t) for t in targets]
    await asyncio.gather(*tasks, return_exceptions=True)

    # Write triage manifest
    _write_triage_manifest(checkpoint, output_dir)

    progress.finish()
    return results


# ── Phase 2: Deliberation ────────────────────────────────

async def run_phase2(
    url: str,
    scan_dir: str,
    server_cmd: str = "deliberation-mcp",
    timeout: int = 300,
) -> ScanResult:
    """Run Phase 2 (deliberation) for a single target."""
    from credence_mcp.deliberation_adapter import build_request, invoke, process_response

    summary_path = Path(scan_dir) / "scan-summary.json"
    summary = json.loads(summary_path.read_text())

    # Build target for result
    target = ScanTarget(url=url, name=summary.get("server_name", url))
    result = ScanResult(target=target, scan_dir=scan_dir)

    try:
        # Build deliberation request (using scan_dir for both artifacts and context)
        request = build_request(scan_dir=scan_dir, repo_dir=scan_dir)

        # Invoke deliberation (blocking, run in thread)
        cmd_list = server_cmd.split()
        response = await asyncio.to_thread(invoke, request, cmd_list, timeout)

        # Process response — updates summary in place
        process_response(response, summary)

        # Write updated summary
        summary_path.write_text(json.dumps(summary, indent=2))

        # Regenerate badge with final verdict
        from credence_mcp.badge_generator import generate_badge
        badge_svg = generate_badge(summary["trust_score"], summary["thinktank_verdict"])
        (Path(scan_dir) / "badge.svg").write_text(badge_svg)

        result.final_score = summary.get("trust_score")
        result.final_verdict = summary.get("thinktank_verdict", "")
        result.status = "phase2_done"

    except Exception as e:
        result.status = "phase1_done"  # Stay at phase1_done so it retries
        result.error = str(e)
        log.error(f"Phase 2 failed for {target.name}: {e}")

    return result


async def run_phase2_batch(
    checkpoint: Checkpoint,
    output_dir: str,
    server_cmd: str = "deliberation-mcp",
    timeout: int = 300,
    max_deliberations: int | None = None,
    budget: float | None = None,
    cost_per_scan: float = 0.60,
    publish: bool = False,
    registry_dir: str = "registry/",
    signing_key_pem: str | None = None,
) -> list[ScanResult]:
    """Run Phase 2 for eligible targets in triage order."""
    triage_order = checkpoint.get_triage_order()
    total = len(triage_order)

    if max_deliberations is not None:
        total = min(total, max_deliberations)
    if budget is not None:
        budget_cap = int(budget / cost_per_scan)
        total = min(total, budget_cap)

    progress = ProgressReporter("Phase 2: Deliberation (triage order)", total)
    results: list[ScanResult] = []
    deliberation_count = 0
    estimated_spend = 0.0

    for url in triage_order:
        # Budget checks
        if max_deliberations is not None and deliberation_count >= max_deliberations:
            log.info(f"Max deliberations reached ({max_deliberations})")
            break
        if budget is not None and estimated_spend >= budget:
            log.info(f"Budget cap reached (${estimated_spend:.2f} >= ${budget:.2f})")
            break

        entry = checkpoint.data["targets"][url]
        scan_dir = entry["scan_dir"]
        prelim = entry.get("preliminary_score", "?")
        progress.start_item(f"{entry['name']} (prelim: {prelim})")

        result = await run_phase2(url, scan_dir, server_cmd, timeout)
        results.append(result)

        if result.status == "phase2_done":
            checkpoint.mark_phase2(url, result)
            deliberation_count += 1
            estimated_spend += cost_per_scan
            checkpoint.data["phase2_estimated_spend"] = round(estimated_spend, 2)
            progress.complete(result.final_score)

            # Incremental publish
            if publish:
                try:
                    _publish_result(scan_dir, registry_dir, signing_key_pem)
                except Exception as e:
                    log.warning(f"Publish failed for {entry['name']}: {e}")
        else:
            progress.error()

        checkpoint.save()

    progress.finish()
    return results


# ── Registry publishing ───────────────────────────────────

def _publish_result(scan_dir: str, registry_dir: str, signing_key_pem: str | None):
    """Publish a single scan result to the registry."""
    from credence_mcp.registry_update import (
        build_attestation, derive_server_id, upsert_registry,
    )
    from credence_mcp.signing import sign_attestation_from_pem

    summary_path = Path(scan_dir) / "scan-summary.json"
    summary = json.loads(summary_path.read_text())

    attestation = build_attestation(summary)

    if signing_key_pem:
        attestation = sign_attestation_from_pem(attestation, signing_key_pem)

    server_id = derive_server_id(summary)
    server_name = summary.get("server_name", server_id)
    repo_url = summary.get("repo_url", "")
    commit_sha = summary.get("commit_sha", "")
    scan_id = commit_sha[:8] if commit_sha else "unknown"

    reg_dir = Path(registry_dir)
    index_path = reg_dir / "index.json"

    if index_path.exists():
        index = json.loads(index_path.read_text())
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

    index = upsert_registry(
        index, server_id, server_name, repo_url, attestation, scan_id,
        registry_dir=reg_dir,
    )

    reg_dir.mkdir(parents=True, exist_ok=True)
    index_path.write_text(json.dumps(index, indent=2))

    # Copy scan results to scan-results/ dir
    results_dir = reg_dir.parent / "scan-results" / scan_id
    results_dir.mkdir(parents=True, exist_ok=True)
    # Write redacted summary (no raw scan_results counts)
    redacted = {k: v for k, v in summary.items() if k not in (
        "scan_results", "scoring_breakdowns",
        "thinktank_debate", "thinktank_score_adjustment", "thinktank_flags",
    )}
    (results_dir / "summary.json").write_text(json.dumps(redacted, indent=2))

    badge_src = Path(scan_dir) / "badge.svg"
    if badge_src.exists():
        shutil.copy2(str(badge_src), str(results_dir / "badge.svg"))

    log.info(f"Published: {server_id} ({scan_id})")


# ── Triage manifest ──────────────────────────────────────

def _write_triage_manifest(checkpoint: Checkpoint, output_dir: str):
    """Write a triage-manifest.json with sorted results and score distribution."""
    targets = checkpoint.data["targets"]
    entries = []
    for url, entry in targets.items():
        entries.append({
            "url": url,
            "name": entry.get("name", ""),
            "status": entry["status"],
            "preliminary_score": entry.get("preliminary_score"),
            "preliminary_verdict": entry.get("preliminary_verdict"),
        })

    # Sort by score ascending (most suspicious first)
    entries.sort(key=lambda x: x.get("preliminary_score") or 0)

    summary = checkpoint.summary()
    manifest = {
        "generated_at": _now_iso(),
        "total_targets": summary["total"],
        "phase1_completed": summary["phase1_done"] + summary["phase2_done"],
        "errors": summary["errors"],
        "score_distribution": summary["score_distribution"],
        "targets": entries,
    }

    path = Path(output_dir) / "triage-manifest.json"
    path.write_text(json.dumps(manifest, indent=2))


# ── Progress reporter ─────────────────────────────────────

class ProgressReporter:
    """Terminal progress display with ETA."""

    def __init__(self, label: str, total: int):
        self.label = label
        self.total = total
        self.completed = 0
        self.errors = 0
        self.skipped = 0
        self.start_time = time.time()
        self.current_item = ""
        self.scores: list[int] = []
        self._print_header()

    def _print_header(self):
        print(f"\n{self.label}")
        print(f"  Total targets: {self.total}")

    def start_item(self, name: str):
        self.current_item = name
        elapsed = time.time() - self.start_time
        done = self.completed + self.errors
        rate = done / elapsed * 60 if elapsed > 0 and done > 0 else 0
        remaining = self.total - done - self.skipped
        eta = remaining / (done / elapsed) if done > 0 and elapsed > 0 else 0
        eta_str = _format_duration(eta)

        bar = _progress_bar(done + self.skipped, self.total)
        print(
            f"\r  {bar}  {done + self.skipped}/{self.total}  "
            f"| {rate:.1f}/min | ETA: {eta_str} | {name[:50]}",
            end="", flush=True,
        )

    def complete(self, score: int | None = None):
        self.completed += 1
        if score is not None:
            self.scores.append(score)

    def error(self):
        self.errors += 1

    def skip(self):
        self.skipped += 1

    def finish(self):
        elapsed = time.time() - self.start_time
        print(f"\n  Done in {_format_duration(elapsed)}")
        print(f"  Completed: {self.completed} | Skipped: {self.skipped} | Errors: {self.errors}")
        if self.scores:
            dist = {
                "0-39": sum(1 for s in self.scores if s <= 39),
                "40-69": sum(1 for s in self.scores if 40 <= s <= 69),
                "70-89": sum(1 for s in self.scores if 70 <= s <= 89),
                "90+": sum(1 for s in self.scores if s >= 90),
            }
            print(f"  Scores: {dist}")


def _progress_bar(done: int, total: int, width: int = 30) -> str:
    if total == 0:
        return "[" + " " * width + "]"
    filled = int(width * done / total)
    return "[" + "=" * filled + "-" * (width - filled) + "]"


def _format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f}s"
    elif seconds < 3600:
        return f"{seconds / 60:.0f}m {seconds % 60:.0f}s"
    else:
        h = int(seconds // 3600)
        m = int((seconds % 3600) // 60)
        return f"{h}h {m}m"


# ── Helpers ───────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── CLI ───────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="credence_mcp.batch_scanner",
        description="Credence Batch Scanner — two-phase scan orchestrator",
    )
    parser.add_argument(
        "input", metavar="INPUT",
        help="Input file (text/JSON with URLs) or output dir when using --resume",
    )
    parser.add_argument("--output", default="batch-results/", help="Output directory")
    parser.add_argument("--resume", action="store_true", help="Resume from checkpoint")
    parser.add_argument("--phase1-only", action="store_true", help="Run Phase 1 only")
    parser.add_argument("--deliberate", action="store_true", help="Run Phase 2 deliberation")
    parser.add_argument("--max-deliberations", type=int, default=None, help="Stop after N deliberations")
    parser.add_argument("--budget", type=float, default=None, help="Dollar budget cap for deliberation")
    parser.add_argument("--cost-per-scan", type=float, default=0.60, help="Estimated cost per deliberation")
    parser.add_argument("--concurrency", type=int, default=4, help="Phase 1 parallelism")
    parser.add_argument("--full-scan", action="store_true", help="Run all scanners regardless of content")
    parser.add_argument("--publish", action="store_true", help="Publish results to registry incrementally")
    parser.add_argument("--registry-dir", default="registry/", help="Registry directory")
    parser.add_argument("--signing-key-env", default=None, help="Env var containing signing key PEM")
    parser.add_argument("--server-cmd", default="deliberation-mcp", help="Deliberation server command")
    parser.add_argument("--timeout", type=int, default=300, help="Deliberation timeout (seconds)")
    parser.add_argument("--verbose", action="store_true", help="Debug logging")

    args = parser.parse_args()

    # Logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # Resolve signing key
    signing_key_pem = None
    if args.signing_key_env:
        signing_key_pem = os.environ.get(args.signing_key_env)
        if not signing_key_pem:
            log.error(f"Environment variable {args.signing_key_env} is not set")
            sys.exit(1)

    if args.resume:
        # Resume mode: INPUT is the output directory
        output_dir = args.input
        checkpoint = Checkpoint(output_dir)
        s = checkpoint.summary()
        print(f"Resuming from {output_dir}")
        print(f"  Phase 1 done: {s['phase1_done']} | Phase 2 done: {s['phase2_done']} | Errors: {s['errors']}")

        if args.deliberate:
            asyncio.run(run_phase2_batch(
                checkpoint=checkpoint,
                output_dir=output_dir,
                server_cmd=args.server_cmd,
                timeout=args.timeout,
                max_deliberations=args.max_deliberations,
                budget=args.budget,
                cost_per_scan=args.cost_per_scan,
                publish=args.publish,
                registry_dir=args.registry_dir,
                signing_key_pem=signing_key_pem,
            ))
        else:
            # Resume Phase 1 — need original targets
            # Load from checkpoint (all pending targets)
            targets = []
            for url, entry in checkpoint.data["targets"].items():
                if entry["status"] == "pending":
                    targets.append(ScanTarget(url=url, name=entry.get("name", "")))

            if targets:
                asyncio.run(run_phase1_batch(
                    targets=targets,
                    output_dir=output_dir,
                    checkpoint=checkpoint,
                    concurrency=args.concurrency,
                    full_scan=args.full_scan,
                    verbose=args.verbose,
                ))
            else:
                print("  No pending Phase 1 targets.")

    else:
        # Fresh run
        output_dir = args.output
        targets = load_targets(args.input)
        if not targets:
            log.error(f"No targets found in {args.input}")
            sys.exit(1)

        print(f"Loaded {len(targets)} targets from {args.input}")

        checkpoint = Checkpoint(output_dir)
        checkpoint.data["input_file"] = args.input

        # Register all targets in checkpoint as pending (if not already there)
        for t in targets:
            if t.url not in checkpoint.data["targets"]:
                checkpoint.data["targets"][t.url] = {
                    "status": "pending",
                    "name": t.name,
                    "scan_dir": "",
                    "commit_sha": "",
                    "preliminary_score": None,
                    "preliminary_verdict": None,
                    "final_score": None,
                    "final_verdict": None,
                    "error": None,
                }
        checkpoint.save()

        # Phase 1
        asyncio.run(run_phase1_batch(
            targets=targets,
            output_dir=output_dir,
            checkpoint=checkpoint,
            concurrency=args.concurrency,
            full_scan=args.full_scan,
            verbose=args.verbose,
        ))

        # Phase 2 (if requested and not phase1-only)
        if args.deliberate and not args.phase1_only:
            asyncio.run(run_phase2_batch(
                checkpoint=checkpoint,
                output_dir=output_dir,
                server_cmd=args.server_cmd,
                timeout=args.timeout,
                max_deliberations=args.max_deliberations,
                budget=args.budget,
                cost_per_scan=args.cost_per_scan,
                publish=args.publish,
                registry_dir=args.registry_dir,
                signing_key_pem=signing_key_pem,
            ))

    # Final summary
    s = checkpoint.summary()
    print(f"\nBatch Summary:")
    print(f"  Total:     {s['total']}")
    print(f"  Phase 1:   {s['phase1_done']}")
    print(f"  Phase 2:   {s['phase2_done']}")
    print(f"  Errors:    {s['errors']}")
    print(f"  Scores:    {s['score_distribution']}")
    spend = checkpoint.data.get("phase2_estimated_spend", 0)
    if spend > 0:
        print(f"  Est. spend: ${spend:.2f}")


if __name__ == "__main__":
    main()
