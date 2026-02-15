#!/usr/bin/env python3
"""
Credence Scan Queue Builder — scrapes MCP server registries and produces a prioritized scan queue.

Pulls server lists from:
  - awesome-mcp-servers (GitHub curated list)
  - Smithery (registry scrape)
  - Glama (registry scrape)

Enriches with:
  - GitHub API (stars, forks, account age, contributors, org status, CI, lockfile)
  - npm (weekly downloads)
  - PyPI (recent downloads)

Scores each server using:
  Priority = (blast_radius × capability_risk) / provenance_confidence

Assigns phases (1–4) and outputs sorted JSON + CSV.

Usage:
    # Full run (slow — hits all APIs):
    python tools/scan-queue-builder.py

    # Quick smoke test (1 page, no GitHub/npm/PyPI enrichment):
    python tools/scan-queue-builder.py --skip-enrichment --max-pages 1

    # With GitHub token for higher rate limits:
    GITHUB_TOKEN=ghp_... python tools/scan-queue-builder.py

    # Custom output prefix:
    python tools/scan-queue-builder.py --output tools/my-queue
"""

import argparse
import csv
import json
import logging
import math
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote as urlquote

# ---------------------------------------------------------------------------
# Optional: requests (required at runtime, but we give a clear error)
# ---------------------------------------------------------------------------
try:
    import requests
except ImportError:
    print("ERROR: 'requests' is required. Install it with: pip install requests", file=sys.stderr)
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("scan-queue-builder")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CACHE_DIR = Path(__file__).parent / ".cache"
REGISTRY_INDEX = Path(__file__).resolve().parent.parent / "registry" / "index.json"

AWESOME_MCP_URL = "https://raw.githubusercontent.com/punkpeye/awesome-mcp-servers/main/README.md"
SMITHERY_API = "https://registry.smithery.ai/servers"
GLAMA_API = "https://glama.ai/api/mcp/v1/servers"

GITHUB_API = "https://api.github.com"
NPM_DOWNLOADS_API = "https://api.npmjs.org/downloads/point/last-week"
PYPI_STATS_API = "https://pypistats.org/api/packages"

USER_AGENT = "credence-scan-queue-builder/1.0 (https://credence.securingthesingularity.com)"

# Capability keywords for tier classification
CAPABILITY_KEYWORDS = {
    "critical": [
        "filesystem", "file system", "file-system", "fs ", "shell", "exec",
        "terminal", "command", "subprocess", "child_process", "puppeteer",
        "playwright", "browser automation", "selenium", "credential",
        "keychain", "password", "vault", "secret",
    ],
    "high": [
        "database", "postgres", "mysql", "sqlite", "mongodb", "redis",
        "http", "fetch", "request", "network", "email", "smtp", "sendgrid",
        "twilio", "webhook",
    ],
    "medium": [
        "api", "oauth", "token", "code generation", "codegen", "llm",
        "openai", "anthropic", "git ",
    ],
    # "low" is the default — no keywords needed
}

CAPABILITY_MULTIPLIERS = {
    "critical": 3.0,
    "high": 2.0,
    "medium": 1.5,
    "low": 1.0,
}


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------
class RateLimiter:
    """Simple per-domain rate limiter."""

    def __init__(self, default_delay: float = 1.0):
        self._last_request: dict[str, float] = {}
        self._default_delay = default_delay

    def wait(self, domain: str, delay: float | None = None):
        delay = delay if delay is not None else self._default_delay
        last = self._last_request.get(domain, 0)
        elapsed = time.time() - last
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self._last_request[domain] = time.time()


rate_limiter = RateLimiter()


def _session(github_token: str | None = None) -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = USER_AGENT
    if github_token:
        s.headers["Authorization"] = f"token {github_token}"
    return s


def _cached_get(session: requests.Session, url: str, cache_key: str,
                cache_hours: int = 24) -> str | None:
    """GET with local file cache. Returns response text or None on failure."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = re.sub(r"[^\w\-.]", "_", cache_key)[:200]
    cache_file = CACHE_DIR / safe_name

    if cache_file.exists():
        age_hours = (time.time() - cache_file.stat().st_mtime) / 3600
        if age_hours < cache_hours:
            return cache_file.read_text(encoding="utf-8")

    try:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
        rate_limiter.wait(domain)
        resp = session.get(url, timeout=30)
        resp.raise_for_status()
        cache_file.write_text(resp.text, encoding="utf-8")
        return resp.text
    except requests.RequestException as e:
        # 404s are expected for npm/PyPI lookups and missing GitHub paths — debug only
        status = getattr(getattr(e, "response", None), "status_code", None)
        if status == 404:
            log.debug("GET %s → 404 (not found)", url)
        else:
            log.warning("GET %s failed: %s", url, e)
        return None


# ---------------------------------------------------------------------------
# Source: awesome-mcp-servers
# ---------------------------------------------------------------------------
def fetch_awesome_mcp_servers(session: requests.Session) -> list[dict]:
    """Parse the awesome-mcp-servers README for GitHub repo URLs."""
    log.info("Fetching awesome-mcp-servers list...")
    text = _cached_get(session, AWESOME_MCP_URL, "awesome-mcp-servers.md")
    if not text:
        log.warning("Could not fetch awesome-mcp-servers")
        return []

    servers = []
    # Match markdown links to GitHub repos, including tree/branch/path for monorepos:
    # [name](https://github.com/owner/repo) or [name](https://github.com/owner/repo/tree/main/src/sub)
    pattern = re.compile(
        r"\[([^\]]+)\]\((https://github\.com/([\w.\-]+)/([\w.\-]+)(?:/tree/[^)]*)?)\)"
    )
    seen = set()
    current_category = "unknown"

    for line in text.splitlines():
        # Track category headers
        header_match = re.match(r"^#{1,3}\s+(.+)", line)
        if header_match:
            raw = header_match.group(1).strip()
            # Strip HTML anchors: '📂 <a name="browser-automation"></a>browser automation' → 'browser automation'
            raw = re.sub(r"<a\s+name=\"[^\"]*\"\s*>\s*</a>\s*", "", raw)
            # Strip leading emoji and variation selectors
            raw = re.sub(r"^[\U0001f300-\U0001faff\U00002600-\U000027bf\ufe00-\ufe0f\u200d]+\s*", "", raw)
            current_category = raw.strip().lower()
            # Skip non-server sections
            if any(skip in current_category for skip in ["contents", "client", "framework", "tip", "resource"]):
                current_category = "skip"
            continue

        if current_category == "skip":
            continue

        for match in pattern.finditer(line):
            name, url, owner, repo = match.groups()
            repo_key = f"{owner}/{repo}".lower()
            if repo_key in seen:
                continue
            seen.add(repo_key)

            # Extract description: text after the link on the same line
            desc_match = re.search(r"\)\s*[-–—:]\s*(.+)", line)
            description = desc_match.group(1).strip() if desc_match else ""

            servers.append({
                "repo": f"{owner}/{repo}",
                "url": url,
                "name": name.strip(),
                "description": description,
                "category": current_category,
                "sources": ["awesome-mcp-servers"],
            })

    log.info("Found %d servers from awesome-mcp-servers", len(servers))
    return servers


# ---------------------------------------------------------------------------
# Source: Smithery (JSON API)
# ---------------------------------------------------------------------------
def fetch_smithery(session: requests.Session, max_pages: int = 200) -> list[dict]:
    """Fetch server listings from Smithery registry API."""
    log.info("Fetching Smithery listings via API (max %d pages)...", max_pages)
    servers = []
    seen = set()
    page_size = 100

    for page in range(1, max_pages + 1):
        url = f"{SMITHERY_API}?pageSize={page_size}&page={page}"
        text = _cached_get(session, url, f"smithery_api_page_{page}.json")
        if not text:
            break

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            log.warning("Smithery API returned invalid JSON on page %d", page)
            break

        for entry in data.get("servers", []):
            # qualifiedName is "owner/repo" or just "name" for single-segment
            qualified = entry.get("qualifiedName", "")
            if not qualified:
                continue

            # Build GitHub repo path from qualifiedName
            # Format: "owner/repo" maps to github.com/owner/repo
            # Single-segment names (e.g. "exa") don't have a direct repo mapping
            parts = qualified.split("/")
            if len(parts) == 2:
                owner, repo = parts
            elif len(parts) == 1:
                # Single-segment — use namespace if available
                ns = entry.get("namespace", "")
                if ns and ns != qualified:
                    owner, repo = ns, qualified
                else:
                    continue  # Can't determine repo
            else:
                continue

            repo_key = f"{owner}/{repo}".lower()
            if repo_key in seen:
                continue
            seen.add(repo_key)

            server = {
                "repo": f"{owner}/{repo}",
                "url": f"https://github.com/{owner}/{repo}",
                "name": entry.get("displayName", repo),
                "description": (entry.get("description") or "")[:500],
                "category": "unknown",
                "sources": ["smithery"],
            }

            # Capture useCount as a pre-enrichment signal
            use_count = entry.get("useCount", 0)
            if use_count:
                server["smithery_use_count"] = use_count

            servers.append(server)

        # Check pagination
        pagination = data.get("pagination", {})
        total_pages = pagination.get("totalPages", 1)
        if page >= total_pages:
            break

    log.info("Found %d servers from Smithery", len(servers))
    return servers


# ---------------------------------------------------------------------------
# Source: Glama (JSON API)
# ---------------------------------------------------------------------------
def fetch_glama(session: requests.Session, max_pages: int = 200) -> list[dict]:
    """Fetch server listings from Glama API (cursor-based pagination)."""
    log.info("Fetching Glama listings via API (max %d pages)...", max_pages)
    servers = []
    seen = set()
    page_size = 100
    cursor = None

    for page in range(1, max_pages + 1):
        url = f"{GLAMA_API}?first={page_size}"
        if cursor:
            url += f"&after={cursor}"
        text = _cached_get(session, url, f"glama_api_page_{page}.json")
        if not text:
            break

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            log.warning("Glama API returned invalid JSON on page %d", page)
            break

        for entry in data.get("servers", []):
            repo_url = (entry.get("repository") or {}).get("url", "")
            if not repo_url or "github.com" not in repo_url:
                continue

            # Parse owner/repo from GitHub URL
            match = re.match(r"https?://github\.com/([\w.\-]+)/([\w.\-]+)", repo_url)
            if not match:
                continue

            owner, repo = match.groups()
            repo_key = f"{owner}/{repo}".lower()
            if repo_key in seen:
                continue
            seen.add(repo_key)

            servers.append({
                "repo": f"{owner}/{repo}",
                "url": f"https://github.com/{owner}/{repo}",
                "name": entry.get("name", repo),
                "description": (entry.get("description") or "")[:500],
                "category": "unknown",
                "sources": ["glama"],
            })

        # Cursor-based pagination
        page_info = data.get("pageInfo", {})
        if not page_info.get("hasNextPage", False):
            break
        cursor = page_info.get("endCursor")
        if not cursor:
            break

    log.info("Found %d servers from Glama", len(servers))
    return servers


# ---------------------------------------------------------------------------
# Merge sources
# ---------------------------------------------------------------------------
def merge_servers(sources: list[list[dict]]) -> dict[str, dict]:
    """Merge server lists from multiple sources, deduplicating by repo key."""
    merged: dict[str, dict] = {}

    for source_list in sources:
        for server in source_list:
            key = server["repo"].lower()
            if key in merged:
                # Merge sources list
                existing_sources = set(merged[key]["sources"])
                existing_sources.update(server["sources"])
                merged[key]["sources"] = sorted(existing_sources)
                # Prefer non-empty descriptions
                if not merged[key]["description"] and server["description"]:
                    merged[key]["description"] = server["description"]
                # Prefer non-unknown categories
                if merged[key]["category"] == "unknown" and server["category"] != "unknown":
                    merged[key]["category"] = server["category"]
                # Carry over Smithery use count
                if "smithery_use_count" in server:
                    merged[key]["smithery_use_count"] = server["smithery_use_count"]
            else:
                merged[key] = server.copy()

    return merged


# ---------------------------------------------------------------------------
# Enrichment: GitHub
# ---------------------------------------------------------------------------
def enrich_github(session: requests.Session, server: dict) -> dict:
    """Add GitHub signals: stars, forks, account age, contributors, org, CI, lockfile."""
    repo = server["repo"]
    cache_key = f"github_{repo.replace('/', '_')}.json"
    text = _cached_get(session, f"{GITHUB_API}/repos/{repo}", cache_key, cache_hours=12)

    if not text:
        return server

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return server

    signals = server.setdefault("signals", {})
    signals["github_stars"] = data.get("stargazers_count", 0)
    signals["github_forks"] = data.get("forks_count", 0)
    signals["is_fork"] = data.get("fork", False)
    signals["is_org"] = data.get("owner", {}).get("type", "").lower() == "organization"

    # Account age
    created = data.get("created_at", "")
    if created:
        try:
            created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - created_dt).days
            signals["account_age_days"] = age_days
        except (ValueError, TypeError):
            pass

    # Use description if we don't have one
    if not server.get("description") and data.get("description"):
        server["description"] = data["description"]

    # Check for CI (look for .github/workflows)
    workflows_url = f"{GITHUB_API}/repos/{repo}/contents/.github/workflows"
    wf_text = _cached_get(session, workflows_url,
                          f"github_{repo.replace('/', '_')}_workflows.json",
                          cache_hours=24)
    if wf_text:
        try:
            wf_data = json.loads(wf_text)
            signals["has_ci"] = isinstance(wf_data, list) and len(wf_data) > 0
        except json.JSONDecodeError:
            signals["has_ci"] = False
    else:
        signals["has_ci"] = False

    # Check for lockfile
    tree_url = f"{GITHUB_API}/repos/{repo}/git/trees/HEAD"
    tree_text = _cached_get(session, tree_url,
                            f"github_{repo.replace('/', '_')}_tree.json",
                            cache_hours=24)
    if tree_text:
        try:
            tree_data = json.loads(tree_text)
            tree_files = [f["path"] for f in tree_data.get("tree", [])]
            lockfiles = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                         "poetry.lock", "Pipfile.lock", "uv.lock"}
            signals["has_lockfile"] = bool(lockfiles & set(tree_files))
            signals["has_license"] = any(
                f.lower().startswith("license") for f in tree_files
            )
        except json.JSONDecodeError:
            pass

    # Contributors count (first page — per_page=100 for reasonable count)
    contribs_url = f"{GITHUB_API}/repos/{repo}/contributors?per_page=100&anon=0"
    contribs_text = _cached_get(session, contribs_url,
                                f"github_{repo.replace('/', '_')}_contributors.json",
                                cache_hours=24)
    if contribs_text:
        try:
            contribs_data = json.loads(contribs_text)
            if isinstance(contribs_data, list):
                signals["contributor_count"] = len(contribs_data)
        except json.JSONDecodeError:
            pass

    return server


# ---------------------------------------------------------------------------
# Enrichment: npm
# ---------------------------------------------------------------------------
def enrich_npm(session: requests.Session, server: dict) -> dict:
    """Check npm for weekly downloads. Tries repo name as package name."""
    repo = server["repo"]
    _, repo_name = repo.split("/", 1)

    # Try common package name patterns
    candidates = [repo_name]
    if repo_name.startswith("mcp-server-"):
        candidates.append(f"@{repo.split('/')[0]}/{repo_name}")
    elif repo_name.startswith("server-"):
        candidates.append(f"@modelcontextprotocol/{repo_name}")

    for pkg in candidates:
        cache_key = f"npm_{pkg.replace('/', '_')}.json"
        url = f"{NPM_DOWNLOADS_API}/{urlquote(pkg, safe='@')}"
        text = _cached_get(session, url, cache_key, cache_hours=12)
        if text:
            try:
                data = json.loads(text)
                downloads = data.get("downloads", 0)
                if downloads > 0:
                    server.setdefault("signals", {})["npm_weekly_downloads"] = downloads
                    break
            except json.JSONDecodeError:
                continue

    return server


# ---------------------------------------------------------------------------
# Enrichment: PyPI
# ---------------------------------------------------------------------------
def enrich_pypi(session: requests.Session, server: dict) -> dict:
    """Check PyPI for recent downloads."""
    repo = server["repo"]
    _, repo_name = repo.split("/", 1)

    # Try the repo name and common variants
    candidates = [repo_name, repo_name.replace("-", "_")]

    for pkg in candidates:
        cache_key = f"pypi_{pkg}.json"
        url = f"{PYPI_STATS_API}/{urlquote(pkg)}/recent"
        text = _cached_get(session, url, cache_key, cache_hours=12)
        if text:
            try:
                data = json.loads(text)
                recent = data.get("data", {}).get("last_week", 0)
                if recent > 0:
                    server.setdefault("signals", {})["pypi_weekly_downloads"] = recent
                    break
            except json.JSONDecodeError:
                continue

    return server


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------
def classify_capability(server: dict) -> str:
    """Determine capability tier from description and name."""
    text = f"{server.get('name', '')} {server.get('description', '')} {server.get('category', '')}".lower()

    for tier in ("critical", "high", "medium"):
        for keyword in CAPABILITY_KEYWORDS[tier]:
            if keyword in text:
                return tier
    return "low"


def compute_blast_radius(signals: dict) -> float:
    """Compute blast radius score (0–100) from signals."""
    score = 0.0

    # npm downloads (weight: 30)
    npm_dl = signals.get("npm_weekly_downloads", 0)
    if npm_dl > 0:
        score += min(math.log10(npm_dl + 1) / math.log10(100_001), 1.0) * 30

    # PyPI downloads (weight: 30)
    pypi_dl = signals.get("pypi_weekly_downloads", 0)
    if pypi_dl > 0:
        score += min(math.log10(pypi_dl + 1) / math.log10(100_001), 1.0) * 30

    # GitHub stars (weight: 20)
    stars = signals.get("github_stars", 0)
    if stars > 0:
        score += min(math.log10(stars + 1) / math.log10(50_001), 1.0) * 20

    # Registry presence (weight: 10)
    smithery = signals.get("smithery_listed", False)
    glama = signals.get("glama_listed", False)
    if smithery and glama:
        score += 10
    elif smithery or glama:
        score += 5

    # awesome-mcp-servers listing (weight: 10)
    if signals.get("awesome_listed", False):
        score += 10

    return score


def compute_provenance_confidence(signals: dict) -> float:
    """Compute provenance confidence (0.1–1.0) from signals."""
    confidence = 0.0

    age_days = signals.get("account_age_days", 0)
    if age_days >= 365:
        confidence += 0.15
    if age_days >= 3 * 365:
        confidence += 0.10

    if signals.get("is_org", False):
        confidence += 0.15

    contribs = signals.get("contributor_count", 0)
    if contribs >= 3:
        confidence += 0.10
    if contribs >= 10:
        confidence += 0.05

    if signals.get("has_lockfile", False):
        confidence += 0.10
    if signals.get("has_ci", False):
        confidence += 0.10
    if signals.get("has_license", False):
        confidence += 0.05
    if not signals.get("is_fork", True):
        confidence += 0.05

    # Clamp
    return max(0.1, min(1.0, confidence))


def assign_phase(server: dict) -> int:
    """Assign a scan phase (1–4) based on server characteristics."""
    repo = server["repo"].lower()
    sources = set(server.get("sources", []))

    # Phase 1: Reference corpus
    if repo.startswith("modelcontextprotocol/"):
        return 1

    # Phase 1: Top awesome-mcp-servers entries (by stars, handled during sorting)
    if "awesome-mcp-servers" in sources:
        stars = server.get("signals", {}).get("github_stars", 0)
        if stars >= 500:
            return 1

    # Phase 3: Adversarial surface (forks)
    if server.get("signals", {}).get("is_fork", False):
        return 3

    # Phase 3: Anomalous signals (new account + high stars)
    signals = server.get("signals", {})
    age = signals.get("account_age_days", 9999)
    stars = signals.get("github_stars", 0)
    if age < 180 and stars > 100:
        return 3

    # Phase 2: High-impact unknowns (has downloads, significant stars, or Smithery usage)
    downloads = (signals.get("npm_weekly_downloads", 0)
                 + signals.get("pypi_weekly_downloads", 0))
    smithery_uses = signals.get("smithery_use_count", 0)
    if downloads > 100 or stars > 50 or smithery_uses > 100:
        return 2

    # Phase 4: Everything else
    return 4


def score_server(server: dict) -> dict:
    """Compute priority score and assign phase."""
    signals = server.setdefault("signals", {})

    # Set source flags
    sources = set(server.get("sources", []))
    signals["smithery_listed"] = "smithery" in sources
    signals["glama_listed"] = "glama" in sources
    signals["awesome_listed"] = "awesome-mcp-servers" in sources

    # Carry over Smithery use count into signals
    if "smithery_use_count" in server:
        signals["smithery_use_count"] = server["smithery_use_count"]

    # Capability
    tier = classify_capability(server)
    server["capability_tier"] = tier
    server["capability_multiplier"] = CAPABILITY_MULTIPLIERS[tier]

    # Blast radius
    blast = compute_blast_radius(signals)
    server["blast_radius"] = round(blast, 2)

    # Provenance
    prov = compute_provenance_confidence(signals)
    server["provenance_confidence"] = round(prov, 2)

    # Priority score
    priority = (blast * CAPABILITY_MULTIPLIERS[tier]) / prov
    server["priority_score"] = round(priority, 2)

    # Phase
    server["phase"] = assign_phase(server)

    # Timestamp
    server["discovered_at"] = datetime.now(timezone.utc).isoformat()

    return server


# ---------------------------------------------------------------------------
# Exclusion: already scanned
# ---------------------------------------------------------------------------
def load_already_scanned() -> set[str]:
    """Load repos already in the registry index."""
    if not REGISTRY_INDEX.exists():
        return set()
    try:
        with open(REGISTRY_INDEX) as f:
            data = json.load(f)
        # index.json is a dict of server_id → metadata
        scanned = set()
        for entry in data.values() if isinstance(data, dict) else data:
            if isinstance(entry, dict):
                repo = entry.get("repo", entry.get("repository", ""))
                if repo:
                    scanned.add(repo.lower())
        return scanned
    except (json.JSONDecodeError, OSError) as e:
        log.warning("Could not read registry index: %s", e)
        return set()


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def write_json(servers: list[dict], path: Path):
    """Write the full queue as JSON."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(servers, f, indent=2, ensure_ascii=False)
    log.info("Wrote %d servers to %s", len(servers), path)


def write_csv(servers: list[dict], path: Path):
    """Write a flattened CSV for manual review."""
    fieldnames = [
        "phase", "priority_score", "repo", "name", "capability_tier",
        "blast_radius", "provenance_confidence", "capability_multiplier",
        "github_stars", "npm_weekly_downloads", "pypi_weekly_downloads",
        "account_age_days", "contributor_count", "is_org", "is_fork",
        "has_lockfile", "has_ci", "sources", "category", "description",
    ]

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for s in servers:
            row = {
                "phase": s.get("phase", ""),
                "priority_score": s.get("priority_score", ""),
                "repo": s.get("repo", ""),
                "name": s.get("name", ""),
                "capability_tier": s.get("capability_tier", ""),
                "blast_radius": s.get("blast_radius", ""),
                "provenance_confidence": s.get("provenance_confidence", ""),
                "capability_multiplier": s.get("capability_multiplier", ""),
                "github_stars": s.get("signals", {}).get("github_stars", ""),
                "npm_weekly_downloads": s.get("signals", {}).get("npm_weekly_downloads", ""),
                "pypi_weekly_downloads": s.get("signals", {}).get("pypi_weekly_downloads", ""),
                "account_age_days": s.get("signals", {}).get("account_age_days", ""),
                "contributor_count": s.get("signals", {}).get("contributor_count", ""),
                "is_org": s.get("signals", {}).get("is_org", ""),
                "is_fork": s.get("signals", {}).get("is_fork", ""),
                "has_lockfile": s.get("signals", {}).get("has_lockfile", ""),
                "has_ci": s.get("signals", {}).get("has_ci", ""),
                "sources": ",".join(s.get("sources", [])),
                "category": s.get("category", ""),
                "description": s.get("description", "")[:200],
            }
            writer.writerow(row)
    log.info("Wrote %d servers to %s", len(servers), path)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Build a prioritized MCP server scan queue for Credence."
    )
    parser.add_argument(
        "--output", "-o", default="tools/scan-queue",
        help="Output path prefix (default: tools/scan-queue). Produces .json and .csv",
    )
    parser.add_argument(
        "--skip-enrichment", action="store_true",
        help="Skip GitHub/npm/PyPI enrichment (fast, uses only registry data)",
    )
    parser.add_argument(
        "--max-pages", type=int, default=200,
        help="Max pages to fetch from each registry API (default: 200, enough for ~20k servers)",
    )
    parser.add_argument(
        "--include-scanned", action="store_true",
        help="Include servers already in registry/index.json",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    github_token = os.environ.get("GITHUB_TOKEN")
    if not github_token and not args.skip_enrichment:
        log.warning("GITHUB_TOKEN not set — GitHub API rate limit will be 60 req/hr. "
                     "Set GITHUB_TOKEN for 5,000 req/hr.")

    session = _session(github_token)

    # ── 1. Fetch from sources ──────────────────────────────────
    awesome = fetch_awesome_mcp_servers(session)
    smithery = fetch_smithery(session, max_pages=args.max_pages)
    glama = fetch_glama(session, max_pages=args.max_pages)

    # ── 2. Merge and deduplicate ───────────────────────────────
    merged = merge_servers([awesome, smithery, glama])
    log.info("Total unique servers after merge: %d", len(merged))

    # ── 3. Exclude already-scanned ─────────────────────────────
    if not args.include_scanned:
        already = load_already_scanned()
        if already:
            before = len(merged)
            merged = {k: v for k, v in merged.items() if k not in already}
            log.info("Excluded %d already-scanned servers", before - len(merged))

    # ── 4. Enrich ──────────────────────────────────────────────
    servers = list(merged.values())
    if not args.skip_enrichment:
        log.info("Enriching %d servers with GitHub/npm/PyPI data...", len(servers))
        for i, server in enumerate(servers):
            if (i + 1) % 50 == 0:
                log.info("  Enriched %d/%d...", i + 1, len(servers))
            enrich_github(session, server)
            enrich_npm(session, server)
            enrich_pypi(session, server)
    else:
        log.info("Skipping enrichment (--skip-enrichment)")

    # ── 5. Score and sort ──────────────────────────────────────
    for server in servers:
        score_server(server)

    # Sort: phase ascending, then priority descending within phase
    servers.sort(key=lambda s: (s["phase"], -s["priority_score"]))

    # ── 6. Summary ─────────────────────────────────────────────
    phase_counts = {}
    for s in servers:
        phase_counts[s["phase"]] = phase_counts.get(s["phase"], 0) + 1
    for phase in sorted(phase_counts):
        log.info("Phase %d: %d servers", phase, phase_counts[phase])

    # ── 7. Write outputs ───────────────────────────────────────
    output_prefix = Path(args.output)
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    write_json(servers, output_prefix.with_suffix(".json"))
    write_csv(servers, output_prefix.with_suffix(".csv"))

    log.info("Done. %d servers in queue.", len(servers))


if __name__ == "__main__":
    main()
