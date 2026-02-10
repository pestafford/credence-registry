"""
Credence Config Resolver — Maps MCP server configurations to verifiable package identities.

Reads claude_desktop_config.json (or similar MCP client configs) and resolves
each server entry to a package name, repo URL, and local path that Credence
can check against the registry.
"""

import json
import os
import platform
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List

import httpx


@dataclass
class ResolvedServer:
    """A resolved MCP server configuration."""
    name: str                           # Config key (e.g., "github", "filesystem")
    command: str                        # Raw command from config
    args: list                          # Raw args from config
    server_type: str = "unknown"        # npx, python, binary, docker, path
    package_name: Optional[str] = None  # e.g., "@modelcontextprotocol/server-github"
    repo_url: Optional[str] = None      # e.g., "https://github.com/modelcontextprotocol/servers"
    local_path: Optional[str] = None    # Path to installed source if found
    version: Optional[str] = None       # Installed version if detectable
    resolve_error: Optional[str] = None # Error message if resolution failed


def find_config_file() -> Optional[Path]:
    """Find the Claude Desktop config file based on OS."""
    system = platform.system()

    candidates = []

    if system == "Darwin":  # macOS
        candidates = [
            Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
        ]
    elif system == "Windows":
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            candidates = [
                Path(appdata) / "Claude" / "claude_desktop_config.json",
            ]
    elif system == "Linux":
        xdg_config = os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))
        candidates = [
            Path(xdg_config) / "Claude" / "claude_desktop_config.json",
        ]

    # Also check Claude Code config
    claude_code_config = Path.home() / ".claude" / "mcp_servers.json"
    candidates.append(claude_code_config)

    for path in candidates:
        if path.exists():
            return path

    return None


def parse_config(config_path: Path) -> dict:
    """Parse MCP client config and extract server definitions."""
    with open(config_path) as f:
        config = json.load(f)

    # Claude Desktop format
    if "mcpServers" in config:
        return config["mcpServers"]

    # Claude Code format (flat dict of servers)
    if any(isinstance(v, dict) and "command" in v for v in config.values()):
        return config

    return {}


def resolve_server(name: str, server_config: dict) -> ResolvedServer:
    """Resolve a single server config entry to a verifiable identity."""
    command = server_config.get("command", "")
    args = server_config.get("args", [])

    server = ResolvedServer(
        name=name,
        command=command,
        args=args
    )

    # ── npx / npm packages ───────────────────────────────
    if command in ("npx", "npx.cmd"):
        server.server_type = "npx"
        # Find the package name in args
        for arg in args:
            if not arg.startswith("-"):
                server.package_name = arg
                break

        if server.package_name:
            server.repo_url = _resolve_npm_repo(server.package_name)
            server.local_path = _find_npx_cache(server.package_name)
            server.version = _get_npm_version(server.package_name)

    # ── node direct ──────────────────────────────────────
    elif command == "node":
        server.server_type = "node"
        for arg in args:
            if arg.endswith(".js") or arg.endswith(".mjs"):
                server.local_path = arg
                server.package_name = _infer_package_from_path(arg)
                break

    # ── python / python3 ─────────────────────────────────
    elif command in ("python", "python3"):
        server.server_type = "python"
        if "-m" in args:
            idx = args.index("-m")
            if idx + 1 < len(args):
                module = args[idx + 1]
                server.package_name = module
                server.repo_url = _resolve_pypi_repo(module)
                server.local_path = _find_python_module(module)
                server.version = _get_pip_version(module)
        else:
            for arg in args:
                if arg.endswith(".py"):
                    server.local_path = arg
                    break

    # ── uvx (Python tool runner) ─────────────────────────
    elif command in ("uvx", "uv"):
        server.server_type = "uvx"
        for arg in args:
            if not arg.startswith("-") and arg != "run":
                server.package_name = arg
                server.repo_url = _resolve_pypi_repo(arg)
                break

    # ── docker ───────────────────────────────────────────
    elif command == "docker":
        server.server_type = "docker"
        if "run" in args:
            # Find the image name (last non-flag arg after 'run')
            after_run = args[args.index("run") + 1:]
            for arg in reversed(after_run):
                if not arg.startswith("-"):
                    server.package_name = arg
                    break

    # ── direct binary / path ─────────────────────────────
    else:
        server.server_type = "binary"
        server.local_path = command
        if "/" in command or "\\" in command:
            server.server_type = "path"

    # Try to infer repo from local path if we don't have one yet
    if not server.repo_url and server.local_path:
        server.repo_url = _infer_git_remote(server.local_path)

    return server


def resolve_all(config_path: Optional[Path] = None) -> tuple[Path, List[ResolvedServer]]:
    """Resolve all servers in the config file."""
    if config_path is None:
        config_path = find_config_file()

    if config_path is None:
        raise FileNotFoundError(
            "Could not find MCP client config. Looked for claude_desktop_config.json "
            "in standard locations. Use --config to specify a path."
        )

    servers_config = parse_config(config_path)
    resolved = []

    for name, server_config in servers_config.items():
        try:
            resolved.append(resolve_server(name, server_config))
        except Exception as e:
            resolved.append(ResolvedServer(
                name=name,
                command=server_config.get("command", "?"),
                args=server_config.get("args", []),
                resolve_error=str(e)
            ))

    return config_path, resolved


# ── Package Registry Lookups ─────────────────────────────────────

def _resolve_npm_repo(package_name: str) -> Optional[str]:
    """Look up the repository URL for an npm package."""
    try:
        # Strip version specifier if present
        clean = re.sub(r"@[\d.]+$", "", package_name)
        resp = httpx.get(f"https://registry.npmjs.org/{clean}", timeout=10.0)
        if resp.status_code == 200:
            data = resp.json()
            repo = data.get("repository", {})
            if isinstance(repo, dict):
                url = repo.get("url", "")
            elif isinstance(repo, str):
                url = repo
            else:
                return None

            # Normalize git URLs to https
            url = url.replace("git+", "").replace("git://", "https://").rstrip(".git")
            if "github.com" in url:
                return url
            return url if url else None
    except Exception:
        return None


def _resolve_pypi_repo(package_name: str) -> Optional[str]:
    """Look up the repository URL for a PyPI package."""
    try:
        # Normalize package name (underscores to hyphens)
        clean = package_name.replace("_", "-")
        resp = httpx.get(f"https://pypi.org/pypi/{clean}/json", timeout=10.0)
        if resp.status_code == 200:
            data = resp.json()
            urls = data.get("info", {}).get("project_urls", {})

            # Check common keys for repo URL
            for key in ("Repository", "Source", "Source Code", "GitHub", "Homepage", "Code"):
                url = urls.get(key, "")
                if "github.com" in url or "gitlab.com" in url:
                    return url

            # Fallback to homepage
            homepage = data.get("info", {}).get("home_page", "")
            if "github.com" in homepage:
                return homepage
    except Exception:
        return None


# ── Local Package Resolution ─────────────────────────────────────

def _find_npx_cache(package_name: str) -> Optional[str]:
    """Find the cached npx package location."""
    try:
        result = subprocess.run(
            ["npm", "root", "-g"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            global_root = Path(result.stdout.strip())
            pkg_path = global_root / package_name.lstrip("@").replace("/", os.sep)
            if pkg_path.exists():
                return str(pkg_path)
    except Exception:
        pass
    return None


def _find_python_module(module_name: str) -> Optional[str]:
    """Find the installed location of a Python module."""
    try:
        result = subprocess.run(
            ["python3", "-c", f"import {module_name}; print({module_name}.__file__)"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            path = result.stdout.strip()
            # Go up to the package directory
            return str(Path(path).parent)
    except Exception:
        pass
    return None


def _get_npm_version(package_name: str) -> Optional[str]:
    """Get installed version of an npm package."""
    try:
        result = subprocess.run(
            ["npm", "list", "-g", package_name, "--json"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            deps = data.get("dependencies", {})
            pkg = deps.get(package_name, {})
            return pkg.get("version")
    except Exception:
        return None


def _get_pip_version(package_name: str) -> Optional[str]:
    """Get installed version of a pip package."""
    try:
        result = subprocess.run(
            ["pip", "show", package_name],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.split("\n"):
            if line.startswith("Version:"):
                return line.split(":")[1].strip()
    except Exception:
        return None


def _infer_package_from_path(path: str) -> Optional[str]:
    """Try to infer a package name from a file path."""
    p = Path(path)
    if "node_modules" in p.parts:
        idx = p.parts.index("node_modules")
        remaining = p.parts[idx + 1:]
        if remaining:
            if remaining[0].startswith("@") and len(remaining) > 1:
                return f"{remaining[0]}/{remaining[1]}"
            return remaining[0]
    return None


def _infer_git_remote(path: str) -> Optional[str]:
    """Check if a path is inside a git repo and get the remote URL."""
    try:
        result = subprocess.run(
            ["git", "-C", str(Path(path).parent), "remote", "get-url", "origin"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            url = result.stdout.strip()
            url = url.replace("git@github.com:", "https://github.com/")
            url = url.rstrip(".git")
            return url
    except Exception:
        return None
